import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone

from .audit import audit_hash, canonical_json
from .domain import ConflictError, NotFoundError, DomainError
from .rules import SUCCESS_RESULTS, TERMINAL_STATUSES


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class Repository:
    def __init__(self, path):
        self.path = path

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    stable_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    payload TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_type, stable_key)
                );
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, source_type, external_id),
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    role TEXT,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS valve_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_code TEXT NOT NULL UNIQUE,
                    item_id INTEGER NOT NULL,
                    pipeline_id TEXT NOT NULL,
                    segment_id TEXT NOT NULL,
                    valve_id TEXT NOT NULL,
                    seq_order INTEGER NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'issued',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS scada_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_code TEXT NOT NULL UNIQUE,
                    command_code TEXT NOT NULL,
                    command_version INTEGER NOT NULL,
                    item_id INTEGER NOT NULL,
                    valve_id TEXT NOT NULL,
                    result TEXT NOT NULL,
                    receipted_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS manual_review (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    command_code TEXT NOT NULL,
                    valve_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    resolved_by TEXT,
                    note TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_manual_review_open
                    ON manual_review(command_code) WHERE status = 'open';
                """
            )
        finally:
            conn.close()

    def _row_to_item(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _last_hash(self, conn, item_id):
        row = conn.execute(
            "SELECT event_hash FROM audit_events WHERE item_id IS ? ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        return row["event_hash"] if row else "GENESIS"

    def append_audit(self, conn, item_id, event_type, actor, role, payload):
        previous = self._last_hash(conn, item_id)
        event = {
            "item_id": item_id,
            "event_type": event_type,
            "actor": actor,
            "role": role,
            "payload": payload,
            "created_at": now_iso(),
        }
        event_hash = audit_hash(previous, event)
        conn.execute(
            "INSERT INTO audit_events(item_id,event_type,actor,role,payload,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (item_id, event_type, actor, role, canonical_json(payload), previous, event_hash, event["created_at"]),
        )

    def create_item(self, entity_type, stable_key, initial_status, payload, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO items(entity_type,stable_key,status,version,payload,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        entity_type,
                        stable_key,
                        initial_status,
                        1,
                        canonical_json(payload),
                        actor,
                        role,
                        now_iso(),
                        now_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_item", "同一业务实体已经存在")
            item_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(conn, item_id, "created", actor, role, {"stable_key": stable_key})
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_item(self, item_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            return self._row_to_item(row)
        finally:
            conn.close()

    def list_items(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute("SELECT * FROM items WHERE status=? ORDER BY id DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM items ORDER BY id DESC").fetchall()
            return [self._row_to_item(row) for row in rows]
        finally:
            conn.close()

    def add_source(self, item_id, source_type, external_id, payload, observed_at, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            try:
                conn.execute(
                    "INSERT INTO sources(item_id,source_type,external_id,payload,observed_at,created_at) VALUES(?,?,?,?,?,?)",
                    (item_id, source_type, external_id, canonical_json(payload), observed_at, now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_source", "同一来源记录已经提交")
            source_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn,
                item_id,
                "source_recorded",
                actor,
                role,
                {"source_id": source_id, "source_type": source_type, "external_id": external_id},
            )
            conn.execute("COMMIT")
            return {"id": source_id, "item_id": item_id, "source_type": source_type, "external_id": external_id, "payload": payload, "observed_at": observed_at}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_sources(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM sources WHERE item_id=? ORDER BY id DESC", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def apply_action(self, item_id, action, actor, role, new_status, new_payload, event_payload, expected_version=None, commands=None, is_update=False):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            if expected_version is not None and int(expected_version) != int(row["version"]):
                raise ConflictError("version_conflict", "记录已被其他操作更新，请重新读取")
            version = int(row["version"]) + 1
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (new_status, version, canonical_json(new_payload), now_iso(), item_id),
            )
            conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                (item_id, action, actor, role, canonical_json(event_payload), now_iso()),
            )
            self.append_audit(conn, item_id, action, actor, role, event_payload)
            if commands is not None:
                self._issue_commands(conn, item_id, new_payload, commands, is_update, actor, role)
            if new_status in TERMINAL_STATUSES:
                conn.execute(
                    "UPDATE valve_commands SET status='cancelled', updated_at=? WHERE item_id=?",
                    (now_iso(), item_id),
                )
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def audit_trail(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute("SELECT status, COUNT(*) AS total FROM items GROUP BY status").fetchall():
                counts[row["status"]] = row["total"]
            return {"counts": counts, "items": self.list_items()}
        finally:
            conn.close()

    # ----- 阀门指令与 SCADA 回执 -----

    def _new_command_code(self):
        return "VCMD-" + uuid.uuid4().hex[:12].upper()

    def _receipt_code(self, command_code, version, result, receipted_at):
        raw = "%s|%s|%s|%s" % (command_code, version, result, receipted_at)
        return "RCPT-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _issue_commands(self, conn, item_id, payload, valves, is_update, actor, role):
        pipeline_id = payload["pipeline_id"]
        segment_id = payload["segment_id"]
        stamp = now_iso()
        if is_update:
            existing_rows = conn.execute(
                "SELECT * FROM valve_commands WHERE item_id=?", (item_id,)
            ).fetchall()
            existing = {row["valve_id"]: row for row in existing_rows}
            seen = set()
            for order, valve in enumerate(valves):
                seen.add(valve)
                row = existing.get(valve)
                if row is not None:
                    conn.execute(
                        "UPDATE valve_commands SET version=version+1, seq_order=?, status='issued', updated_at=? WHERE id=?",
                        (order, stamp, row["id"]),
                    )
                else:
                    code = self._new_command_code()
                    conn.execute(
                        "INSERT INTO valve_commands(command_code,item_id,pipeline_id,segment_id,valve_id,seq_order,version,status,created_at,updated_at) VALUES(?,?,?,?,?,?,1,'issued',?,?)",
                        (code, item_id, pipeline_id, segment_id, valve, order, stamp, stamp),
                    )
            for valve, row in existing.items():
                if valve not in seen:
                    conn.execute(
                        "UPDATE valve_commands SET status='cancelled', updated_at=? WHERE id=?",
                        (stamp, row["id"]),
                    )
            self.append_audit(conn, item_id, "commands_updated", actor, role, {"valves": valves})
        else:
            for order, valve in enumerate(valves):
                code = self._new_command_code()
                conn.execute(
                    "INSERT INTO valve_commands(command_code,item_id,pipeline_id,segment_id,valve_id,seq_order,version,status,created_at,updated_at) VALUES(?,?,?,?,?,?,1,'issued',?,?)",
                    (code, item_id, pipeline_id, segment_id, valve, order, stamp, stamp),
                )
            self.append_audit(conn, item_id, "commands_issued", actor, role, {"valves": valves})

    def find_occupiers(self, item_id, pipeline_id, segment_id):
        conn = self.connect()
        try:
            rows = conn.execute(
                """
                SELECT i.id, i.status, i.payload, i.updated_at
                FROM items i
                WHERE i.entity_type = 'pipeline_leak'
                  AND i.id != ?
                  AND json_extract(i.payload, '$.pipeline_id') = ?
                  AND json_extract(i.payload, '$.segment_id') = ?
                  AND i.status NOT IN ('restored', 'cancelled')
                  AND EXISTS (
                      SELECT 1 FROM valve_commands vc
                      WHERE vc.item_id = i.id AND vc.status != 'cancelled'
                  )
                ORDER BY i.id
                """,
                (item_id, pipeline_id, segment_id),
            ).fetchall()
            occupiers = []
            for row in rows:
                payload = json.loads(row["payload"])
                occupiers.append({
                    "item_id": row["id"],
                    "status": row["status"],
                    "valve_sequence": payload.get("valve_sequence", []),
                    "updated_at": row["updated_at"],
                })
            return occupiers
        finally:
            conn.close()

    def _row_to_receipt(self, row):
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _command_status(self, conn, cmd):
        if cmd["status"] == "cancelled":
            return "cancelled"
        current_version = int(cmd["version"])
        rows = conn.execute(
            "SELECT * FROM scada_receipts WHERE command_code=? ORDER BY id",
            (cmd["command_code"],),
        ).fetchall()
        receipts = [self._row_to_receipt(row) for row in rows]
        confirmed = any(
            r["command_version"] == current_version
            and r["status"] == "valid"
            and str(r["result"]).lower() in SUCCESS_RESULTS
            for r in receipts
        )
        failed = any(
            r["command_version"] == current_version
            and r["status"] == "valid"
            and str(r["result"]).lower() not in SUCCESS_RESULTS
            for r in receipts
        )
        stale = any(r["command_version"] < current_version for r in receipts)
        if confirmed:
            return "confirmed"
        if failed:
            return "failed"
        if stale:
            return "stale"
        return "pending"

    def _command_view(self, conn, cmd):
        rows = conn.execute(
            "SELECT * FROM scada_receipts WHERE command_code=? ORDER BY id",
            (cmd["command_code"],),
        ).fetchall()
        receipts = [self._row_to_receipt(row) for row in rows]
        view = {
            "command_code": cmd["command_code"],
            "item_id": cmd["item_id"],
            "pipeline_id": cmd["pipeline_id"],
            "segment_id": cmd["segment_id"],
            "valve_id": cmd["valve_id"],
            "seq_order": cmd["seq_order"],
            "version": cmd["version"],
            "status": cmd["status"],
            "receipts": receipts,
        }
        view["confirm_status"] = self._command_status(conn, cmd)
        return view

    def list_commands(self, item_id):
        conn = self.connect()
        try:
            cmds = conn.execute(
                "SELECT * FROM valve_commands WHERE item_id=? ORDER BY seq_order, id",
                (item_id,),
            ).fetchall()
            return [self._command_view(conn, cmd) for cmd in cmds]
        finally:
            conn.close()

    def command_gate(self, item_id):
        """返回阻碍隔离任务前进（repair/restore）的指令：回执失效或当前版本回执失败。"""
        commands = self.list_commands(item_id)
        return [c for c in commands if c["confirm_status"] in ("stale", "failed")]

    def add_receipt(self, command_code, version, result, receipted_at, receipt_code, raw, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cmd = conn.execute(
                "SELECT * FROM valve_commands WHERE command_code=?",
                (command_code,),
            ).fetchone()
            if cmd is None:
                raise NotFoundError("command_not_found", "阀门指令不存在")
            if cmd["status"] == "cancelled":
                raise ConflictError("command_cancelled", "阀门指令已取消，不能回执")
            current_version = int(cmd["version"])
            if version is None:
                version = current_version
            if receipt_code is None:
                receipt_code = self._receipt_code(command_code, version, result, receipted_at)
            existing = conn.execute(
                "SELECT * FROM scada_receipts WHERE receipt_code=?",
                (receipt_code,),
            ).fetchone()
            duplicate = existing is not None
            if not duplicate:
                if version < current_version:
                    rec_status = "stale"
                elif version > current_version:
                    rec_status = "invalid"
                else:
                    rec_status = "valid"
                try:
                    conn.execute(
                        """
                        INSERT INTO scada_receipts
                            (receipt_code,command_code,command_version,item_id,valve_id,result,receipted_at,payload,status,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            receipt_code,
                            command_code,
                            version,
                            cmd["item_id"],
                            cmd["valve_id"],
                            result,
                            receipted_at,
                            canonical_json(raw),
                            rec_status,
                            now_iso(),
                        ),
                    )
                except sqlite3.IntegrityError:
                    duplicate = True
                if not duplicate and rec_status == "valid" and str(result).lower() in SUCCESS_RESULTS:
                    conn.execute(
                        "UPDATE valve_commands SET status='receipted', updated_at=? WHERE id=?",
                        (now_iso(), cmd["id"]),
                    )
                if not duplicate:
                    self.append_audit(
                        conn,
                        cmd["item_id"],
                        "receipt_recorded",
                        actor,
                        role,
                        {
                            "receipt_code": receipt_code,
                            "command_code": command_code,
                            "command_version": version,
                            "result": result,
                            "receipt_status": rec_status,
                        },
                    )
            conn.execute("COMMIT")
            fresh = conn.execute(
                "SELECT * FROM valve_commands WHERE command_code=?",
                (command_code,),
            ).fetchone()
            receipts = conn.execute(
                "SELECT * FROM scada_receipts WHERE command_code=? ORDER BY id",
                (command_code,),
            ).fetchall()
            return {
                "duplicate": duplicate,
                "receipt": self._row_to_receipt(existing) if duplicate else self._row_to_receipt(
                    conn.execute("SELECT * FROM scada_receipts WHERE receipt_code=?", (receipt_code,)).fetchone()
                ),
                "command": self._command_view(conn, fresh),
            }
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _ensure_manual_review(self, conn, item_id, cmd):
        reason = cmd["confirm_status"]
        existing = conn.execute(
            "SELECT * FROM manual_review WHERE command_code=? AND status='open'",
            (cmd["command_code"],),
        ).fetchone()
        if existing is not None:
            if existing["reason"] != reason:
                conn.execute(
                    "UPDATE manual_review SET reason=? WHERE id=?",
                    (reason, existing["id"]),
                )
            return
        stamp = now_iso()
        conn.execute(
            """
            INSERT INTO manual_review(item_id,command_code,valve_id,reason,status,created_at)
            VALUES(?,?,?,?, 'open', ?)
            """,
            (item_id, cmd["command_code"], cmd["valve_id"], reason, stamp),
        )
        self.append_audit(
            conn,
            item_id,
            "manual_review_opened",
            "system",
            "system",
            {"command_code": cmd["command_code"], "valve_id": cmd["valve_id"], "reason": reason},
        )

    def _resolve_manual_review(self, conn, command_code):
        stamp = now_iso()
        rows = conn.execute(
            "SELECT * FROM manual_review WHERE command_code=? AND status='open'",
            (command_code,),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE manual_review SET status='resolved', resolved_at=? WHERE id=?",
                (stamp, row["id"]),
            )
            self.append_audit(
                conn,
                row["item_id"],
                "manual_review_resolved",
                "system",
                "system",
                {"command_code": command_code},
            )

    def reconcile(self):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT id, status, payload FROM items
                WHERE entity_type = 'pipeline_leak'
                  AND status NOT IN ('restored', 'cancelled')
                ORDER BY id
                """
            ).fetchall()
            items_view = []
            total_confirmed = 0
            total_unfinished = 0
            for row in rows:
                payload = json.loads(row["payload"])
                cmds = conn.execute(
                    "SELECT * FROM valve_commands WHERE item_id=? ORDER BY seq_order, id",
                    (row["id"],),
                ).fetchall()
                views = [self._command_view(conn, cmd) for cmd in cmds]
                confirmed = [c for c in views if c["confirm_status"] == "confirmed"]
                unfinished = [c for c in views if c["confirm_status"] in ("pending", "stale", "failed")]
                for cmd in views:
                    if cmd["confirm_status"] in ("confirmed", "cancelled"):
                        self._resolve_manual_review(conn, cmd["command_code"])
                    elif cmd["confirm_status"] in ("pending", "stale", "failed"):
                        self._ensure_manual_review(conn, row["id"], cmd)
                total_confirmed += len(confirmed)
                total_unfinished += len(unfinished)
                items_view.append({
                    "item_id": row["id"],
                    "status": row["status"],
                    "pipeline_id": payload.get("pipeline_id"),
                    "segment_id": payload.get("segment_id"),
                    "confirmed": confirmed,
                    "unfinished": unfinished,
                })
            conn.execute("COMMIT")
            manual = self.list_manual_review("open")
            return {
                "reconciled_at": now_iso(),
                "items": items_view,
                "summary": {
                    "confirmed_commands": total_confirmed,
                    "unfinished_commands": total_unfinished,
                    "manual_review": len(manual),
                },
                "manual_review": manual,
            }
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_manual_review(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute(
                    "SELECT * FROM manual_review WHERE status=? ORDER BY id",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM manual_review ORDER BY id").fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def resolve_manual_review(self, review_id, note, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM manual_review WHERE id=?",
                (review_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("manual_review_not_found", "人工处理记录不存在")
            if row["status"] != "open":
                raise ConflictError("manual_review_closed", "该人工处理记录已结案")
            conn.execute(
                "UPDATE manual_review SET status='resolved', resolved_at=?, resolved_by=?, note=? WHERE id=?",
                (now_iso(), actor, note or "", review_id),
            )
            self.append_audit(
                conn,
                row["item_id"],
                "manual_review_resolved",
                actor,
                role,
                {"command_code": row["command_code"], "note": note or ""},
            )
            conn.execute("COMMIT")
            return dict(conn.execute("SELECT * FROM manual_review WHERE id=?", (review_id,)).fetchone())
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()
