import json
import sqlite3
from datetime import datetime, timezone

from .audit import audit_hash, canonical_json
from .domain import ConflictError, NotFoundError, DomainError


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
                CREATE TABLE IF NOT EXISTS isolation_plans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    pipeline_id TEXT NOT NULL,
                    segment_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    steps TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_isolation_plans_active_segment
                    ON isolation_plans(segment_id) WHERE status IN ('draft','executing');
                CREATE TABLE IF NOT EXISTS valve_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_code TEXT NOT NULL UNIQUE,
                    plan_id INTEGER NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL,
                    targets TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(plan_id) REFERENCES isolation_plans(id)
                );
                CREATE TABLE IF NOT EXISTS valve_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT NOT NULL UNIQUE,
                    command_id INTEGER NOT NULL,
                    command_revision INTEGER NOT NULL,
                    result TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    targets TEXT,
                    observed_at TEXT,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(command_id) REFERENCES valve_commands(id)
                );
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

    def apply_action(self, item_id, action, actor, role, new_status, new_payload, event_payload, expected_version=None):
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

    # ---- 隔离任务 / 阀门指令 / 回执 ----

    def _row_to_plan(self, row):
        if row is None:
            return None
        result = dict(row)
        result["steps"] = json.loads(result["steps"])
        return result

    def _row_to_command(self, row):
        if row is None:
            return None
        result = dict(row)
        result["targets"] = json.loads(result["targets"])
        return result

    def _row_to_receipt(self, row):
        if row is None:
            return None
        result = dict(row)
        if result.get("targets"):
            result["targets"] = json.loads(result["targets"])
        return result

    def _get_plan_for_update(self, conn, plan_id):
        row = conn.execute("SELECT * FROM isolation_plans WHERE id=?", (plan_id,)).fetchone()
        if row is None:
            raise NotFoundError("plan_not_found", "隔离任务不存在")
        return self._row_to_plan(row)

    def _get_command_for_update(self, conn, command_id):
        row = conn.execute("SELECT * FROM valve_commands WHERE id=?", (command_id,)).fetchone()
        if row is None:
            raise NotFoundError("command_not_found", "阀门指令不存在")
        return self._row_to_command(row)

    def _commands_of_plan(self, conn, plan_id):
        rows = conn.execute(
            "SELECT * FROM valve_commands WHERE plan_id=? ORDER BY id", (plan_id,)
        ).fetchall()
        return [self._row_to_command(row) for row in rows]

    def create_plan(self, item_id, pipeline_id, segment_id, steps, note, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO isolation_plans(item_id,pipeline_id,segment_id,status,steps,note,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (item_id, pipeline_id, segment_id, "draft", canonical_json(steps), note, actor, role, now_iso(), now_iso()),
                )
            except sqlite3.IntegrityError:
                active = conn.execute(
                    "SELECT * FROM isolation_plans WHERE segment_id=? AND status IN ('draft','executing')",
                    (segment_id,),
                ).fetchone()
                raise ConflictError("segment_occupied", "管段 %s 已被隔离任务 #%s 占用" % (segment_id, active["id"] if active else "?"))
            plan_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn, item_id, "isolation_plan_created", actor, role,
                {"plan_id": plan_id, "segment_id": segment_id, "steps": steps},
            )
            conn.execute("COMMIT")
            return self.get_plan(plan_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_plan(self, plan_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM isolation_plans WHERE id=?", (plan_id,)).fetchone()
            if row is None:
                raise NotFoundError("plan_not_found", "隔离任务不存在")
            return self._row_to_plan(row)
        finally:
            conn.close()

    def list_plans(self, segment_id=None, item_id=None):
        conn = self.connect()
        try:
            sql = "SELECT * FROM isolation_plans"
            clauses, params = [], []
            if segment_id:
                clauses.append("segment_id=?")
                params.append(segment_id)
            if item_id:
                clauses.append("item_id=?")
                params.append(item_id)
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            sql += " ORDER BY id DESC"
            return [self._row_to_plan(row) for row in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def get_active_plan(self, segment_id):
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM isolation_plans WHERE segment_id=? AND status IN ('draft','executing')",
                (segment_id,),
            ).fetchone()
            return self._row_to_plan(row)
        finally:
            conn.close()

    def list_plan_commands(self, plan_id):
        conn = self.connect()
        try:
            return self._commands_of_plan(conn, plan_id)
        finally:
            conn.close()

    def set_plan_status(self, conn, plan_id, status):
        conn.execute(
            "UPDATE isolation_plans SET status=?,updated_at=? WHERE id=?",
            (status, now_iso(), plan_id),
        )

    def create_command(self, plan_id, command_code, targets, note, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            plan = self._get_plan_for_update(conn, plan_id)
            try:
                conn.execute(
                    "INSERT INTO valve_commands(command_code,plan_id,revision,status,targets,note,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (command_code, plan_id, 1, "pending", canonical_json(targets), note, actor, role, now_iso(), now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_command_code", "指令代号 %s 已存在" % command_code)
            command_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            if plan["status"] == "draft":
                self.set_plan_status(conn, plan_id, "executing")
            self.append_audit(
                conn, plan["item_id"], "valve_command_issued", actor, role,
                {"plan_id": plan_id, "command_id": command_id, "command_code": command_code, "revision": 1, "targets": targets},
            )
            conn.execute("COMMIT")
            return self.get_command(command_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_command(self, command_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM valve_commands WHERE id=?", (command_id,)).fetchone()
            if row is None:
                raise NotFoundError("command_not_found", "阀门指令不存在")
            return self._row_to_command(row)
        finally:
            conn.close()

    def get_command_by_code(self, command_code):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM valve_commands WHERE command_code=?", (command_code,)).fetchone()
            if row is None:
                raise NotFoundError("command_not_found", "阀门指令 %s 不存在" % command_code)
            return self._row_to_command(row)
        finally:
            conn.close()

    def update_command(self, command_id, targets, note, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            command = self._get_command_for_update(conn, command_id)
            plan = self._get_plan_for_update(conn, command["plan_id"])
            revision = int(command["revision"]) + 1
            conn.execute(
                "UPDATE valve_commands SET revision=?,status='pending',targets=?,note=?,updated_at=? WHERE id=?",
                (revision, canonical_json(targets), note, now_iso(), command_id),
            )
            self.append_audit(
                conn, plan["item_id"], "valve_command_updated", actor, role,
                {
                    "plan_id": plan["id"],
                    "command_id": command_id,
                    "command_code": command["command_code"],
                    "revision": revision,
                    "targets": targets,
                    "invalidated_before_revision": revision,
                },
            )
            conn.execute("COMMIT")
            return self.get_command(command_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def record_receipt(self, command_id, receipt, actor, role):
        """登记回执。同一 receipt_id 只算一次；只接受当前修订的回执。

        返回 (command, applied, ignored_reason)。
        """
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            command = self._get_command_for_update(conn, command_id)
            plan = self._get_plan_for_update(conn, command["plan_id"])
            existing = conn.execute(
                "SELECT * FROM valve_receipts WHERE receipt_id=?", (receipt["receipt_id"],)
            ).fetchone()
            if existing is not None:
                conn.execute("COMMIT")
                return self.get_command(command_id), False, "duplicate_receipt"
            if receipt["command_revision"] != int(command["revision"]):
                conn.execute("COMMIT")
                return self.get_command(command_id), False, "stale_revision"
            try:
                conn.execute(
                    "INSERT INTO valve_receipts(receipt_id,command_id,command_revision,result,detail,targets,observed_at,actor,role,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        receipt["receipt_id"],
                        command_id,
                        receipt["command_revision"],
                        receipt["result"],
                        receipt["detail"],
                        canonical_json(receipt["targets"]) if receipt["targets"] is not None else None,
                        receipt["observed_at"],
                        actor,
                        role,
                        now_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                conn.execute("COMMIT")
                return self.get_command(command_id), False, "duplicate_receipt"
            if receipt["result"] in ("executed", "verified"):
                new_status = receipt["result"]
            else:
                new_status = "failed"
            conn.execute(
                "UPDATE valve_commands SET status=?,updated_at=? WHERE id=?",
                (new_status, now_iso(), command_id),
            )
            self.append_audit(
                conn, plan["item_id"], "valve_receipt_recorded", actor, role,
                {
                    "plan_id": plan["id"],
                    "command_id": command_id,
                    "command_code": command["command_code"],
                    "receipt_id": receipt["receipt_id"],
                    "command_revision": receipt["command_revision"],
                    "result": receipt["result"],
                },
            )
            conn.execute("COMMIT")
            return self.get_command(command_id), True, None
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_receipts(self, command_id):
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM valve_receipts WHERE command_id=? ORDER BY id", (command_id,)
            ).fetchall()
            return [self._row_to_receipt(row) for row in rows]
        finally:
            conn.close()

    def set_command_status(self, command_id, status, actor, role, event_type, event_payload):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            command = self._get_command_for_update(conn, command_id)
            plan = self._get_plan_for_update(conn, command["plan_id"])
            conn.execute(
                "UPDATE valve_commands SET status=?,updated_at=? WHERE id=?",
                (status, now_iso(), command_id),
            )
            payload = dict(event_payload)
            payload.update({"plan_id": plan["id"], "command_id": command_id, "command_code": command["command_code"]})
            self.append_audit(conn, plan["item_id"], event_type, actor, role, payload)
            conn.execute("COMMIT")
            return self.get_command(command_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_open_commands(self):
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM valve_commands WHERE status IN ('pending','sent') ORDER BY id"
            ).fetchall()
            return [self._row_to_command(row) for row in rows]
        finally:
            conn.close()

    def list_manual_review_commands(self):
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM valve_commands WHERE status='manual_review' ORDER BY id"
            ).fetchall()
            return [self._row_to_command(row) for row in rows]
        finally:
            conn.close()

    def finish_plan(self, plan_id, status, actor, role, event_type, event_payload):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            plan = self._get_plan_for_update(conn, plan_id)
            self.set_plan_status(conn, plan_id, status)
            payload = dict(event_payload)
            payload.update({"plan_id": plan_id, "segment_id": plan["segment_id"]})
            self.append_audit(conn, plan["item_id"], event_type, actor, role, payload)
            conn.execute("COMMIT")
            return self.get_plan(plan_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()
