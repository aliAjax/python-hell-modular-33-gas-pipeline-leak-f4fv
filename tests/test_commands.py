import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError


def make_payload(pipeline, segment, reported_at):
    return {
        "pipeline_id": pipeline,
        "segment_id": segment,
        "reported_at": reported_at,
        "pressure_drop_kpa": 30,
        "sensor_value_ppm": 120,
        "odor_reports": 3,
        "reporter": "dispatch-1",
    }


class CommandLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _verified(self, pipeline, segment, reported_at):
        item = self.service.create_item(make_payload(pipeline, segment, reported_at), "d", "dispatcher")
        item = self.service.act(item["id"], "verify", {"field_confirmed": True}, "r", "responder", item["version"])
        return item

    def _cmd(self, item_id, valve_id):
        for cmd in self.service.list_commands(item_id):
            if cmd["valve_id"] == valve_id:
                return cmd
        self.fail("command for valve %s not found" % valve_id)

    def _receipt(self, cmd, result="closed", code=None, at="2026-09-27T09:00:00+00:00"):
        payload = {"command_code": cmd["command_code"], "result": result, "receipted_at": at}
        if code:
            payload["receipt_code"] = code
        return self.service.submit_receipt(payload, "scada", "dispatcher")

    def test_command_codes_and_receipt_dedup(self):
        item = self._verified("P-1", "S-8", "2026-09-27T08:00:00+00:00")
        item = self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", item["version"])
        cmds = self.service.list_commands(item["id"])
        self.assertEqual(len(cmds), 2)
        codes = {c["command_code"] for c in cmds}
        self.assertEqual(len(codes), 2)
        for code in codes:
            self.assertTrue(code.startswith("VCMD-"))

        c1 = self._cmd(item["id"], "V-1")
        first = self._receipt(c1, code="RCPT-FIXED-1")
        self.assertFalse(first["duplicate"])
        again = self._receipt(c1, code="RCPT-FIXED-1")
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["receipt"]["receipt_code"], "RCPT-FIXED-1")
        # 重复回执只算一次
        fresh = self._cmd(item["id"], "V-1")
        self.assertEqual(len(fresh["receipts"]), 1)
        self.assertEqual(fresh["confirm_status"], "confirmed")

    def test_late_receipt_for_old_version_is_stale(self):
        item = self._verified("P-1", "S-8", "2026-09-27T08:00:00+00:00")
        item = self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", item["version"])
        c1 = self._cmd(item["id"], "V-1")
        self._receipt(c1, code="R-1")
        c2 = self._cmd(item["id"], "V-2")
        self._receipt(c2, code="R-2")

        # 更新顺序：V-1 保留（版本+1），V-2 移除，新增 V-3
        item = self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-3"]}, "s", "supervisor", item["version"])
        c1 = self._cmd(item["id"], "V-1")
        self.assertEqual(c1["version"], 2)
        self.assertEqual(c1["confirm_status"], "stale")  # 旧回执失效
        c3 = self._cmd(item["id"], "V-3")
        self.assertEqual(c3["version"], 1)
        self.assertEqual(c3["confirm_status"], "pending")

        # 旧回执晚到（显式带旧版本）仍然失效，不能确认当前指令
        late = self.service.submit_receipt({
            "command_code": c1["command_code"], "command_version": 1,
            "result": "closed", "receipted_at": "2026-09-27T09:05:00+00:00",
        }, "scada", "dispatcher")
        self.assertEqual(late["receipt"]["status"], "stale")
        self.assertEqual(late["command"]["confirm_status"], "stale")

        # 旧回执未重新确认前，隔离任务拒绝前进到修复
        with self.assertRaises(DomainError) as ctx:
            self.service.act(item["id"], "repair", {"work_order": "WO-2"}, "t", "technician", item["version"])
        self.assertEqual(ctx.exception.code, "commands_not_confirmed")

        # 新版本回执到齐后放行
        self._receipt(c1, code="R-3", at="2026-09-27T09:10:00+00:00")
        self._receipt(c3, code="R-4", at="2026-09-27T09:11:00+00:00")
        item = self.service.act(item["id"], "repair", {"work_order": "WO-2"}, "t", "technician", item["version"])
        self.assertEqual(item["status"], "repaired")

    def test_failed_receipt_blocks(self):
        item = self._verified("P-1", "S-8", "2026-09-27T08:00:00+00:00")
        item = self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", item["version"])
        c1 = self._cmd(item["id"], "V-1")
        self._receipt(c1, result="failed", code="R-FAIL")
        with self.assertRaises(DomainError) as ctx:
            self.service.act(item["id"], "repair", {"work_order": "WO-1"}, "t", "technician", item["version"])
        self.assertEqual(ctx.exception.code, "commands_not_confirmed")
        blocked = ctx.exception.details["blocked"]
        self.assertTrue(any(b["valve_id"] == "V-1" and b["confirm_status"] == "failed" for b in blocked))

    def test_occupation_blocks_second_task_with_diff(self):
        a = self._verified("P-1", "S-8", "2026-09-27T08:00:00+00:00")
        a = self.service.act(a["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", a["version"])

        b = self._verified("P-1", "S-8", "2026-09-27T10:00:00+00:00")
        with self.assertRaises(ConflictError) as ctx:
            self.service.act(b["id"], "isolate", {"valve_sequence": ["V-1", "V-3"]}, "s", "supervisor", b["version"])
        self.assertEqual(ctx.exception.code, "segment_occupied")
        details = ctx.exception.details
        self.assertEqual(details["segment_id"], "S-8")
        self.assertEqual(len(details["occupiers"]), 1)
        self.assertEqual(details["occupiers"][0]["item_id"], a["id"])
        diff = details["occupiers"][0]["diff"]
        self.assertIn("V-1", diff["same"])
        self.assertIn("V-3", diff["added"])
        self.assertIn("V-2", diff["removed"])
        self.assertEqual(diff["replaced"][0]["position"], 1)
        self.assertEqual(diff["replaced"][0]["from"], "V-2")
        self.assertEqual(diff["replaced"][0]["to"], "V-3")

        # 完全相同的顺序也被占用方拒绝（差异为空）
        with self.assertRaises(ConflictError):
            self.service.act(b["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", b["version"])

        # 不同管段不冲突
        other = self._verified("P-1", "S-9", "2026-09-27T10:00:00+00:00")
        other = self.service.act(other["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", other["version"])
        self.assertEqual(other["status"], "isolated")

    def test_terminal_releases_occupation(self):
        a = self._verified("P-1", "S-8", "2026-09-27T08:00:00+00:00")
        a = self.service.act(a["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", a["version"])
        for valve, code in [("V-1", "R-1"), ("V-2", "R-2")]:
            self._receipt(self._cmd(a["id"], valve), code=code)
        a = self.service.act(a["id"], "repair", {"work_order": "WO-1"}, "t", "technician", a["version"])
        a = self.service.act(a["id"], "pressure_test", {"test_passed": True, "pressure_kpa": 150, "minimum_pressure_kpa": 100}, "t", "technician", a["version"])
        a = self.service.act(a["id"], "restore", {"hazards_clear": True}, "s", "supervisor", a["version"])
        self.assertEqual(a["status"], "restored")

        # 任务结束后占用释放，新任务可接管同一管段
        b = self._verified("P-1", "S-8", "2026-09-27T12:00:00+00:00")
        b = self.service.act(b["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", b["version"])
        self.assertEqual(b["status"], "isolated")

    def test_reconcile_lists_unfinished_and_manual_review(self):
        item = self._verified("P-1", "S-8", "2026-09-27T08:00:00+00:00")
        item = self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", item["version"])
        # 只回执 V-1，V-2 无回执
        self._receipt(self._cmd(item["id"], "V-1"), code="R-1")

        result = self.service.reconcile("sup", "supervisor")
        self.assertGreaterEqual(result["summary"]["unfinished_commands"], 1)
        self.assertGreaterEqual(result["summary"]["manual_review"], 1)
        open_reviews = self.service.list_manual_review("open")
        self.assertTrue(any(r["valve_id"] == "V-2" and r["reason"] == "pending" for r in open_reviews))

        # V-2 回执到达后，人工处理自动结案
        self._receipt(self._cmd(item["id"], "V-2"), code="R-2")
        result = self.service.reconcile("sup", "supervisor")
        self.assertEqual(result["summary"]["unfinished_commands"], 0)
        open_reviews = self.service.list_manual_review("open")
        self.assertFalse(any(r["item_id"] == item["id"] for r in open_reviews))

    def test_manual_review_resolve(self):
        item = self._verified("P-1", "S-8", "2026-09-27T08:00:00+00:00")
        item = self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", item["version"])
        self.service.reconcile("sup", "supervisor")
        open_reviews = self.service.list_manual_review("open")
        review = open_reviews[0]
        resolved = self.service.resolve_manual_review(review["id"], "现场手动确认阀门已关", "sup", "supervisor")
        self.assertEqual(resolved["status"], "resolved")
        with self.assertRaises(ConflictError):
            self.service.resolve_manual_review(review["id"], "重复处理", "sup", "supervisor")

    def test_state_survives_restart(self):
        item = self._verified("P-1", "S-8", "2026-09-27T08:00:00+00:00")
        item = self.service.act(item["id"], "isolate", {"valve_sequence": ["V-1", "V-2"]}, "s", "supervisor", item["version"])
        self._receipt(self._cmd(item["id"], "V-1"), code="R-1")
        self.service.reconcile("sup", "supervisor")

        # 模拟服务重启：新建 Repository/Service 指向同一数据库文件
        repo2 = Repository(self.tmp.name)
        repo2.initialize()
        service2 = Service(repo2)
        cmds = service2.list_commands(item["id"])
        self.assertEqual(len(cmds), 2)
        v1 = next(c for c in cmds if c["valve_id"] == "V-1")
        self.assertEqual(v1["confirm_status"], "confirmed")
        v2 = next(c for c in cmds if c["valve_id"] == "V-2")
        self.assertEqual(v2["confirm_status"], "pending")
        open_reviews = service2.list_manual_review("open")
        self.assertTrue(any(r["item_id"] == item["id"] and r["valve_id"] == "V-2" for r in open_reviews))
        # 重启后对账继续
        result = service2.reconcile("sup", "supervisor")
        self.assertGreaterEqual(result["summary"]["manual_review"], 1)


if __name__ == "__main__":
    unittest.main()
