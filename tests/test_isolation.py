import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError


class IsolationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)
        self.item = self.service.create_item({
            "pipeline_id": "P-9",
            "segment_id": "S-1",
            "reported_at": "2026-09-28T08:00:00+00:00",
            "pressure_drop_kpa": 30,
            "sensor_value_ppm": 120,
            "odor_reports": 2,
            "reporter": "dispatch-1",
        }, "dispatch-1", "dispatcher")

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _plan(self, segment="S-1", steps=None):
        return self.service.create_plan(self.item["id"], {
            "segment_id": segment,
            "steps": steps or [
                {"valve_id": "V-1", "operation": "close"},
                {"valve_id": "V-2", "operation": "close"},
            ],
        }, "sup-1", "supervisor")

    def _command(self, plan_id, code="CMD-001", valve="V-1"):
        return self.service.issue_command(plan_id, {
            "command_code": code,
            "targets": [{"valve_id": valve, "operation": "close"}],
        }, "sup-1", "supervisor")

    def _receipt(self, command_id, receipt_id, revision=1, result="executed"):
        return self.service.record_receipt(command_id, {
            "receipt_id": receipt_id,
            "result": result,
            "command_revision": revision,
        }, "scada-1", "scada")

    def test_second_plan_sees_occupancy_and_diff(self):
        plan = self._plan()
        with self.assertRaises(ConflictError) as context:
            self._plan(steps=[{"valve_id": "V-3", "operation": "close"}])
        exc = context.exception
        self.assertEqual(exc.code, "segment_occupied")
        self.assertEqual(exc.detail["active_plan"]["id"], plan["id"])
        self.assertEqual(
            exc.detail["diff"]["only_in_submitted"],
            [{"operation": "close", "valve_id": "V-3"}],
        )
        self.assertEqual(
            {s["valve_id"] for s in exc.detail["diff"]["only_in_active"]}, {"V-1", "V-2"}
        )
        # 其他管段不受影响
        other_item = self.service.create_item({
            "pipeline_id": "P-9",
            "segment_id": "S-2",
            "reported_at": "2026-09-28T08:30:00+00:00",
            "pressure_drop_kpa": 10,
            "sensor_value_ppm": 40,
            "odor_reports": 0,
            "reporter": "dispatch-1",
        }, "dispatch-1", "dispatcher")
        other = self.service.create_plan(other_item["id"], {
            "segment_id": "S-2",
            "steps": [{"valve_id": "V-7", "operation": "close"}],
        }, "sup-1", "supervisor")
        self.assertEqual(other["status"], "draft")

    def test_command_code_unique_and_duplicate_receipt_counted_once(self):
        plan = self._plan()
        command = self._command(plan["id"])
        self.assertEqual(command["revision"], 1)
        with self.assertRaises(ConflictError) as context:
            self._command(plan["id"], code="CMD-001", valve="V-9")
        self.assertEqual(context.exception.code, "duplicate_command_code")
        first = self._receipt(command["id"], "RCV-1")
        self.assertTrue(first["applied"])
        self.assertEqual(first["command"]["status"], "executed")
        second = self._receipt(command["id"], "RCV-1")
        self.assertFalse(second["applied"])
        self.assertEqual(second["ignored"], "duplicate_receipt")
        self.assertEqual(len(self.repo.list_receipts(command["id"])), 1)

    def test_update_invalidates_old_receipts_and_blocks_progress(self):
        plan = self._plan()
        command = self._command(plan["id"])
        self._command(plan["id"], code="CMD-002", valve="V-2")
        # 指令更新：修订号递增，旧回执失效
        updated = self.service.update_command(command["id"], {
            "targets": [{"valve_id": "V-1", "operation": "close"}, {"valve_id": "V-3", "operation": "close"}],
        }, "sup-1", "supervisor")
        self.assertEqual(updated["revision"], 2)
        self.assertEqual(updated["status"], "pending")
        stale = self._receipt(command["id"], "RCV-old", revision=1)
        self.assertFalse(stale["applied"])
        self.assertEqual(stale["ignored"], "stale_revision")
        self.assertEqual(stale["command"]["status"], "pending")
        # 指令未确认，隔离任务拒绝前进
        with self.assertRaises(DomainError) as context:
            self.service.complete_plan(plan["id"], "sup-1", "supervisor")
        self.assertEqual(context.exception.code, "isolation_blocked")
        # 新修订回执生效
        fresh = self._receipt(command["id"], "RCV-new", revision=2)
        self.assertTrue(fresh["applied"])
        self.assertEqual(fresh["command"]["status"], "executed")

    def test_complete_requires_full_sequence_and_releases_segment(self):
        plan = self._plan()
        c1 = self._command(plan["id"])
        c2 = self._command(plan["id"], code="CMD-002", valve="V-2")
        self._receipt(c1["id"], "RCV-1")
        with self.assertRaises(DomainError) as context:
            self.service.complete_plan(plan["id"], "sup-1", "supervisor")
        self.assertEqual(context.exception.code, "isolation_blocked")
        self._receipt(c2["id"], "RCV-2")
        done = self.service.complete_plan(plan["id"], "sup-1", "supervisor")
        self.assertEqual(done["status"], "completed")
        # 管段释放后可以提交新计划
        follow_up = self._plan()
        self.assertEqual(follow_up["status"], "draft")

    def test_reconcile_lists_unconfirmed_and_restart_keeps_state(self):
        plan = self._plan()
        command = self._command(plan["id"])
        # 模拟服务重启：同一数据库新建 Repository/Service
        restarted = Service(Repository(self.tmp.name))
        result = restarted.reconcile("sup-1", "supervisor")
        self.assertEqual([c["id"] for c in result["reconciled"]], [command["id"]])
        self.assertEqual(result["reconciled"][0]["status"], "manual_review")
        self.assertEqual(len(result["manual_review"]), 1)
        # 待人工处理期间任务拒绝前进
        with self.assertRaises(DomainError) as context:
            restarted.complete_plan(plan["id"], "sup-1", "supervisor")
        self.assertEqual(context.exception.code, "isolation_blocked")
        # 人工确认现场状态后解除阻塞
        restarted.resolve_manual_command(command["id"], {"resolution": "executed"}, "sup-1", "supervisor")
        c2 = restarted.issue_command(plan["id"], {
            "command_code": "CMD-002",
            "targets": [{"valve_id": "V-2", "operation": "close"}],
        }, "sup-1", "supervisor")
        restarted.record_receipt(c2["id"], {
            "receipt_id": "RCV-2", "result": "executed", "command_revision": 1,
        }, "scada-1", "scada")
        done = restarted.complete_plan(plan["id"], "sup-1", "supervisor")
        self.assertEqual(done["status"], "completed")
        # 重启后状态仍可读出
        again = Service(Repository(self.tmp.name))
        self.assertEqual(again.get_plan(plan["id"])["status"], "completed")
        self.assertEqual(again.list_manual_review(), [])

    def test_closed_plan_rejects_commands_and_receipts(self):
        plan = self._plan()
        command = self._command(plan["id"])
        aborted = self.service.abort_plan(plan["id"], {"reason": "改用另一套方案"}, "sup-1", "supervisor")
        self.assertEqual(aborted["status"], "aborted")
        with self.assertRaises(DomainError) as context:
            self._command(plan["id"], code="CMD-002", valve="V-2")
        self.assertEqual(context.exception.code, "plan_closed")
        with self.assertRaises(DomainError) as context:
            self._receipt(command["id"], "RCV-late")
        self.assertEqual(context.exception.code, "plan_closed")
        # 中止后管段释放
        follow_up = self._plan()
        self.assertEqual(follow_up["status"], "draft")

    def test_multi_target_command_covers_steps_but_no_skipping(self):
        plan = self._plan(steps=[
            {"valve_id": "V-1", "operation": "close"},
            {"valve_id": "V-2", "operation": "close"},
            {"valve_id": "V-3", "operation": "close"},
        ])
        # 一条指令同时覆盖第 2、3 步：不能跳步，任务仍拒绝前进
        skip = self.service.issue_command(plan["id"], {
            "command_code": "CMD-SKIP",
            "targets": [
                {"valve_id": "V-2", "operation": "close"},
                {"valve_id": "V-3", "operation": "close"},
            ],
        }, "sup-1", "supervisor")
        self._receipt(skip["id"], "RCV-skip")
        with self.assertRaises(DomainError) as context:
            self.service.complete_plan(plan["id"], "sup-1", "supervisor")
        self.assertEqual(context.exception.code, "isolation_blocked")
        # 补上第 1 步后，已确认的多目标指令顺势覆盖后续步骤
        first = self._command(plan["id"], code="CMD-FIRST", valve="V-1")
        self._receipt(first["id"], "RCV-first")
        done = self.service.complete_plan(plan["id"], "sup-1", "supervisor")
        self.assertEqual(done["status"], "completed")

    def test_plan_requires_matching_segment_and_permission(self):
        with self.assertRaises(DomainError) as context:
            self.service.create_plan(self.item["id"], {
                "segment_id": "S-OTHER",
                "steps": [{"valve_id": "V-1", "operation": "close"}],
            }, "sup-1", "supervisor")
        self.assertEqual(context.exception.code, "segment_mismatch")
        with self.assertRaises(DomainError) as context:
            self.service.create_plan(self.item["id"], {
                "segment_id": "S-1",
                "steps": [{"valve_id": "V-1", "operation": "close"}],
            }, "sensor-1", "sensor")
        self.assertEqual(context.exception.status, 403)


if __name__ == "__main__":
    unittest.main()
