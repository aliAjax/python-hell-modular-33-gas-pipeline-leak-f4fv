import re

from .domain import DomainError

PLAN_ROLES = {"dispatcher", "supervisor"}
COMMAND_ROLES = {"supervisor", "responder"}
RECEIPT_ROLES = {"scada", "supervisor"}
RECONCILE_ROLES = {"dispatcher", "supervisor"}
RESOLVE_ROLES = {"supervisor"}

PLAN_OPEN_STATUSES = ("draft", "executing")
PLAN_TERMINAL_STATUSES = ("completed", "aborted")

COMMAND_OPEN_STATUSES = ("pending", "sent")
COMMAND_CONFIRMED_STATUSES = ("executed", "verified")
COMMAND_MANUAL_STATUS = "manual_review"
COMMAND_FAILED_STATUS = "failed"

RECEIPT_ACCEPT = {"executed": "executed", "verified": "verified"}
RECEIPT_FAIL = {"failed", "rejected", "timeout"}

_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _text(payload, name):
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise DomainError("field_required", "%s 不能为空" % name)
    return value.strip()


def normalize_steps(payload):
    steps = payload.get("steps")
    if not isinstance(steps, list) or not steps:
        raise DomainError("steps_required", "隔离顺序至少需要一步")
    normalized = []
    seen = set()
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise DomainError("invalid_step", "第 %d 步格式无效" % (index + 1))
        valve_id = step.get("valve_id")
        operation = step.get("operation")
        if not isinstance(valve_id, str) or not valve_id.strip():
            raise DomainError("invalid_step", "第 %d 步缺少阀门" % (index + 1))
        if operation not in ("open", "close"):
            raise DomainError("invalid_step", "第 %d 步操作必须是 open 或 close" % (index + 1))
        valve_id = valve_id.strip()
        if valve_id in seen:
            raise DomainError("invalid_step", "阀门 %s 在顺序中重复" % valve_id)
        seen.add(valve_id)
        normalized.append({"valve_id": valve_id, "operation": operation})
    return normalized


def normalize_plan(payload, item):
    segment_id = _text(payload, "segment_id")
    if segment_id != item["payload"].get("segment_id"):
        raise DomainError(
            "segment_mismatch",
            "隔离任务管段 %s 与事件管段 %s 不一致" % (segment_id, item["payload"].get("segment_id")),
            409,
        )
    return {
        "item_id": item["id"],
        "pipeline_id": item["payload"].get("pipeline_id"),
        "segment_id": segment_id,
        "steps": normalize_steps(payload),
        "note": payload.get("note", ""),
    }


def diff_steps(current_steps, new_steps):
    current = {(step["valve_id"], step["operation"]) for step in current_steps}
    new = {(step["valve_id"], step["operation"]) for step in new_steps}
    to_step = {step["valve_id"]: step["operation"] for step in new_steps}
    return {
        "only_in_active": [
            {"valve_id": valve_id, "operation": operation}
            for valve_id, operation in sorted(current - new)
        ],
        "only_in_submitted": [
            {"valve_id": valve_id, "operation": operation}
            for valve_id, operation in sorted(new - current)
        ],
        "order_changed": [step["valve_id"] for step in current_steps if step["valve_id"] in to_step]
        != [step["valve_id"] for step in new_steps if step["valve_id"] in {s["valve_id"] for s in current_steps}],
    }


def occupancy_conflict(active_plan, new_steps):
    return {
        "code": "segment_occupied",
        "message": "管段 %s 已被隔离任务 #%d 占用，请先完成或中止该任务"
        % (active_plan["segment_id"], active_plan["id"]),
        "active_plan": {
            "id": active_plan["id"],
            "item_id": active_plan["item_id"],
            "segment_id": active_plan["segment_id"],
            "status": active_plan["status"],
            "steps": active_plan["steps"],
            "created_by": active_plan["created_by"],
            "created_at": active_plan["created_at"],
        },
        "diff": diff_steps(active_plan["steps"], new_steps),
    }


def normalize_command_code(payload):
    code = _text(payload, "command_code")
    if not _CODE_RE.match(code):
        raise DomainError("invalid_command_code", "指令代号只能包含字母、数字、-、_，最长 64 位")
    return code


def normalize_targets(payload):
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets:
        raise DomainError("targets_required", "指令至少需要一个目标阀门")
    normalized = []
    seen = set()
    for target in targets:
        if not isinstance(target, dict):
            raise DomainError("invalid_target", "指令目标格式无效")
        valve_id = target.get("valve_id")
        operation = target.get("operation")
        if not isinstance(valve_id, str) or not valve_id.strip():
            raise DomainError("invalid_target", "指令目标缺少阀门")
        if operation not in ("open", "close"):
            raise DomainError("invalid_target", "指令目标操作必须是 open 或 close")
        valve_id = valve_id.strip()
        if valve_id in seen:
            raise DomainError("invalid_target", "指令目标阀门 %s 重复" % valve_id)
        seen.add(valve_id)
        normalized.append({"valve_id": valve_id, "operation": operation})
    return normalized


def targets_match(command_targets, receipt_targets):
    if receipt_targets is None:
        return True
    if not isinstance(receipt_targets, list):
        return False
    current = {(t["valve_id"], t["operation"]) for t in command_targets}
    reported = set()
    for target in receipt_targets:
        if not isinstance(target, dict):
            return False
        reported.add((target.get("valve_id"), target.get("operation")))
    return current == reported


def validate_receipt(payload):
    receipt_id = _text(payload, "receipt_id")
    result = payload.get("result")
    if result not in RECEIPT_ACCEPT and result not in RECEIPT_FAIL:
        raise DomainError("invalid_receipt_result", "回执结果必须是 executed/verified/failed/rejected/timeout")
    command_revision = payload.get("command_revision")
    if not isinstance(command_revision, int) or isinstance(command_revision, bool) or command_revision < 1:
        raise DomainError("invalid_command_revision", "回执必须携带正整数 command_revision")
    observed_at = payload.get("observed_at")
    if observed_at is not None and (not isinstance(observed_at, str) or not observed_at.strip()):
        raise DomainError("invalid_timestamp", "observed_at 必须是 ISO 时间字符串")
    return {
        "receipt_id": receipt_id,
        "result": result,
        "command_revision": command_revision,
        "observed_at": observed_at.strip() if isinstance(observed_at, str) else None,
        "detail": payload.get("detail", ""),
        "targets": payload.get("targets"),
    }


def plan_progress(steps, commands):
    """顺序已完成的前缀步数。

    回执可能迟到或乱序，确认顺序不代表现场执行顺序，因此只要求每一步
    都被至少一条已确认指令覆盖；返回第一个未覆盖步之前的长度。
    """
    covered = set()
    for command in commands:
        if command["status"] in COMMAND_CONFIRMED_STATUSES:
            for target in command["targets"]:
                covered.add((target["valve_id"], target["operation"]))
    cursor = 0
    while cursor < len(steps) and (steps[cursor]["valve_id"], steps[cursor]["operation"]) in covered:
        cursor += 1
    return cursor


def plan_blockers(plan, commands):
    blockers = []
    if plan["status"] not in PLAN_OPEN_STATUSES:
        return blockers
    for command in commands:
        if command["status"] in COMMAND_OPEN_STATUSES:
            blockers.append(
                "指令 %s 尚未确认（状态 %s）" % (command["command_code"], command["status"])
            )
        elif command["status"] == COMMAND_MANUAL_STATUS:
            blockers.append("指令 %s 待人工处理" % command["command_code"])
        elif command["status"] == COMMAND_FAILED_STATUS:
            blockers.append("指令 %s 执行失败" % command["command_code"])
    cursor = plan_progress(plan["steps"], commands)
    if cursor < len(plan["steps"]):
        step = plan["steps"][cursor]
        blockers.append("顺序第 %d 步未完成：%s %s" % (cursor + 1, step["valve_id"], step["operation"]))
    return blockers
