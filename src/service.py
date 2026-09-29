from . import domain, isolation, rules
from .domain import ConflictError, DomainError


class Service:
    def __init__(self, repository):
        self.repository = repository

    def create_item(self, payload, actor, role, region=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.CREATE_ROLES:
            raise DomainError("forbidden", "当前角色不能创建此类业务记录", 403)
        normalized = domain.normalize_create(payload)
        stable_key = normalized.pop("_stable_key")
        return self.repository.create_item(
            rules.ENTITY_TYPE, stable_key, rules.INITIAL_STATUS, normalized, actor, role
        )

    def add_source(self, item_id, payload, actor, role, region=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.SOURCE_ROLES:
            raise DomainError("forbidden", "当前角色不能提交来源记录", 403)
        item = self.repository.get_item(item_id)
        normalized = domain.normalize_source(payload)
        if region and rules.ENFORCE_REGION and role != "regulator" and normalized.get("region") and normalized["region"] != region:
            raise DomainError("region_mismatch", "来源记录不属于当前管辖区域", 403)
        result = self.repository.add_source(
            item_id,
            normalized.pop("source_type"),
            normalized.pop("external_id"),
            normalized,
            normalized.pop("observed_at"),
            actor,
            role,
        )
        return result

    def act(self, item_id, action, payload, actor, role, expected_version=None, region=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        item = self.repository.get_item(item_id)
        allowed = rules.ACTION_ROLES.get(action, set())
        if role not in allowed:
            raise DomainError("forbidden", "当前角色不能执行该操作", 403)
        if rules.ENFORCE_REGION and action in rules.REGION_SENSITIVE_ACTIONS and region and role != "regulator":
            if item["payload"].get("region") != region:
                raise DomainError("region_mismatch", "不能处理其他区域的记录", 403)
        if action in rules.ACTION_REQUIRES_VERSION and expected_version is None:
            raise DomainError("expected_version_required", "该操作需要 expected_version", 400)
        new_status, new_payload, event_payload = rules.apply_action(item, action, payload, actor, role)
        self.repository.apply_action(
            item_id, action, actor, role, new_status, new_payload, event_payload, expected_version
        )
        return self.get_item(item_id)

    def get_item(self, item_id):
        item = self.repository.get_item(item_id)
        item["sources"] = self.repository.list_sources(item_id)
        item["audit"] = self.repository.audit_trail(item_id)
        item["assessment"] = rules.assess(item["payload"])
        return item

    def list_items(self, status=None):
        return self.repository.list_items(status)

    def state(self):
        return self.repository.state_summary()

    # ---- 隔离任务 / 阀门指令 ----

    def _require_identity(self, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)

    def _require_role(self, role, allowed, message):
        if role not in allowed:
            raise DomainError("forbidden", message, 403)

    def create_plan(self, item_id, payload, actor, role):
        self._require_identity(actor, role)
        self._require_role(role, isolation.PLAN_ROLES, "当前角色不能提交隔离任务")
        item = self.repository.get_item(item_id)
        if item["status"] not in ("reported", "verified"):
            raise DomainError("invalid_state", "事件状态 %s 不允许新建隔离任务" % item["status"], 409)
        normalized = isolation.normalize_plan(payload, item)
        active = self.repository.get_active_plan(normalized["segment_id"])
        if active is not None:
            detail = isolation.occupancy_conflict(active, normalized["steps"])
            raise ConflictError(detail["code"], detail["message"]).with_detail(detail)
        return self.repository.create_plan(
            normalized["item_id"],
            normalized["pipeline_id"],
            normalized["segment_id"],
            normalized["steps"],
            normalized["note"],
            actor,
            role,
        )

    def get_plan(self, plan_id):
        plan = self.repository.get_plan(plan_id)
        commands = self.repository.list_plan_commands(plan_id)
        cursor = isolation.plan_progress(plan["steps"], commands)
        plan["commands"] = commands
        plan["progress"] = {"confirmed_steps": cursor, "total_steps": len(plan["steps"])}
        plan["blockers"] = isolation.plan_blockers(plan, commands)
        return plan

    def list_plans(self, segment_id=None, item_id=None):
        return self.repository.list_plans(segment_id, item_id)

    def issue_command(self, plan_id, payload, actor, role):
        self._require_identity(actor, role)
        self._require_role(role, isolation.COMMAND_ROLES, "当前角色不能下达阀门指令")
        plan = self.repository.get_plan(plan_id)
        if plan["status"] not in isolation.PLAN_OPEN_STATUSES:
            raise DomainError("plan_closed", "隔离任务已结束，不能继续下达指令", 409)
        command_code = isolation.normalize_command_code(payload)
        targets = isolation.normalize_targets(payload)
        return self.repository.create_command(
            plan_id, command_code, targets, payload.get("note", ""), actor, role
        )

    def update_command(self, command_id, payload, actor, role):
        self._require_identity(actor, role)
        self._require_role(role, isolation.COMMAND_ROLES, "当前角色不能更新阀门指令")
        command = self.repository.get_command(command_id)
        plan = self.repository.get_plan(command["plan_id"])
        if plan["status"] not in isolation.PLAN_OPEN_STATUSES:
            raise DomainError("plan_closed", "隔离任务已结束，不能更新指令", 409)
        if command["status"] in isolation.COMMAND_CONFIRMED_STATUSES:
            raise DomainError("command_confirmed", "指令已确认，不能修改；如需变更请中止任务后重新下达", 409)
        targets = isolation.normalize_targets(payload)
        return self.repository.update_command(command_id, targets, payload.get("note", ""), actor, role)

    def record_receipt(self, command_id, payload, actor, role):
        self._require_identity(actor, role)
        self._require_role(role, isolation.RECEIPT_ROLES, "当前角色不能登记回执")
        command = self.repository.get_command(command_id)
        plan = self.repository.get_plan(command["plan_id"])
        if plan["status"] not in isolation.PLAN_OPEN_STATUSES:
            raise DomainError("plan_closed", "隔离任务已结束，回执不再受理", 409)
        receipt = isolation.validate_receipt(payload)
        if receipt["result"] in isolation.RECEIPT_ACCEPT and not isolation.targets_match(
            command["targets"], receipt["targets"]
        ):
            raise DomainError("receipt_target_mismatch", "回执内容与指令目标不一致", 409)
        command, applied, ignored = self.repository.record_receipt(command_id, receipt, actor, role)
        return {"command": command, "applied": applied, "ignored": ignored}

    def complete_plan(self, plan_id, actor, role):
        self._require_identity(actor, role)
        self._require_role(role, isolation.PLAN_ROLES, "当前角色不能完成隔离任务")
        plan = self.get_plan(plan_id)
        if plan["status"] not in isolation.PLAN_OPEN_STATUSES:
            raise DomainError("plan_closed", "隔离任务已结束", 409)
        if plan["blockers"]:
            raise DomainError(
                "isolation_blocked",
                "隔离任务拒绝前进：" + "；".join(plan["blockers"]),
                409,
            )
        return self.repository.finish_plan(
            plan_id, "completed", actor, role, "isolation_plan_completed",
            {"confirmed_steps": plan["progress"]["confirmed_steps"]},
        )

    def abort_plan(self, plan_id, payload, actor, role):
        self._require_identity(actor, role)
        self._require_role(role, isolation.PLAN_ROLES, "当前角色不能中止隔离任务")
        plan = self.repository.get_plan(plan_id)
        if plan["status"] not in isolation.PLAN_OPEN_STATUSES:
            raise DomainError("plan_closed", "隔离任务已结束", 409)
        reason = payload.get("reason", "")
        if not isinstance(reason, str) or not reason.strip():
            raise DomainError("field_required", "reason 不能为空")
        return self.repository.finish_plan(
            plan_id, "aborted", actor, role, "isolation_plan_aborted", {"reason": reason.strip()}
        )

    def reconcile(self, actor, role):
        """网络恢复后对账：列出未确认指令并全部转入人工处理。服务重启后可直接再跑。"""
        self._require_identity(actor, role)
        self._require_role(role, isolation.RECONCILE_ROLES, "当前角色不能执行对账")
        open_commands = self.repository.list_open_commands()
        reconciled = []
        for command in open_commands:
            updated = self.repository.set_command_status(
                command["id"],
                isolation.COMMAND_MANUAL_STATUS,
                actor,
                role,
                "valve_command_manual_review",
                {"reason": "网络恢复对账时仍未确认", "revision": command["revision"]},
            )
            reconciled.append(updated)
        return {
            "reconciled": reconciled,
            "manual_review": self.repository.list_manual_review_commands(),
        }

    def list_manual_review(self):
        return self.repository.list_manual_review_commands()

    def resolve_manual_command(self, command_id, payload, actor, role):
        """人工确认现场实际状态后，把待处理指令落为终态。"""
        self._require_identity(actor, role)
        self._require_role(role, isolation.RESOLVE_ROLES, "当前角色不能处理人工指令")
        command = self.repository.get_command(command_id)
        if command["status"] != isolation.COMMAND_MANUAL_STATUS:
            raise DomainError("not_in_manual_review", "指令不在人工处理列表中", 409)
        resolution = payload.get("resolution")
        if resolution not in ("executed", "verified", "failed"):
            raise DomainError("invalid_resolution", "resolution 必须是 executed/verified/failed")
        note = payload.get("note", "")
        return self.repository.set_command_status(
            command_id,
            resolution,
            actor,
            role,
            "valve_command_manual_resolved",
            {"resolution": resolution, "note": note},
        )
