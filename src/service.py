from . import domain, rules
from .domain import DomainError, ConflictError
from .rules import sequence_diff


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

        commands = None
        is_update = False
        if action == "isolate":
            is_update = item["status"] == "isolated"
            if not is_update:
                pipeline_id = item["payload"]["pipeline_id"]
                segment_id = item["payload"]["segment_id"]
                occupiers = self.repository.find_occupiers(item_id, pipeline_id, segment_id)
                if occupiers:
                    submitted = payload.get("valve_sequence") if isinstance(payload, dict) else None
                    err = ConflictError("segment_occupied", "同一管段已有未结束的隔离任务，只保留一套有效顺序")
                    err.details = {
                        "pipeline_id": pipeline_id,
                        "segment_id": segment_id,
                        "occupiers": [
                            {
                                "item_id": occ["item_id"],
                                "status": occ["status"],
                                "valve_sequence": occ["valve_sequence"],
                                "diff": sequence_diff(occ["valve_sequence"], submitted or []),
                            }
                            for occ in occupiers
                        ],
                    }
                    raise err

        if action in ("repair", "restore"):
            blocked = self.repository.command_gate(item_id)
            if blocked:
                err = DomainError("commands_not_confirmed", "阀门指令未全部确认，隔离任务拒绝前进", 409)
                err.details = {"blocked": [
                    {
                        "command_code": c["command_code"],
                        "valve_id": c["valve_id"],
                        "version": c["version"],
                        "confirm_status": c["confirm_status"],
                    }
                    for c in blocked
                ]}
                raise err

        new_status, new_payload, event_payload = rules.apply_action(item, action, payload, actor, role)
        if action == "isolate":
            commands = new_payload["valve_sequence"]
        self.repository.apply_action(
            item_id, action, actor, role, new_status, new_payload, event_payload, expected_version,
            commands=commands, is_update=is_update,
        )
        return self.get_item(item_id)

    def submit_receipt(self, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.RECEIPT_ROLES:
            raise DomainError("forbidden", "当前角色不能提交 SCADA 回执", 403)
        normalized = domain.normalize_receipt(payload)
        return self.repository.add_receipt(
            normalized["command_code"],
            normalized["command_version"],
            normalized["result"],
            normalized["receipted_at"],
            normalized["receipt_code"],
            normalized,
            actor,
            role,
        )

    def list_commands(self, item_id):
        self.repository.get_item(item_id)
        return self.repository.list_commands(item_id)

    def reconcile(self, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.RECONCILE_ROLES:
            raise DomainError("forbidden", "当前角色不能执行对账", 403)
        return self.repository.reconcile()

    def list_manual_review(self, status=None):
        return self.repository.list_manual_review(status)

    def resolve_manual_review(self, review_id, note, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.MANUAL_REVIEW_ROLES:
            raise DomainError("forbidden", "当前角色不能处理人工复核", 403)
        return self.repository.resolve_manual_review(review_id, note, actor, role)

    def get_item(self, item_id):
        item = self.repository.get_item(item_id)
        item["sources"] = self.repository.list_sources(item_id)
        item["audit"] = self.repository.audit_trail(item_id)
        item["commands"] = self.repository.list_commands(item_id)
        item["assessment"] = rules.assess(item["payload"])
        return item

    def list_items(self, status=None):
        return self.repository.list_items(status)

    def state(self):
        return self.repository.state_summary()
