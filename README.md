# 燃气管线泄漏检测与隔离协调

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8333`。

- `app.py`：参数、依赖和服务生命周期。
- `src/domain.py`：管段、传感值和来源记录校验。
- `src/rules.py`：泄漏评分、阀门顺序、修复、试压、恢复状态机。
- `src/isolation.py`：隔离任务占用、阀门指令修订、回执与对账规则。
- `src/repository.py`：SQLite、重复保护、乐观版本和审计链。
- `src/service.py`：角色权限和业务编排。
- `src/http_api.py`：JSON 接口与首页。
- `src/audit.py`：可校验的审计事件。

```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8333
python3 -m unittest discover -s tests -v
```

接口包括 `GET /health`、`GET /api/state`、`POST /api/items`、`POST /api/items/<id>/sources`、`POST /api/items/<id>/actions` 和审计查询。测试覆盖完整抢修流程、重复事件、阀门顺序、试压阈值、现场危险条件、权限和版本冲突。模型不替代 SCADA、管网水力计算或正式应急预案。

## 隔离任务与阀门指令

断网恢复后同一管段可能重复开出隔离方案，本模块把隔离任务和阀门指令绑定，保证管段未结束前只有一套有效顺序：

- `POST /api/items/<id>/plans` 提交隔离任务。同一管段存在未结束任务时返回 `409 segment_occupied`，响应 `detail` 中带占用方任务和两套顺序的差异（`only_in_active` / `only_in_submitted` / `order_changed`），后提交者据此决定等待或中止对方。
- `POST /api/plans/<id>/commands` 下达阀门指令，`command_code` 全局唯一，重复代号返回 `409 duplicate_command_code`。
- `POST /api/commands/<id>/receipts` 登记 SCADA 回执。`receipt_id` 全局唯一，重复回执只算一次（返回 `applied=false, ignored=duplicate_receipt`）；回执必须携带 `command_revision`，与当前修订不符的迟到回执被忽略（`ignored=stale_revision`）。
- `POST /api/commands/<id>/update` 更新指令内容，修订号递增并回到待确认，此前回执全部失效；存在未确认或待人工指令时 `POST /api/plans/<id>/complete` 返回 `409 isolation_blocked`，隔离任务拒绝前进。
- `POST /api/reconcile` 网络恢复后对账，把所有未确认指令转入人工处理列表（`GET /api/commands/manual-review`），由 `POST /api/commands/<id>/resolve` 按现场实际状态落为终态。
- 全部状态存于 SQLite（指令修订、回执、任务状态），服务重启后自动接续，可直接重新对账。
