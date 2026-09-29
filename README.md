# 燃气管线泄漏检测与隔离协调

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8333`。

- `app.py`：参数、依赖和服务生命周期。
- `src/domain.py`：管段、传感值和来源记录校验。
- `src/rules.py`：泄漏评分、阀门顺序、修复、试压、恢复状态机，以及顺序差异比对。
- `src/repository.py`：SQLite、重复保护、乐观版本、审计链、阀门指令、SCADA 回执与人工复核。
- `src/service.py`：角色权限、业务编排、跨管段占用检查与前进卡点。
- `src/http_api.py`：JSON 接口与首页。
- `src/audit.py`：可校验的审计事件。

```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8333
python3 -m unittest discover -s tests -v
```

接口包括 `GET /health`、`GET /api/state`、`POST /api/items`、`POST /api/items/<id>/sources`、`POST /api/items/<id>/actions`、`GET /api/items/<id>/commands`、`POST /api/receipts`、`POST /api/reconcile`、`GET /api/manual-review`、`POST /api/manual-review/<id>/resolve` 和审计查询。

隔离任务与阀门指令的衔接：

- **一套有效顺序**：同一 `pipeline_id + segment_id` 在任务未结束（非 restored/cancelled）前只保留一套有效顺序。第二个任务下发隔离指令时返回 `409 segment_occupied`，并在 `details.occupiers` 中给出占用方任务与其阀门顺序差异（`same`/`added`/`removed`/`replaced`）。
- **指令独立代号**：隔离（`isolate`）会为顺序中每个阀门下发一条阀门指令（`VCMD-...`）。SCADA 回执通过 `POST /api/receipts` 提交，携带 `command_code`、`result`、`receipted_at`；回执有独立代号 `receipt_code`，重复提交幂等（`duplicate=true`），只计一次。
- **版本与失效**：指令更新（重新 `isolate`）后版本号递增，旧版本回执标记为 `stale`；在收到当前版本回执前，`repair`/`restore` 返回 `409 commands_not_confirmed`，隔离任务拒绝前进。
- **对账与人工**：断网恢复后 `POST /api/reconcile` 扫描所有未结束任务的指令，未确认（`pending`/`stale`/`failed`）的指令列入人工复核 `manual_review`；指令确认后复核自动结案，也可人工 `resolve`。
- **状态接续**：指令、回执、人工复核全部落 SQLite，重启服务后状态自动接续。

模型不替代 SCADA、管网水力计算或正式应急预案。
