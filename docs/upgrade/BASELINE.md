# 升级基线（2026-10-21）

> 本文件记录 M0 时点的可复现基线。后续每个里程碑的对比都以本文件为起点。
> **注意**：当前工作区存在大量未提交改动；本基线是“当前工作区”的事实快照，不是某个干净 commit 的快照。

## 1. 代码与工作区

| 项 | 值 | 命令 |
|---|---|---|
| HEAD | `98d4c44` | `git rev-parse --short HEAD` |
| 已修改文件 | 148 | `git status --porcelain` 统计 |
| 未跟踪文件 | 165 | 同上 |
| 后端生产代码 | 311 个 `.py` / 79,987 行 | 排除 `backend/tests` |
| 后端测试 | 222 个 `.py` / 45,184 行 | `backend/tests` |
| 前端 | 100 个 `.ts/.tsx` / 17,310 行 | `frontend/src` |
| Flink Java | 18 个 `.java` / 3,584 行 | `flink-jobs` |
| Compose 服务 | 27 个 | `docker-compose.yml` |
| healthcheck | 6 个 | 同上 |
| networks 段 | 0 个 | 同上 |

## 2. 守卫测试（本次实跑）

```bash
cd backend
python -m pytest tests/test_dormant_modules_guard.py \
  tests/test_active_module_coverage_gap.py \
  tests/test_threat_intel_pipeline_gap.py -q
```

结果：**20 passed, 22 xfailed**（31.51s）。

- dormant 守卫仍为 strict xfail：能力接线成功后会自动转红。
- 零覆盖守卫仍为 strict xfail：`protocol_parser/*`、`pcap_store.py` 等仍在清单内。
- 威胁情报写入缺口仍为 strict xfail。

## 3. Schema 校验探针（本次实跑）

```python
from schema_registry import SchemaRegistryClient
c = SchemaRegistryClient()
topics = [
  "security-events-ingest", "security-logs-raw", "security-logs-validated",
  "security-events-enriched", "security-audit-queue", "security-alerts",
  "security-logs-rejected", "security-audit-results", "ndr-flows", "edr-sysmon",
]
for t in topics:
    print(t, len(c.validate(t, {"bad": object()})))
```

结果：

| topic | errors | 结论 |
|---|---:|---|
| `security-events-ingest` | 0 | **无校验** |
| `security-logs-raw` | 5 | 有校验 |
| `security-logs-validated` | 5 | 有校验 |
| `security-events-enriched` | 5 | 有校验 |
| `security-audit-queue` | 5 | 有校验 |
| `security-alerts` | 7 | 有校验 |
| `security-logs-rejected` | 0 | **无校验** |
| `security-audit-results` | 0 | **无校验** |
| `ndr-flows` | 0 | **无校验** |
| `edr-sysmon` | 0 | **无校验** |

`TOPIC_SCHEMA_MAP` 当前前缀：`security-alerts`, `security-audit-queue`, `security-events-enriched`, `security-logs-raw`, `security-logs-validated`。

## 4. 关键默认值（本次代码核对）

| 项 | 当前值 | 位置 |
|---|---|---|
| `execution_mode` | `live` | `backend/config.py:338` |
| `.env` 是否设置 `EXECUTION_MODE` | 否 | 实际 `.env` 键清单 |
| `allow_self_registration` | **字段不存在**，注册永远开 | `backend/config.py` / `routers/auth.py` |
| `llm_budget_unlimited` | `True` | `backend/config.py:500` |
| `env_name` | `dev` | `backend/config.py:132` |
| `field_encryption_key` | 空串（`.env.example`），未配则静默关闭 | `docker-compose.yml` |

## 5. 已确认的代码事实（本次逐行核对）

- `block_ip` / `isolate_host` / `unblock_ip` / `restore_host` 直接调用 `ssh_firewall`，不走 `SafeExecutor`（`response_registry.py:288,473-648`）。
- `ssh_firewall._connect_once` 使用 `paramiko.AutoAddPolicy()`（`ssh_firewall.py:167`）。
- `transport.py` 使用 `StrictHostKeyChecking=accept-new`，`known_hosts` 缺失时退化为 `/dev/null`（`transport.py:181-194`）。
- MISP 证书校验逻辑反转：`ssl_ctx = None if not self.misp_verify_ssl else False`（`stix_taxii.py:157`）。
- `audit_triage.admit()` 重建 `TriageResult` 时未复制 `analysis_status` / `analysis_complete` / `strong_count`（`audit_triage.py:288-298`）。
- `_handle_alert` / `_handle_behavior_alert` 捕获响应编排异常后仅 warning（`kafka_consumer.py:2176-2177,2260-2261`）。
- `ThreatIoc(` 仅出现在 `models.py` 与测试中，无生产写入路径。
- `CapabilitiesDashboard` 数据来自配置开关 + Prometheus 计数（`routers/capabilities.py:17-28`），不能区分“已实现”与“已验证”。
- `components/hero/*` 无任何 import，Three.js 场景不在渲染路径上。

## 6. 待补基线

以下数据来自 2026-10-21 审计报告，本次 M0 尚未复跑；M1 完成后统一复跑并更新：

- 全量 pytest：**2776 passed, 18 skipped, 55 xfailed**，退出码 0，约 1141s。
- 总覆盖率：**64%**（CI 门禁 `--cov-fail-under=20`）。
- 零覆盖生产代码：约 **170 KB**。
- 吞异常点：**370 处**。
- 断言弱化门禁：**REPLACED=16, TEST_REMOVED=2**，退出码 0。
- Schema 校验：10 个 topic 中 5 个有校验（与本次探针一致）。

## 7. 复跑顺序（M1 后）

```bash
cd backend
python -m pytest tests -q --cov=. --cov-report=json:../artifacts/coverage-after-m1.json
python -m eval_datasets.evaluate_detection
cd ..
python tools/scan-swallowed-failures.py
python tools/scan-active-zero-coverage.py
python tools/assert-no-assert-weakening.py --base HEAD
```

所有产物写入 `artifacts/`，不提交覆盖率临时文件。
