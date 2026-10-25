# 免费威胁情报源接线 — 证据与运维说明(2026-10-25)

## 此前状态(质量评审短板)

`SHARED_MEMORY_MISP_URL` / `SHARED_MEMORY_TAXII_URL` 均为空,`_import_csv`
只支持本地文件 —— 平台情报链路"客户端就绪、零真实情报",capabilities.yaml
threat_intel 条目自评 experimental,能力看板 count 恒 0。

## 现在的接线

| 源 | feed_type | 内容 | 费用/Key |
|---|---|---|---|
| abuse.ch Feodo Tracker | `csv_http`(csv 方言) | Botnet C2 IP 黑名单(Emotet/QakBot 等,数千条) | 免费,无 Key |
| OpenPhish free feed | `csv_http`(plain 方言) | 活跃钓鱼 URL 列表 | 免费,无 Key |

链路:`threat_intel_feeds` 表 → scheduler 每小时轮询(或手动 POST
`/api/intel/feeds/{id}/poll`)→ `stix_taxii._import_csv_http`(HTTP 拉取,
注释头剥离,方言映射)→ `ioc_ingest.store_iocs`(规范化:非法 IP/过期情报
不落库)→ `ioc_matcher.refresh_cache` → 事件富化与 `/api/intel/match` 命中。

## 一键接线

```bash
SOC_BASE=http://<平台>:8001 SOC_USER=admin SOC_PASS=*** \
  bash tools/seed-free-intel-feeds.sh
# 输出 IOC 规模与样例 —— 即答辩证据(截图存档 docs/drill/evidence/)
```

## 顺带修复的接线缺陷

1. `scheduler._poll_due_feeds` 与 `POST /intel/feeds/{id}/poll` 构建 cfg 时
   **漏传 `config` JSON 列** —— 即使库里配了方言映射也永远按默认解析;
2. `POST /intel/feeds` 的 feed_type 白名单不认 `csv_http`;
3. `_import_csv` 本地路径语义保留(value|ioc_value / type|ioc_type 回退链),
   由 `tests/test_intel_csv_http_feeds.py::test_legacy_local_csv_semantics_preserved`
   锁定。

## 单元测试锚点

`backend/tests/test_intel_csv_http_feeds.py`(5 条):
- Feodo 方言解析(2026-03 实抓真实表头,上游改版即红)
- OpenPhish plain 格式
- 旧本地 csv 语义不回退
- poll_feed dispatch → store_iocs 端到端(sqlite)
- csv_http 拒绝非 http(s) url(路径穿越面)

## 升级 verified 的判据

- [ ] 云服务器上运行 seed 脚本,IOC 落库 ≥1000 条(Feodo 单源)
- [ ] `/api/intel/match` 用库内真实 IOC 命中一次(样例截图)
- [ ] 事件富化:注入 src_ip=库内 C2 IP 的事件,告警上下文带 TI 字段
- [ ] capabilities.yaml threat_intel: experimental → verified(附证据链接)
