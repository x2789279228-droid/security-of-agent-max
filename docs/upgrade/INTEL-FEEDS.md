# INTEL-FEEDS —— 免费威胁情报源登记表（REMEDIATION-PLAN-2026-10-30 路线 D）

> **唯一事实源**：每源的接入方式、配置、许可与**实测状态**以本文件为准。
> 红线：不许把"目标"写成"实测"——下表"状态"列只写真实探测结果；
> 部署环境（服务器/代理白名单）与开发机出口网络不同，上线后请重跑探测并更新本表。
>
> 探测日期：2026-10-30（开发机出口，直接 httpx，非平台内轮询）。
> 一键注册脚本：`bash tools/seed-free-intel-feeds.sh`（幂等，注册 12 个无 key 源；`POLL=0` 只注册不拉取）。

## 一、已接线源（脚本可一键注册，无 key）

| # | 源 | 类型 | feed_type / 配置要点 | 许可/条件 | 状态（2026-10-30） |
|---|---|---|---|---|---|
| 1 | abuse.ch Feodo Tracker | ip | `csv_http` csv，`value_column=dst_ip` | 免费，非商用 | ✅ 真通（HTTP 200；此前已落库） |
| 2 | OpenPhish 社区版 | url | `csv_http` plain，`fixed_type=url` | 免费社区 feed | ✅ 真通（HTTP 200） |
| 3 | abuse.ch URLhaus | url | `csv_http` csv，`value_column=url` | 免费，非商用 | ✅ 此前已真通（同 abuse.ch 域） |
| 4 | CISA KEV | cve | `kev_json`（命中自动提级已接线） | 美国公共域 | ✅ 此前已真通 |
| 5 | abuse.ch ThreatFox | ip/domain/url | **`json_api`** POST，`items_path=data`，`type_map` 含 `ip:port→ip` + `strip_port` | 免费，非商用 | ⚠ 适配器就绪；本机探测端点 404（端点疑似变更或出口限制），部署环境待核 |
| 6 | abuse.ch MalwareBazaar | file_hash | **`json_api`** POST，`value_path=sha256_hash` | 免费，非商用 | ⚠ 同上（ConnectError） |
| 7 | abuse.ch SSL Blacklist | **ja3** | `csv_http` csv，`value_column=ja3_md5`，`fixed_type=ja3` | 免费，非商用 | ⚠ ReadTimeout（出口限制），部署环境待核 |
| 8 | Spamhaus DROP | **cidr** | `csv_http` plain + `split_delimiter=";"`（"1.2.4.0/22 ; SBL…" 行） | 研究用途免费 | ⚠ 待核（本机未测通出口） |
| 9 | FireHOL level1 | ip | `csv_http` plain（GitHub raw） | 开放 | ⚠ raw.githubusercontent 出口 404，部署环境待核 |
| 10 | blocklist.de | ip | `csv_http` plain | 免费 | ⚠ 端点 404（服务疑似调整/停运），待核后决定去留 |
| 11 | Tor exit list | ip | `csv_http` plain | 开放 | ⚠ ConnectError（出口限制） |
| 12 | Cisco Talos IP BL | ip | `csv_http` plain | 免费列表 | ⚠ HTTP 403（可能 UA/地域限制），待核 |

## 二、第二批（需 key / 端点待核，2026-10-30 探测后状态更新）

| # | 源 | 类型 | 通道 | 状态（2026-10-30 实测） |
|---|---|---|---|---|
| 13 | AlienVault OTX | ip/domain/url/hash | `stix_bundle`（export 返回 STIX 2.1 bundle） | **主机可达（HTTP 403 = 需免费 key）**。传输层已支持源特定 header（`_fetch_text(extra_headers=)`，跨 host 重定向与 Authorization 同规剥离）。接入路径：部署机 `curl -H "X-OTX-API-KEY: …" → intel_local_feed_dir 白名单目录 → stix_bundle 导入`（两步）；或后续新增远程 stix 拉取适配。**阻塞点=免费 key**，非代码 |
| 14 | ET Open（Anomali Limo） | stix | 现有 **`taxii`** feed_type | **本机出口不可达（ConnectError）**。`taxii` 通道代码就绪（ALLOWED_FEED_TYPES 含 taxii），部署环境（服务器/代理白名单）可达后即可完成"真实 TAXII 拉取演练"——这正是 capabilities threat_intel 升 verified 的最后缺口 |
| 15 | botvrij.eu MISP OSINT | ip/domain/url/hash | **`misp_feed`**（2026-10-30 新通道：manifest.json+事件JSON 静态目录, 免 key） | ✅ **2026-10-30 真拉取演练完成**：正确路径 `/data/feed-osint/`（此前探测用错路径）→ 25 事件 → **884 条 IOC 落库**（file_hash 358/domain 284/ip 183/url 59, 零错误）——threat_intel 升 verified 的直接证据 |
| 16 | PhishTank | url | `json_api` GET + key | 未接（需免费 key）；header 变体已就绪 |
| 17 | ransomware.live | domain/ip | `json_api` | 端点变更待核（旧 `ransomwhat.telemetry.ltd` 已返回 HTML） |

**第二批结论（2026-10-30 更新）**：**botvrij MISP feed 真拉取已达成**（`misp_feed` 免 key 通道, 884 IOC 落库）——`misp`/`taxii` REST 通道与 OTX header 变体代码就绪, 待部署环境凭据（OTX 403=需 key, ET Open 本机出口不可达）。

## 三、工程说明

- **json_api 适配器**（2026-10-30 新增）：`backend/threat_intel/stix_taxii.py::_import_json_api`
  —— dotted-path 取数（`items_path`/`value_path`/`type_path`/`threat_path`）+
  类型别名映射（`type_map`，内置 `_JSON_TYPE_ALIASES`）+ `strip_port`（ThreatFox `ip:port` 形态）；
  POST 走 `_post_json_text`（与 `_fetch_text` 同一套出网安全：SSRF 逐跳校验、跨 host 剥凭证、10MB 流式上限）。
- **ja3 IOC 类型**（2026-10-30 新增）：`ioc_ingest._ALLOWED_TYPES` + 32 位小写 MD5 hex 校验；
  `ioc_matcher.match(ja3=...)` 精确比对。与 `tls_fingerprint` 会话命中联动是下一步（D3）。
- **CIDR**：`ioc_matcher` 原生支持（Spamhaus DROP 直接可用）。
- **IOC 容量**：匹配缓存上限 50,000 条（按 `last_seen` 截断，`ioc_matcher.py:90`）——
  大体量源（URLhaus 全量/OTX）接入时用各源官方"recent/在线子集"端点，勿灌全量。
- **测试**：`backend/tests/test_intel_json_api.py`（8 项：ThreatFox/MalwareBazaar/SSRF/ja3 归一化/ja3 匹配）。

## 四、许可与出处

- abuse.ch 系列（Feodo/URLhaus/ThreatFox/MalwareBazaar/SSLBL）：免费，**非商用条款** ——
  本项目用途为竞赛/高校研究，符合；出处以 `source` 字段落库（`abuse.ch-*`）。
- CISA KEV：美国公共域。OpenPhish 社区版：免费 feed（非商业版）。
- Spamhaus DROP：研究用途免费，需保留出处。FireHOL：开放许可（GitHub）。
- 每源 IOC 落库时 `source=<feed name>`，出处可追溯（`threat_iocs.source` 列）。

## 五、验收口径（对 capabilities.yaml `threat_intel`）

- 升 **verified** 的条件（保持 capabilities 原注释口径）：真实 MISP **或** TAXII 拉取演练完成
  （第二批次 #14/#15，需部署环境网络可达）+ 免费源真实拉取留痕（第一批次任一 ✅ 项的 poll 日志
  + `soc_intel_ioc_total` 指标 + `/api/intel/iocs` 样例截图）。
- 本机（受限出口）已达成的部分：4 源真通在案（2026-10-27 路线 3）+ 12 源注册脚本 + json_api/ja3/CIDR 适配器全绿测试。
