# 检测引擎正确性审查报告

**审查对象**：`backend/` 检测链路（Sigma 引擎、异常检测、关联引擎、零日沙箱、因果链、融合与契约）
**审查方式**：只读代码 + 实测复现。**未修改任何生产代码。**
**日期**：2026-10-18

---

## 0. 方法与可复现性

审查按用户给出的建议顺序逐条推进，每条结论标注证据等级：

| 标注 | 含义 |
|---|---|
| **已实证** | 实际运行代码观察到的行为，附实测数值或复现命令 |
| **仅代码推断** | 读源码得出的判断，未实际执行 |
| **无法验证** | 本机环境不具备条件，明确列出原因 |

### 0.1 证据文件（可重跑）

| 文件 | 用例数 | 覆盖 |
|---|---|---|
| `backend/tests/test_review_sigma_detector.py` | 26 | Q1–Q4 |
| `backend/tests/test_review_anomaly.py` | 14 | Q5–Q6 |
| `backend/tests/test_review_correlation.py` | 23 | Q7–Q8 |
| `backend/tests/test_review_contract_fusion.py` | 24 | Q14–Q15 |

```powershell
$env:PYTHONIOENCODING='utf-8'
Set-Location '...\源代码\backend'
python -m pytest tests/test_review_sigma_detector.py tests/test_review_anomaly.py `
          tests/test_review_correlation.py tests/test_review_contract_fusion.py -q
```

**实测结果：`87 passed`**。全量回归 `1732 passed / 10 xfailed / 0 failed`（基线 1645 + 新增 87，**零回归**）。

### 0.2 一条贯穿全局的方法论结论

本次审查最重要的发现不是任何单点缺陷，而是**同一个错误模式在 6 个模块重复出现**：

> **把「我没有能力判断」编码成「我判断结果是 0 / clean / no_result / UNKNOWN」。**

审查问题里「检测失败时会不会把『没有检测到』误判为『没有威胁』」问的就是它。它在以下位置逐一复现：

| 模块 | 「无法判断」的编码 | 位置 |
|---|---|---|
| Sigma | 单条规则 SQL 失败 → `hit = False` | `sigma_engine/engine.py:263-264` |
| 异常检测 | 基线样本不足 → 偏离度 `0.0` | `anomaly_detector.py:238-239` |
| 关联引擎 | 模式匹配异常 → `logger.warning` 后继续 | `correlation_engine.py:361-362` |
| EDR 关联 | 任意异常 → `return results`（空列表） | `edr_fusion/cross_correlator.py:135-138` |
| 零日 | 报告为 None → `verdict="clean"` | `zeroday_detect/behavior_analyzer.py:74-75` |
| 因果链 | 无后门调整集 → `causal_support` | `causal_chain/compare.py:66-72` |

下游没有一个字段能把这两种状态区分开。因此下文所有 P0 都不是孤立 bug，而是同一个根因的不同表现。

---

## 1. 四个基础问题的回答

### 1.1 检测结果准不准？

**不准，存在三处方向明确的系统性漏报与一处夸大。**

| # | 问题 | 实测证据 |
|---|---|---|
| 1 | **全新源 IP 永远判不出异常** | 基线 <3 条时统计偏离度恒 0，新实体分数理论上限 **0.51 < 阈值 0.60**。灌 0/10/100/300/1000/2000 条历史后，全新 IP 的 critical 事件得分恒为 0.31–0.51，`is_anomaly` 恒 `False` |
| 2 | **关键字检测只覆盖 6 个字段** | `KEYWORD_FIELDS` 只有 url / cs-uri-query / message / details / http.url / event。关键字落在 `user_agent` / `request_body` 等字段时必然漏报 |
| 3 | **约 55% 的因果方向是编造的** | 3 组种子 × 100 个随机 DAG：先验强制定向占比 **55.9% / 54.7% / 52.9%**，与数据推导方向在输出里同形同权 |
| 4 | **攻击链名不副实** | `[端口扫描, 暴力破解, 数据外泄]` 三条即命中 `classic_killchain`，告警文案写「经典杀伤链」——中间跳过了「横向移动」和「C2 回连」 |

正面结论：Sigma 的 **SQL 转换语义在已覆盖的 8 种场景矩阵上全部正确**（大小写、子串、通配符转义、字段缺失/NULL/空串、精确字段不被改坏、命中后不因历史行残留继续命中）。

### 1.2 相同输入能否稳定复现？

**对 Sigma 匹配可以，对异常检测不行，对因果链不可追溯。**

| 组件 | 可复现性 | 证据 |
|---|---|---|
| Sigma 匹配 | ✅ 稳定 | 同一事件连续检测 10 次，`rule_id` 集合不漂移 |
| 异常检测 | ❌ 非幂等 | 同一条事件重放 6 次得到 **4 种分数**：`0.15 → 0.15 → 0.15 → 0.36 → 0.43 → 0.50`，`is_anomaly` 从 `False` 翻转到 `True` |
| 异常检测（时钟） | ❌ 不可回放 | `analyze()` 内部硬编码 `datetime.now(timezone.utc)`，无注入点；跨 UTC 小时重放必然得到不同分数 |
| Sigma 规则 ID | ❌ 会重排 | 无 `x-soc-id` 的规则回退到位置序号 `SIG-nnn`，YAML 增删/重排后重新编号，而 ID 会进 Kafka 载荷 |
| 因果链 | ❌ 不可追溯 | 返回结构中无任何统计后端/版本字段；SciPy 装与不装会静默改变学出的图（90 次运行中 5 次骨架不同） |

### 1.3 多个检测器之间会不会互相干扰？

**会，三条干扰路径。**

1. **共享可变状态**：Sigma 引擎在单个共享 `sqlite3.Connection` 上对固定表名 `events` 做 `DROP → CREATE → INSERT`。确定性交错复现：A 事件入表后 B 事件 DROP 重建，A 的检测查询随即返回未命中。表名常量，全仓无锁、无临时表、无每事件独立库。
   *当前缓解*：生产所有触发点都是 `async def`，且 `detect_for_event` 内部无 `await`，单事件循环线程内不会交错。所以这是**潜在**而非当前活跃的缺陷——但一旦有人加同步 `def` 端点或线程池调度即刻激活。

2. **基线是全局有状态单例**：`anomaly_detector` 的 `baselines` 在所有事件间累积并互相影响。第 1 条事件的判定依赖此前所有事件的顺序，检测器之间无法隔离评估。

3. **先验污染输出**：因果链的 `TACTIC_RANK` 对无法定向的边强行赋方向，输出里不携带来源标记，下游 `query_do` / `annotate_chain` 无法把它与数据推导的方向区分开。

### 1.4 检测失败时会不会把「没有检测到」误判为「没有威胁」？

**会。这是本次审查最严重的结论。**

**统一契约不存在**：全仓无 `detection_contract.py`，五个检测器各用各的结构体，互不引用、互不继承、无共同基类。

**七字段清单核对（0-7 表示满足几个）**：

| 载荷 | 满足数 |
|---|---|
| `sigma.DetectionResult` | **0/7** |
| `sigma.empty_sigma()`（错误态） | **0/7** |
| `anomaly.AnomalyReport` | **0/7** —— 字段叫 `anomaly_score`，连 `score` 都没有 |
| `zeroday.BehaviorAnalysis` | **1/7** —— 只有 `score`，无量纲声明 |

`status` / `error_code` / `detector_version` / `rule_version` / `analysis_window` **全局为零**。

**决定性实测**：真实 critical Sigma 命中（SIG-003 path_traversal）+ 异常引擎报 0.0

| Sigma 状态 | 融合分数 | is_anomaly | 下游 triage |
|---|---|---|---|
| 正常 | **0.75** | True | **P0 / llm_agent / pri=100 / strong=2** |
| 崩溃 | **0.00** | False | **P3 / rule_close / pri=20 / strong=0** |

一次 Sigma 引擎故障，把已确认的严重攻击降级成「零 LLM 的噪声关闭」。唯一痕迹是一条 WARNING 日志和内存里的 `DetectResult.errors`。

**更糟的变体**：Sigma 引擎**内部**的单条规则 SQL 失败（`engine.py:263-264`）被吞成 `hit=False`，此时 `detect_for_event` 返回一个**格式完好**的「未命中」结果——`errors` 为空、`inc_detector_error` 不触发、**连一行 WARNING 都不打**。这比崩溃更危险，因为崩溃至少有日志。

**被固化的证据**：`anomaly_error` 这个唯一标记经全仓扫描只有两个**写入点**、**零个消费点**。实测「异常引擎崩溃」与「真的干净」事件经 `audit_triage.score_event()` 后 `to_dict()` **完全相等**。

---

## 2. 逐条回答

### Q1 · pySigma → SQL 的语义是否一致？

**8 种场景矩阵全部正确（已实证）。**

| 场景 | 结果 |
|---|---|
| 完全匹配 / 大小写变化 / 子串 | ✅ 全部命中 |
| LIKE 通配符 `%` `_` | ✅ `50%_off` 命中，`50XoYff` 不命中，`_escape_like` 转义顺序正确 |
| 字段缺失 / NULL / 空串 | ✅ 不产生意外命中 |
| 精确字段规则 | ✅ 未被自定义 backend 改坏 |
| 命中后检测不命中事件 | ✅ 不因历史行残留继续命中（单线程下 DROP→CREATE 有效） |

**但发现 3 处语义缺口**：

1. `backend_keywords.py:25-32` — `KEYWORD_FIELDS` 只有 6 个字段，关键字落在其他字段时**必然漏报**。
2. `convert_condition_val_num` 把数字也转成字符串 LIKE → 子串匹配，语义改变。
3. `engine.py:202` — `_rule_meta` 用 `getattr(getattr(sigmarule,"id",None) or None,"value",None)` 取 Sigma UUID，但 **pySigma 1.5 里 `sigmarule.id` 是 `uuid.UUID`，没有 `.value` 属性**（实测 `id.value = None`）→ 恒为 None，回退到位置序号。
   *当前影响*：生产 16 条规则**全部带 `x-soc-id`**（实测 25 个 yml 中 16 个带，缺的 9 个全在 `rules_community_candidate/` 目录、不被默认加载），故暂未触发。**一旦把候选规则提升为生产规则，ID 会随 YAML 增删重排而改变。**

### Q2 · `_ensure_table:291` 的 DROP → CREATE 并发安全？

**不安全（已实证）。**

```python
# 确定性交错复现，不依赖线程调度
det._ensure_table(list(ea.keys()), ea)   # A 建表 + 插入 A
det._ensure_table(list(eb.keys()), eb)   # B DROP + CREATE + 插入 B
sql = [s for m, s in det._compiled if "SECRETALPHA" in s][0]
hit = det._conn.execute(sql).fetchone() is not None   # → False，A 的检测丢失
```

- `TABLE = "events"` 是模块常量，全进程共享。
- `detect()` 与 `_ensure_table()` 源码中均**无 `lock` 字样**（静态核对）。
- **额外发现（Q2 的线程分支）**：`sqlite3.Connection` 默认 `check_same_thread=True`。任何跨线程调用在 `engine.py:304` `self._conn.cursor()` 处直接抛 `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same thread`，且该异常在 `_ensure_table` 内**无 try 兜底**，会外泄出 `detect()`。
  *当前缓解*：生产所有触发点都是 `async def`（`ingest_pipeline.detect`、`routers/audit.py`、`routers/ops.py`），单事件循环线程内安全。
- **DDL 未转义**：`engine.py:306-310` 字段名直接 f-string 拼接。事件字段名含 `"` 时 `CREATE TABLE "evil"col" TEXT` 抛 `sqlite3.OperationalError`，且 DROP 那步有 try/except 兜着、**CREATE 那步没有** → 异常未受控外泄。已实测复现。

### Q3 · `reload()` 原子性？

**设计正确，但无锁，且关闭旧连接会造成静默丢检测。**

- ✅ **先构建后替换**：坏 YAML 不会清空旧规则（实测：新规则目录加一份无效 YAML，`reload()` 后 `rule_id` 集合不变）。
- ✅ **单文件失败只 skip**：注释与实现一致，坏文件只丢自己。
- ❌ **无锁**：`reload()` 源码中无 `lock`。
- ❌ **旧连接被 close**：实测 `old_conn.execute(...)` → `sqlite3.ProgrammingError: Cannot operate on a closed database`。并发 detect 仍持有旧连接时会踩到。

> 注：我最初假设 `finally: cur.close()` 会用 `NameError` 掩盖原始异常，**实测否证**——失败发生在 `_ensure_table`（在 try 之外），异常类型得以保留，且会被 `ingest_pipeline._run_sigma` 捕获并记入 `errors`。这条不算缺陷。

- ❌ **加载结果不可观测**：`stats()` 返回 `['attack_types','enabled_count','engine','rules_count','rules_dir','severity_distribution','shadow_count']`——**无任何 skipped / load_errors 字段**。「哪些规则没加载上」不可知。

### Q4 · Legacy 兜底是否悄悄改变检测语义？

**不改变（已实证）。**

`engine.py:240-241` 的 Legacy 分支条件是 `if not self._compiled` —— **仅在完全没有规则编译成功时触发**。pySigma 可用且有规则时 legacy 永不运行，因此「双引擎同时运行导致重复检测」的问题实际不存在。

代价是：一旦 pySigma 全部编译失败，语义**整体**降级到 legacy，而不是双引擎互补。

### Q5 · 泊松近似的输入与边界？

**输入条件与边界有 6 处问题。**

| # | 问题 | 实测 |
|---|---|---|
| 1 | `std = max(1.0, mean**0.5)` 的夹逼 | mean<1 时强行抬到 1.0，压低 sigma；mean≥1 时纯泊松，无过度离散修正 |
| 2 | **`mean == 0` 分支绕过 `min(sigma, 10.0)` 上限** | 实测返回 **5000.0**，直接进 `AnomalyReport.deviation_sigma` 与日志文本 |
| 3 | **`total_count < 3` 返回 `0.0`，与「偏离度确实为 0」同值无标记** | 基线 2 条时 `hourly_counts[3]==2` 但返回 0.0 |
| 4 | **`analyze()` 非幂等** | 同一事件重放 6 次得 4 种分数（见 1.2） |
| 5 | **`temporal` 用服务器 UTC 钟点，与日志时间戳无关** | UTC 02:00（北京时间 10:00，正常上班）→ `temporal=0.4`「非活跃时段」；UTC 18:00（北京时间 02:00，真正的凌晨）→ `temporal=0.0`。**语义对国内部署完全反转** |
| 6 | **文档声称「滑动窗口（默认 7 天）」，实际计数无限累计** | 灌 200 条后 `total_count=200`，再灌 200 条 → `400`。7 天只体现在 Redis TTL 与实体清理上 |

**额外量化：灵敏度随基线年龄单调衰减**（二分求解 σ>3 的最小突增量，基准每小时 50 条）：

| 基线天数 | 触发 3σ 所需突增 |
|---|---|
| 1 | 21 |
| 7 | 54 |
| 30 | 112 |
| 60 | **158** |

60 天基线需要的突增量是 1 天基线的 **7.5 倍**。机制：`hourly_counts[h]` 是「历史第 h 个钟点」的**累计量**而非「本小时」的量（`sum(hourly_counts) == total_count` 恒成立），基线越厚越难判异常。

### Q6 · 五维加权评分是否被某一项掩盖？

**不是被某一项掩盖，是被「缺失维度按 0 分计入」系统性压低。**

| 事实 | 值 |
|---|---|
| 文件头声称的检测维度数 | 5 |
| **实际参与打分的维度数** | **4**（第 5 项「目标IP统计」只 `_update_baseline`，从不进 `dimensions`、不加 `total_score`） |
| 权重和 | 0.35 + 0.20 + 0.15 + 0.25 = **0.95** |
| 理论最大分 | 0.35 + 0.20 + 0.4×0.15 + 0.25 = **0.86** |
| **新实体（基线<3）理论上限** | 0.20 + 0.06 + 0.25 = **0.51** |
| 判定阈值 | `anomaly_score > 0.6` 或 `max_sigma > 3` |

**决定性结论**：新实体 `dim1` 恒为 0 → 上限 0.51 < 0.6，且 `max_sigma = 0` 走不了第二条件 → **全新源 IP 的事件无论严重度多高、灌多少历史，都判不出异常**。实测灌 2000 条历史后得分 0.51，仍 `is_anomaly=False`。

**这恰恰是最该被发现的场景**：攻击者轮换源 IP（每个只用一两次）是横向移动与分布式扫描的标准手法，而唯一能在新实体上起作用的统计偏离度维度，恰好被「数据不足」门槛关掉。

**另一处尺度问题**：`rarity = max(0.0, 1.0 - ratio * 100)`，`ratio` 是事件类型占比。要让 rarity 非零需要主流/稀有计数比 > 100：

| 先灌 benign 条数 | ratio | rarity |
|---|---|---|
| 10 | 0.0909 | **0.0** |
| 100 | 0.0099 | 0.0099 |
| 200 | 0.004975 | 0.5025 |
| 10000 | 0.0001 | 0.9900 |

即 rarity 是**部署规模**的函数，不是「事件稀有性」的函数。小规模部署下这 20% 权重恒为 0。

**另外**：`severity` 维度（权重 0.25）是**输入回显**，实测同一条日志只改 severity 字段，分数线性变化 0.25。它不构成独立检测信号。

### Q7 · 四条关联路径的正反案例？

| 路径 | 正例（应命中且命中） | 反例（不应命中却命中 / 应分却合） |
|---|---|---|
| **pattern** | `[端口扫描, 暴力破解, C2回连]` 1 分钟间隔 → 命中；中文事件名归一后同样命中；`max_gap` 约束有效（gap 31 > 30 不命中）；`min_match` 门槛有效 | ❌ **跳步过宽松**：`allow_skip_missing` 默认 True 使 `skippable` 形同虚设 → `[端口扫描, 暴力破解, 数据外泄]` 命中 `classic_killchain`（无 C2 无横向）；`[可疑登录, C2回连]` 命中 `lateral_movement`（无任何横向移动事件） |
| **hub** | 先作 dst 后作 src 的枢纽能串联跨源链；只作目标的 IP 不会成为枢纽；同一枢纽只保留最高优先级命中 | ❌ `chain_id` 取自 `deduped[0]`（时间轴首条）而非 `matched_events[0]`（链首），chain_id 与链内容脱钩 |
| **时间窗口** | 单事件组不产出（降噪正确）；跨 11 分钟正确切分 | ❌ **链式而非固定窗口**：比较基准是「组内最后一条」，`09:00 / 09:09 / 09:18` 三条相邻 gap 均 9 ≤ 10 全部并入一组，**整组跨度 18 分钟 > 10 分钟窗口** |
| **实体链接** | 两个真实源 IP 打同一目标 → 产出关联；单源不产出 | ⚠️ 否证：`src_ip` 缺失的事件全被归入 `"unknown"` 虚拟节点，但因只有一个 key，`len(srcs)>=2` 不成立，**此路径不误报**。真正的误报在 pattern 路径——来源无关的事件会被当成**同一个攻击者**的完整攻击链 |

**顺序约束是否失效？——否证。** 审查初稿假设「跳步导致方向性反转」，实测反序序列 `[C2, 端口扫描, 暴力破解]` **不会**命中，因为单个事件只能消费一个 step、`step_idx` 单调推进。真实缺陷是跳步**宽松**而非方向**反转**。

### Q8 · 关联的组合与去重？

**去重逻辑有三处问题（已实证）。**

1. **`_dedup_chains:653` 用「完全包含」而非「重叠」判定**：
   `if event_ids - used_event_ids:` —— 只要有**一个**新事件就整条保留。两条链共享 id=1 但各有独有事件 → **两条都保留，同一事件被两条攻击链各认领一次**，下游按链累加会重复计数。

2. **优先级 = 插入顺序，而非语义优先级**：`_dedup_chains` 只按 `len(events)` 排序，Python 稳定排序让并列项保持输入序。实测两条同长度链，`[c1, c2]` 与 `[c2, c1]` 输入得到**相反的保留顺序**。而输入序来自 `events_by_ip` 遍历序 + 模式字典定义序，都不是「更完整/更严重优先」的显式规则。

3. **不具传递性**：A-B 重叠、B-C 重叠时，结果取决于排序。实测 id=5 同时出现在两条「保留」的链中。

**正向**：真子集的链会被正确丢弃。

### Q9 · PC 与 GES 的结果解释？

**「55% 的因果方向没有任何数据支持」是本模块最核心的问题。**

| 问题 | 结论 |
|---|---|
| 用的是不是 causal-learn？ | **否，全部手写。** `causallearn` 未安装、未在 `requirements.txt` 声明；`ges.py:1-4` 自述「不是 Chickering 全套 CPDAG 算子」，且**不做 CPDAG 投影** |
| 骨架恢复准不准？ | **准且保守。** 8 个已知合成结构中骨架 **8/8 精确恢复**，不可识别方向保守留白（全 0 定向），碰撞结构定向正确 |
| 弱信号下会不会反向？ | **会。** S8（弱 CPT 0.45/0.58）中 PC 给出 `C→B` 而真值是 `B→C`——**一条完全反向的边，且 consensus 标 `high_confidence`**（PC 与 GES 恰好同向错） |
| CPDAG 有没有被强制定向？ | **是，且这是最大的信息损失源。** 全仓无 `TACIT`/`UNDETERMINED`/`REVERSED` 三元状态；`ges.py:161` 硬编码 `"undirected": []`（GES 永不表达不确定性）；`learn.py:22-49` 用 `TACTIC_RANK` 对 PC 的 undirected 边强行定向，输出**不携带任何来源标记** |

**信息损失量化（3 组种子 × 100 个随机 DAG）**：

| 种子基 | 先验强制定向 | 输出方向总数 | 占比 |
|---|---|---|---|
| 5000 | 775 | 1386 | **55.9%** |
| 70000 | 768 | 1403 | **54.7%** |
| 123456 | 748 | 1415 | **52.9%** |

**冲突边的处理是自相矛盾的**：证据强时保留冲突并标 `prior_violation=True`（正确）；证据弱、数据毫无方向支持时，`_orient_with_prior` **凭先验凭空造出方向且无任何标记**，且 `agree_rate` 因 GES 自身 tie-break 恰好同向而显示 `1.0`——**伪装成双算法共识**。

**措辞层面是克制的**（`pc.py:3` 写明「未定向边不算 CEP 因果支持」，前端用「因果支持/伪相关/未知」而非「已证实因果」），语义缺陷在实现层。

### Q10 · G² 分层累计与 SciPy 可选依赖的 fallback 语义？

**fallback 确实改变语义，且稀疏数据下 df 崩塌会删掉真边。**

**G² 实现本身**（`pc.py:30-69`，全仓唯一）：列联表构造、边缘计数、每 stratum +1 自由度、零格掩码均正确。**但缺期望频数闸门**，且 `xs.size < 4` 的 stratum 被**静默跳过且不加 df** → df 收缩过度。

**df 崩塌（决定性）**——真值 A→B（`P(B=1|A=1)=0.90, =0.10`），条件集 |S|=3：

| n | 各 stratum 样本数 | G² | df | p | 边缘 p | A-B 边保留？ |
|---|---|---|---|---|---|---|
| 4000 | 全 ≥4 | 3016.45 | 8 | 0.0000 | 0.00e+00 | 否（正确） |
| 40 | 2 个 <4 | 39.55 | 6 | 0.0000 | 8.91e-11 | 否（正确） |
| **12** | `[0,0,1,1,2,2,3,3]` | 10.61 | **0** | **1.0000** | **9.29e-05** | **否（真边被删）** |
| **8** | `[0,0,0,1,1,1,2,3]` | 5.55 | **0** | **1.0000** | **8.68e-04** | **否（真边被删）** |

机制：`pc.py:67-68` 在 `df <= 0` 时 `return 1.0`，此时 `_chi2_sf` **根本未被调用**（monkeypatch 实测 `sf NEVER called`）。p=1.0 > alpha → 删边。**一条边缘 p=8.7e-04 的真实依赖，在加了 3 个条件变量后被判定为「独立」并从骨架中抹除。**

默认 `min_windows=40` 只是总行数下限，不保证每 stratum 够大；在 11–14 节点、`max_cond=3` 的默认配置下，8 个 stratum 均分 40 行也只有 5 行/格——**该风险是常态而非边缘情况**。

**SciPy fallback 改变语义**：`pc.py:24-27` 注释自称「df=1 退化」，但 `pc.py:69` 对**任意 df** 都套用 `erfc` 公式，而 `erfc(z/√2)` 恒等于 `chi2.sf(x, 1)`：

| df | 真实 `chi2.sf(6,df)` | fallback | 比值 |
|---|---|---|---|
| 1 | 0.014306 | 0.014306 | 1.0000 |
| 2 | 0.049787 | 0.014306 | 0.2873 |
| 8 | 0.647232 | 0.014306 | **0.0221** |

**决策层差异**：30 组数据 × 3 个 alpha = 90 次 PC 运行，**5 次给出不同骨架**，全部是 fallback 多出边。**装/不装 scipy 会静默改变学出来的图。**

**fallback 完全无记录**：`learn_from_matrix` 返回键中无任何统计后端/版本信息；`pc.py:15-16` 的 `except Exception: _chi2 = None` 连 log 都没有。（缓解：scipy 是 `requirements.txt:15` 的硬依赖，该路径在正常部署下不可达——但也意味着**从未被 CI 覆盖**。）

### Q11 · TACTIC_RANK 的软先验语义 + 后门准则？

**是软先验（正确），但后门准则会把「找不到调整集」静默转成「因果关系」。**

**软先验部分——设计正确：**

| 位置 | 行为 |
|---|---|
| `variables.py:183-189 prior_forbids` | 纯谓词，无副作用 |
| `learn.py:63-69` | 注释「先验标记，不删边」；仅**覆写** `confidence` 字段 |
| `compare.py:103-104` | `candidate_edges` 跳过违反先验的边——仅影响广播门，不影响图 |

实测反证：强行构造出 `DATA_EXFIL→PORT_SCAN`（rank 5→0，强烈违反先验），该边**完整保留**在 `directed` 中并直接喂给 `do()`/后门计算。数据**可以**推翻先验，冲突证据被保留并标记。这是**正确**的先验设计。

**但 100 个先验不一致 DAG 的汇总**：先验强制定向 662 条，其中 37 条与真实 DAG 方向相反，**0 条越界**——先验不阻断任何数据方向，但**它会在 55% 的边上主动编造方向**。

**后门准则——两处 P0：**

| 情形 | `backdoor_set` | intervene 结果 |
|---|---|---|
| U 在 names 中但未标为混杂 | `None` | `identifiable=False, reason='no_backdoor'` ✅ 显式 |
| **U 完全不可观察（不在 names）** | **`[]`** | **`identifiable=True, reason='backdoor', z=[]`** ❌ |

第二种情形实测偏误（U→A 0.7/0.2，U→B 0.9/0.3，n=200000）：

```
TRUE ACE (ground truth)   = +0.6000
reported ACE (z=[])       = +0.2783      低估 53.6%
identifiable = True, reason='backdoor', z = []
```

**不可观察混杂被静默当成「无可调整项 = 无混杂」，输出一个有偏数字并标注为已识别。**（符号未翻转——该假设未被证实——但偏误幅度显著。）

**「找不到调整集」→「因果支持」直接实测成立**：

```
directed 含未标混杂 U → causal_verdict = 'causal_support'
                         identifiable   = False            ← 明确不可识别
```

根因 `compare.py:66-72`：`elif path_ok: verdict = "causal_support"` —— **该分支不看 `identifiable`**。`data=None`（完全没有数据）同样给出 `causal_support`。

**另外两处后门逻辑问题**：
- `do_calculus.py:141` 的 `extra` 过滤条件是 `is_confounder(n) and n not in preferred`，而 `preferred` 已是 names 中**全部**混杂变量 → `extra` 恒为空。**任何非混杂变量永远不会被尝试作为调整集**，候选空间实际只有 {全部混杂} / {} / {单个混杂} 三种。
- `compare.py:51-59` 只要求 CEP 相邻步之间存在**某条**有向路径，从不校验 CEP 步骤序列本身就是那条路径。实测：图中只有 `SUSPICIOUS_LOGIN→LATERAL_MOVE` 直连边、中间 `FILE_ACCESS` 步骤根本不在图里，`has_directed_path` 仍返回 `True`。

### Q12 · 沙箱服务失败时的状态？

**「沙箱没给结果 ≠ 样本安全」——已实证违反。**

**核心链路（实测，指向 `http://127.0.0.1:1` 无人监听）**：

```
沙箱不可达 → get_report()=None → behavior_analyzer.analyze(None)
→ {"verdict":"clean","score":0.0,"behavior_summary":"","mitre_techniques":[],...}
```

**没有任何字段能区分「真没发现威胁」与「根本没跑起来」。** `analyze(None)` 与 `analyze({})` 返回**完全相同**的 dict。

**评分映射边界**（`behavior_analyzer.py:149-154`，阈值 ≥0.7 malicious / ≥0.3 suspicious）：

| 输入 | → score | → verdict |
|---|---|---|
| 0.0 / 10.0 | 0.0 / 1.0 | clean / malicious ✅ 边界正确 |
| -1 | 0.0 | **clean**（被 `max()` 静默丢弃，无标志） |
| `None` / `"abc"` / `"8"` | 0.0 | **clean**（字符串数字 `"8"` 不被接受） |
| `True` | 0.1 | clean（`isinstance(True,int)` 为真，JSON `true` 被当 0.1） |

**故障态不可区分**：连接被拒 / HTTP 404 / 真实超时（实测 15.7s）**三者返回完全相同的 `None`**，且 HTTP 非 200 时 `get_task_status` **一条日志都不打**（实测日志记录数 = 0），状态查询异常仅 DEBUG 级。

**任务状态词表几乎不存在**：代码只识别 `"reported"`、`"failed_analysis"`、`"failed_processing"`；`models.py:722` 声明的 `running/completed/failed` **连接器一个都不写**。缺 `unavailable` / `timeout` / `no_result`。

**任务无法回连**：`sandbox_connector.py:59` 计算的 `sha256` **计算后即丢弃**（全函数未再使用），`SandboxTask.sample_hash` 根本没被赋值。同 payload 提交两次 → 两个独立 CAPE 任务，无去重、无本地任务表。

**重定向与凭据**（实测，与常见猜测相反）：
- **token 未进日志** ✅ 6 条日志仅含 `Cannot connect to host 127.0.0.1:1`
- **跨源重定向会被跟随，但 `Authorization` 被 aiohttp 剥离** → **无凭据外泄**。不过恶意沙箱可把连接导向内网任意地址并把响应当报告解析（默认明文 HTTP）

### Q13 · Jaccard ≥ 0.5 的变种聚类？

**阈值判定数值上可靠，但特征提取与聚类算法有 4 处缺陷。**

**实际算的是什么**（实测真实 CAPE 报告）：

```
['file:HKLM\Run\x', 'file:c:\evil.dll', 'mitre:T1219', 'mitre:T1555',
 'net:9.9.9.9', 'net:http://a/b', 'sig:banker', 'sig:rat']
```

即 **Jaccard 算在「签名名 + MITRE 技术 ID + 网络 IOC 值 + 文件 IOC 路径」的并集上，不是文件哈希**。模块 docstring 声称的「API 调用序列」与「DBSCAN 聚类」**与实现不符**（`api_calls` / `registry_keys` 任何路径都不写入，实测恒为空集；`math` 导入 0 处使用）。

**阈值边界——穷举验证无 bug**：`49/100=0.49` 不同簇；`1/2=0.5` 同簇（`>=` 含等号）；`0.5000000000000001` 同簇；`0.49999999999999994` 不同簇。穷举 `u<4000` 的所有数学精确 1/2 比值，**0 个**因浮点误差偏离。

**4 处缺陷**：

| # | 缺陷 | 实测 |
|---|---|---|
| 1 | **`empty ∩ empty = 1.0`** | 5 个零特征样本**全落进同一个 cluster**。与 Q12 的 #1 复合：沙箱全挂 → 所有样本「高度相似」 |
| 2 | **畸形 IOC 产生幻影 token** | `:165/:172/:179` 用 `get(...,"")` 产生万能 token `net:`/`mitre:`/`file:`，两个无内容样本被判 **100% 同族** |
| 3 | **leader 算法顺序依赖** | 新样本只与簇代表（`hashes[0]`）比、不与簇内任一成员比。构造 `sim(A,B)=0.67`、`sim(B,C)=0.5`、`sim(A,C)=0.17`，插入顺序 C,B,A 时 A 被划进与最近邻 B **不同的簇** |
| 4 | **`sigs[:20]` 截断误判同族** | 两个样本各 30 条签名、前 20 条相同 → **20 条差异签名全被丢掉** → 截断后特征集完全相同 → 误判同族 |

**传递性——直接回答**：A~B、B~C 而 A≁C 时**不会**把三者并成一簇（连通分量式膨胀不存在）。但缺陷 #3 的**顺序依赖**是对「变种家族」判定的可靠性问题。

**显示与判定不一致**：`:124` 的 `round(sim, 3)` 使 raw=0.4996 **显示为 `0.5`**，而聚类判定（raw ≥ 0.5）已把它分到别的簇——分析师看到「0.5」却不同族。

---

## 3. 发现清单

### P0 安全

| # | 标题 | 位置 | 复现 | 影响 |
|---|---|---|---|---|
| **P0-1** | 检测器故障 fail-open，把严重攻击降级为噪声 | `ingest_pipeline.py:299-308, 321-325`；`sigma_engine/engine.py:263-264` | `pytest tests/test_review_contract_fusion.py::TestQ15Fusion -q` | Sigma 崩溃时 SIG-003 critical 命中从 P0/llm_agent/pri=100 变为 P3/rule_close/pri=20，响应编排完全不触发。**引擎内部吞异常时连 WARNING 都没有**，`errors` 为空、指标不触发 |
| **P0-2** | 「找不到调整集」被静默升级为「因果支持」 | `causal_chain/compare.py:66-72` | 见 Q11.3：`annotate_chain` 传入含未标混杂 U 的 directed 图 | `identifiable=False`（明确 no_backdoor）仍返回 `causal_support` 并直供前端徽章；`data=None` 也返回 `causal_support` |
| **P0-3** | 不可观察混杂被当成「无混杂」，输出有偏 ACE 并标已识别 | `causal_chain/do_calculus.py:141-143, 129-153` | U 完全不在 names 中 | ACE +0.2783 vs 真值 +0.6000（**低估 53.6%**），`identifiable=True`，无任何警告 |
| **P0-4** | temporal 维度用服务器 UTC 钟点，对国内部署语义完全反转 | `anomaly_detector.py:299-304, 321-322` | `pytest tests/test_review_anomaly.py::TestQ5PoissonBounds::test_q5_4 -q` | 北京时间凌晨 0–5 点（UTC 16–21）时序分恒为 0；北京时间正常上班（UTC 0–5）被判「非活跃时段」+0.4 并直接进 `reasons` |
| **P0-5** | 沙箱未跑起来输出 `verdict=clean`，与真实干净样本逐字段相同 | `zeroday_detect/behavior_analyzer.py:74-75` | `analyze(None)` | **仓库内无生产调用方**（仅测试），故当前不可触发；一旦接线即成漏报源。已被 `test_review_contract_fusion.py:315` 固化为已知缺陷 |
| **P0-6** | `submit_url` 对 URL 零校验，可被请求参数影响 | `zeroday_detect/sandbox_connector.py:109` | `POST /edr-intel/sandbox/submit` 传 `url=file:///etc/passwd` | `file:///`、`http://169.254.169.254/latest/meta-data/`、`gopher://127.0.0.1:6379/_INFO`、`not a url` **全部原样转发并返回 task_id**。有生产路由与角色校验（admin/operator），**故可达** |

### P1 可靠性

| # | 标题 | 位置 | 复现 |
|---|---|---|---|
| **P1-1** | 新实体理论上限 0.51 < 阈值 0.60 → 永远判不出异常 | `anomaly_detector.py:238-239, 341, 391-392` | `test_review_anomaly.py::test_q6_3` |
| **P1-2** | 缺失维度按 0 分计入而非重新分配权重 | `anomaly_detector.py:334-381` | `test_q6_4` |
| **P1-3** | `analyze()` 非幂等，同一事件 4 种分数 | `anomaly_detector.py:306-414` | `test_q5_3` |
| **P1-4** | 灵敏度随基线年龄衰减（60 天基线需 7.5× 突增量） | `anomaly_detector.py:241-261` | `test_q5_6` |
| **P1-5** | `rarity` 的 ×100 魔法数，小规模部署恒为 0 | `anomaly_detector.py:288` | `test_q6_6` |
| **P1-6** | 关键字检测只覆盖 6 个字段 | `sigma_engine/backend_keywords.py:25-32` | `test_q1_4` |
| **P1-7** | 单条规则 SQL 失败静默记为未命中 | `sigma_engine/engine.py:263-264` | `test_q1_10` |
| **P1-8** | 共享 SQLite 表 DROP→CREATE，无锁 | `sigma_engine/engine.py:291-323` | `test_q2_2` / `test_q2_3` |
| **P1-9** | 共享连接线程亲和，跨线程抛未捕获异常 | `sigma_engine/engine.py:304` | `test_q2_4` |
| **P1-10** | DDL 字段名未转义，CREATE 步异常外泄 | `sigma_engine/engine.py:306-310` | `test_q1_8` |
| **P1-11** | `reload()` 无锁且 close 旧连接 | `sigma_engine/engine.py:89-113` | `test_q3_3` / `test_q3_4` |
| **P1-12** | 规则 ID 回退到位置序号，YAML 增删即重排 | `sigma_engine/engine.py:202` | `test_q3_1` |
| **P1-13** | `allow_skip_missing` 默认 True → `skippable` 形同虚设 | `correlation_engine.py:507-509` | `test_q7_1` |
| **P1-14** | 无 C2 回连、无横向移动也命中 `classic_killchain` | `correlation_engine.py:181-256` | `test_q7_2` |
| **P1-15** | 无任何横向移动事件也命中 `lateral_movement` | 同上 | `test_q7_3` |
| **P1-16** | 时间分组链式比较，组跨度可远超窗口 | `correlation_engine.py:585` | `test_q7_8` |
| **P1-17** | `src_ip` 缺失合并为单一虚拟攻击者 | `correlation_engine.py:334` | `test_q7_11` |
| **P1-18** | 去重用「完全包含」而非「重叠」，同一事件归属多条链 | `correlation_engine.py:653` | `test_q8_1` |
| **P1-19** | 去重优先级 = 插入顺序而非语义 | `correlation_engine.py:646` | `test_q8_3` |
| **P1-20** | 「error」与「not_detected」在载荷层完全同形 | `ingest_pipeline.py:174-175, 296`；`edr_fusion/cross_correlator.py:135-138` | `test_q14_2` / `test_q14_4` |
| **P1-21** | 下游准入把「未分析」等同于「干净」 | `audit_triage.py:94-208` | `test_q14_7` |
| **P1-22** | 约 55% 的因果方向零数据支持 | `causal_chain/learn.py:22-49, 91` | 见 Q9.3 表 |
| **P1-23** | df=0 → p=1.0 → 真实依赖被从骨架删除 | `causal_chain/pc.py:51-52, 67-68` | 见 Q10.2 表 |
| **P1-24** | SciPy fallback 套用 df=1 公式，5/90 次骨架不同 | `causal_chain/pc.py:24-27, 69` | 见 Q10.3 表 |
| **P1-25** | 冲突边同时输出 `A→B` 与 `B→A` | `causal_chain/ges.py:169-199` | S2 / S5 用例 |
| **P1-26** | GES 硬编码 `"undirected": []`，永不表达不确定性 | `causal_chain/ges.py:161` | 任意 |
| **P1-27** | 沙箱三种故障同为 `None`，零重试，HTTP 非 200 零日志 | `zeroday_detect/sandbox_connector.py:147-150, 175-176` | 不可达 / 404 / 超时 |
| **P1-28** | `task_id=None` → 返回字面量字符串 `"None"`，永久悬空 | `zeroday_detect/sandbox_connector.py:80` | `{"task_id": null}` |
| **P1-29** | sha256 算了不用，任务无法回连原始样本 | `zeroday_detect/sandbox_connector.py:59` | 同 payload 提交两次 |
| **P1-30** | `task_id` 可注入请求路径 | `zeroday_detect/sandbox_connector.py:133, 157` | `get_task_status("../../v1/admin")` → 服务端实收 `/v1/admin`（**带 Bearer 头**）。当前无生产调用方传入用户输入，属潜在 |
| **P1-31** | 空集合 Jaccard=1.0 → 所有无特征样本并成一族 | `zeroday_detect/variant_cluster.py:49-57, 94` | 5 个 `{}` 分析 |
| **P1-32** | 畸形 IOC 产生幻影 token → 无关样本判 100% 同族 | `zeroday_detect/variant_cluster.py:165, 172, 179` | 两条畸形 IOC |
| **P1-33** | leader 算法新样本只与簇代表比 → 分区随插入序变化 | `zeroday_detect/variant_cluster.py:85` | 顺序 C,B,A |
| **P1-34** | `sigs[:20]` 截断丢差异签名 → 误判同族 | `behavior_analyzer.py:155` | 两样本各 30 签名、前 20 相同 |

### P2 可观测性

| # | 标题 | 位置 |
|---|---|---|
| **P2-1** | `stats()` 无 skipped / load_errors，「哪些规则没加载上」不可知 | `sigma_engine/engine.py:418-433` |
| **P2-2** | `mean == 0` 分支绕过 `min(sigma, 10.0)`，`deviation_sigma` 字段可达 5000.0 | `anomaly_detector.py:249-250` |
| **P2-3** | 文档称「7 天滑动窗口」，实际无限累计 | `anomaly_detector.py:53, 193-203` |
| **P2-4** | 稳态实体偏离度恒为 0.0（累计桶口径无噪声底） | `anomaly_detector.py:241-242` |
| **P2-5** | `src_ip` 为空则整维跳过，报告无法区分「无 IP」与「无偏离」 | `anomaly_detector.py:338` |
| **P2-6** | `severity` 维度是输入回显，不构成独立信号 | `anomaly_detector.py:374-381` |
| **P2-7** | 第 5 项「目标IP统计」从不参与打分，但文档列为 5 维 | `anomaly_detector.py:383-385` + 模块 docstring |
| **P2-8** | 无统一契约，五检测器字段矩阵几乎全空 | 五个检测器各自的数据类 |
| **P2-9** | FastPath 冷却窗口（60s）丢弃重复的 critical 事件，无升级策略 | `ingest_pipeline.py:543-545` |
| **P2-10** | 违反先验的冲突边不进人工复核队列 | `causal_chain/compare.py:103-104` |
| **P2-11** | `confidence` 被 `prior_violation` 覆写，丢失原始置信度 | `causal_chain/learn.py:67-69` |
| **P2-12** | 缺期望频数闸门，无稀疏度诊断输出 | `causal_chain/pc.py:58-69` |
| **P2-13** | SciPy fallback 完全静默（无 log、无后端标志），产出图不可追溯 | `causal_chain/pc.py:15-16` |
| **P2-14** | CEP 路径校验不检查步骤序列本身 | `causal_chain/compare.py:51-59` |
| **P2-15** | 后门候选集实际只有 3 种，`extra` 恒为空 | `causal_chain/do_calculus.py:141` |
| **P2-16** | `wait_for_completion(poll_interval=0)` 永不退出；`elapsed` 按迭代计数而非墙钟 | `sandbox_connector.py:173, 182-183` |
| **P2-17** | `auto_submit` 失败无指标、无日志 | `sandbox_connector.py:198-215` |
| **P2-18** | `add_sample` 不传 hash 时全部样本 hash 为 `""`，`find_similar` 返回 `[]` | `variant_cluster.py:69` + docstring |
| **P2-19** | 同 hash 重复添加 → `sample_count` 虚高 | `variant_cluster.py:97` |
| **P2-20** | `round(sim,3)` 显示 0.5 但聚类判定已分到别的簇 | `variant_cluster.py:124` |
| **P2-21** | 跨源重定向被跟随（响应会被当报告解析） | `behavior_analyzer.py:74, 116, 135, 159` |
| **P2-22** | `SHARED_MEMORY_SKIP_DOTENV` 拦不住 pydantic 自己的 `env_file=".env"` | `config.py:486-487, 499-512` |

### P3 说明性

| # | 标题 | 位置 |
|---|---|---|
| **P3-1** | `analyze()` docstring 写 `event_type`，实现读 `event`/`type`（生产已由 `_normalize_event` 保证，无实际影响） | `anomaly_detector.py:311` vs `:317` |
| **P3-2** | hub 链 `chain_id` 取自时间轴首条而非链首，与链内容脱钩 | `correlation_engine.py:456` |
| **P3-3** | 严重度/置信度两套词表并存，`confidence` 无 `critical` 档 | `ingest_pipeline.py:66-69` vs `:553` |
| **P3-4** | `variables.py:26` 注释写「软先验：禁止反向边」，实为**软标记**（不禁止），措辞误导 | `causal_chain/variables.py:26` |
| **P3-5** | 非 Chickering GES（无 forward/backward/reverse 算子、无 CPDAG 投影），但 `README` 称「GES 算法」 | `causal_chain/ges.py:1-4, 159` |
| **P3-6** | `try_apply` 定义后从未调用（死代码） | `causal_chain/ges.py:73-82` |
| **P3-7** | `ges.py:190` 三元式中 `high_confidence` 分支永不可达 | `causal_chain/ges.py:186-190` |
| **P3-8** | `models.py:722` 声明的 `running/completed/failed` 连接器从不写入 | `models.py:722` |
| **P3-9** | `variant_cluster` docstring 谎称 DBSCAN + API 调用序列 | `variant_cluster.py:7, 16` |
| **P3-10** | `/sandbox/status` 仅需登录即返回内网 CAPE 主机:端口 | `routers/edr_intel.py:199-203` |
| **P3-11** | 自带 `test_causal_chain.py` 的 `_edge_set` 把 `oriented_by_one`（先验编造类）与 `high_confidence` 同等采信；5 个测试全通过但覆盖不到本文任何一条缺陷 | `tests/test_causal_chain.py:46-48` |

---

## 4. 总判定

**VERDICT: FAIL**

三条阻断性理由，均有实测数值支撑：

1. **P0-1**：检测器故障时 fail-open，SIG-003 critical 命中从 P0/llm_agent/pri=100 降级到 P3/rule_close/pri=20。这是五个检测器共用同一个「无证据 = 无威胁」编码造成的系统性问题，不是单点 bug。
2. **P0-2 / P0-3**：因果链把「明确不可识别」静默升级为「因果支持」，并把不可观察混杂当成「无混杂」输出低估 53.6% 的 ACE 并标 `identifiable=True`。
3. **P1-1**：异常检测对新实体理论上限 0.51 < 阈值 0.60，**攻击者轮换源 IP 时异常检测完全失明**——而这正是最需要它的场景。

**值得肯定的部分**：
- Sigma 的 SQL 转换语义在 8 种场景矩阵上全部正确，包括 LIKE 通配符转义与字段缺失处理。
- `reload()` 的「先构建后替换」设计正确，坏 YAML 不会清空旧规则。
- 融合是**单调下限**而非加权平均——对 anomaly ∈ {0, 0.25, 0.5, 0.74, 0.9, 1.0} 全量扫描，融合结果恒等于 `max(anomaly, 0.75)`，critical 档从未跌破 0.5。**「强信号被平均掉」这条假设被实测否证。**
- Jaccard 阈值 `>= 0.5` 的浮点判定经穷举验证可靠，无边界 bug。
- TACTIC_RANK 作为软先验的设计是正确的：数据可以推翻先验，冲突证据被保留并标记。

---

## 5. 未验证清单

| # | 项 | 原因 |
|---|---|---|
| 1 | **Q2 的 DROP→CREATE 在生产拓扑下是否真的会交错** | 需确认是否存在同步 `def` 端点 / 线程池调度路径。本次静态核对了全部触发点均为 `async def` 且 `detect_for_event` 内无 `await`，但未做生产并发压测 |
| 2 | **真实 CAPE/Cuckoo 的任务状态词表** | 离线环境，无真实实例。实测只覆盖 mock 返回值 |
| 3 | `submit_file`(60s)/`submit_url`(30s)/`get_report`(60s) 硬超时 | 单条命令预算不足，未实测。`get_task_status` 的 15s 真实超时已实测（15.7s） |
| 4 | **因果链在真实 `security_events` 上的表现** | 无数据库访问。仅用合成 SCM 替代，真实数据的边缘分布与稀缺度未知，P1-23/P2-12 的实际触发率无法估计 |
| 5 | `events_to_matrix` 端到端（真实事件 → 稀疏度） | 未连 DB，矩阵切分逻辑仅静态阅读 |
| 6 | 因果链调度器与 HTTP 层 | `scheduler.py:947 _causal_learn_loop`、`routers/causal.py:112-115` 的 names 对齐分支（列名不同时直接改用当前 names，图与数据可能错配）未实测 |
| 7 | `correlation_engine.analyze()` 的异常折叠 | `:361-362`、`:372-373` 逐 pattern `except: logger.warning` 后继续，同样把引擎故障折叠成「无攻击链」，但需 DB，未实测 |
| 8 | Kafka 入口对 list/dict 型字段是否有 schema 强校验 | `anomaly_detector.analyze()` 确会被 `src_ip=['1.1.1.1']` 等打挂（实测 `TypeError: unhashable type`），但 `kafka_consumer.py:1546` 前的校验链未追完 |
| 9 | 规则加载时 `severity` 是否归一化大小写 | `sigma_detector.py:524` 的 `severity_order` 大小写敏感，YAML 若写 `level: Critical` 会被排成最低档——未能确认加载时是否已归一化 |
| 10 | Flink/Kafka 端到端行为 | `kafka_consumer.py:2051-2069` 的资产加权只会上调分数（上限 1.0），不影响判定方向，未跑集成 |
| 11 | `variant_cluster` 全局单例在多进程/多副本下的持久性 | 进程重启即全部丢失、`_next_cluster` 归零。未测（属设计观察） |
| 12 | **四类测试集 A/B/C/D 的量化指标** | 用户要求建立 A 黄金样本 / B 对抗与边界 / C 故障与并发 / D 评估与性能（Precision/Recall/F1/误报率/漏报率/延迟/吞吐/资源占用，按检测器与事件类型分别统计）。本次完成的是 B 类（对抗与边界）与 C 类（故障与并发）的**定性**审查；**A 类需要标注好的黄金样本集，D 类需要生产流量基线，本机两者都不具备，未建立** |

---

## 6. 文件清单

### 6.1 交付的审查证据（`backend/tests/`，87 个用例，全绿）

| 路径 | 用例数 | 字节 | 编码 |
|---|---|---|---|
| `tests/test_review_sigma_detector.py` | 26 | 23737 | LF / 无 BOM / 无 U+FFFD |
| `tests/test_review_anomaly.py` | 14 | 14011 | 同上 |
| `tests/test_review_correlation.py` | 23 | 20125 | 同上 |
| `tests/test_review_contract_fusion.py` | 24 | 24770 | 同上 |

**生产代码零改动。**

### 6.2 ⚠️ 无法删除的临时文件（需手动清理）

本地硬安全策略同时拦截 `rm --` 与 `mavis-trash`，以下 5 个文件无法删除：

| 路径 | 用途 | 产生者 |
|---|---|---|
| `backend/_review_probe_sigma_id.py` | Sigma 规则 ID 来源探针（确认 pySigma 1.5 的 `uuid.UUID` 无 `.value`） | 本次审查 |
| `backend/_review_probe_anomaly.py` | Q5/Q6 异常检测探针（一次性量数用） | 本次审查 |
| `backend/tests/_tmp_write_probe.py` | 验证写入通道会产生 BOM | Q14/Q15 子审查 |
| `backend/tests/_tmp_write_probe2.py` | 验证剥 BOM 后 LF/CJK 是否完好 | Q14/Q15 子审查 |
| `backend/tools/_tmp_probe_unbounded.py` | 上轮审查遗留 | 历史 |

> `tests/` 下的两个 `_tmp_write_probe*.py` 位于 pytest 收集目录下，文件名不以 `test_` 开头，**不会被收集执行**，但建议一并删除以保持目录整洁。

### 6.3 环境注意

`config.py` 的 `Settings` 使用 pydantic `env_file=".env"` + `extra="forbid"`。`SHARED_MEMORY_SKIP_DOTENV=1` **拦不住 pydantic 自己的 env_file 加载**。从仓库根目录（含 `.env` 的上层）导入会因未声明键而崩溃。审查全程在 `backend/` 作为 CWD 运行。
