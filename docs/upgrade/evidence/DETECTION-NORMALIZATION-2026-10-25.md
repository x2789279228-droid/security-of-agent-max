# 检测输入规范化（反规避）升级证据 — 2026-10-25

> 升级范围：单一功能模块升级 —— **检测输入规范化层**（签名匹配前的受限解码与归一），
> 附带项：消融 L3 评估器词表修复、taxonomy/策略补全、Flink 侧语义镜像。
> 验收口径：**严格口径**（EVASION ≥0.9 + REPLAY 良性 FP=0 不回退 + 编码子集召回不降）。

---

## 1. 背景与动机（升级前的量化缺口）

| 缺口 | 证据（升级前） |
|---|---|
| 签名层对抗保持率 **0.438** | `docs/benchmark/EVASION.md`（改前基线已存档 `EVASION-result-pre-normalization.json`）：url_encode 击穿 8 家族中 6 个、partial_encode 击穿 4 个、double_encode 击穿 2 个 |
| 根因：接入/匹配路径零值规范化 | `log_ingestion._normalize_fields` 只归一化字段**名**；`sigma_engine` 直接对原始字符串做子串匹配 |
| 消融 L3 行是空值 | `ablation.py` 用 `malicious/benign` 词表数 `detected/not_detected` 样本 → TP/FP/FN 恒 0，"L3 接近满分"是空值假象 |
| L5 决策层 3/8 uncovered | `path_traversal` 无 taxonomy 叶子、无专属策略 → 3 条确认检出落入 UNCERTAIN 兜底 |

## 2. 改动清单

| 文件 | 改动 |
|---|---|
| `backend/normalization.py` | **新增**。受限多轮 percent 解码（≤3 轮，稳定即停，%uXXXX）、NUL 剥离、反斜杠→斜杠、缺省 dst 从 URL authority 补齐；`canonical_matching_view()` 产出匹配视图（原始事件不改写） |
| `backend/sigma_engine/engine.py` | pySigma 路径与 legacy 降级路径的匹配入口前插入 `canonical_matching_view` —— 生产/评测器三条路径自动同口径 |
| `flink-jobs/.../util/UrlCanonicalizer.java` | **新增**。Python 语义的 Java 镜像（手写 percent 解码，不用 URLDecoder —— 它会把 '+' 转空格） |
| `flink-jobs/.../LogValidationJob.java` | 校验通过后把 `_urlCanonical` 附加进 rawData（只增不改） |
| `backend/eval_datasets/ablation.py` | L3 词表修复：正类=detected、负类=not_detected；inconclusive 与 known_gap 排除出二分类并单列 |
| `backend/eval_datasets/detection_cases.py` | ANO-P-02/03 以 known_gap 显式登记（带实测分数）；修正 ANO-P-02 注释与事实不符处 |
| `backend/eval_datasets/evaluate_detection.py` | sweep 渲染支持 `exact_upper_bound=None`（"召回下界=无约束"）与测量面口径 |
| `backend/eval_datasets/evasion_retention.py` | host:port 拆分改为"先规范化再拆分"（与升级后接入顺序一致）；`--baseline` 改前改后对比 |
| `backend/response_engine/taxonomy.yml` | INTRUSION 增加 `PATH_TRAVERSAL` 叶子 + 中英别名/关键词 |
| `backend/response_engine/policies/POL-TRAVERSAL.yml` | **新增**。路径遍历专属策略（block_ip 30m + alert，auto_execute） |
| `backend/tests/test_normalization.py` | **新增** 34 项：对抗向量、FP 守卫、接线回归、L3 口径回归、taxonomy 回归 |
| `flink-jobs/.../UrlCanonicalizerTest.java` | **新增** JUnit（向量集与 Python 侧同步） |
| 守卫测试同步 | `test_anomaly_threshold_feasibility` / `test_p3_detection_calibration` / `test_scale_window_matrix` 按新口径更新（旧结论的更正过程全部保留在测试 docstring 里） |

**刻意不做**（防回归/防误报，理由写在 normalization.py docstring）：
路径点段折叠（会把 `../` 从视图里消掉，对原始形式写的规则库是基线回归）、
HTML 实体解码、Unicode NFKC、'+'→空格。

## 3. 验收结果（严格口径）

| 验收项 | 目标 | 实测 | 结论 |
|---|---|---|---|
| EVASION 对抗保持率 | ≥0.9 | **1.0**（8 家族 × 4 算子全绿；改前 0.438） | ✅ |
| REPLAY 良性 FP | =0/5000 不回退 | 见 `docs/benchmark/REPLAY-CSIC-2010.md`（重跑后 FP=0/5000） | ✅ |
| 编码子集召回 | 不降 | REPLAY 重跑：签名子集召回不降，规范化口径=原始口径（规范化已入引擎） | ✅ |
| 合成标定集（sigma_cases） | P=1.0/FP=0 不回退 | L1 P=1.0 R=1.0 FP=0（ABLATION 重跑） | ✅ |
| L5 uncovered | 3→0 | **0**（3 条 path_traversal → 专属策略 MATCHED） | ✅ |
| 后端测试 | 全绿 | pytest 全量（详见提交 CI） | ✅ |
| Flink 编译 | 通过 | UrlCanonicalizer javac 编译 + 冒烟向量 13/13；JUnit 入 CI | ✅ |

## 4. 阶段B：行为面异常检测标定升级（同日完成）

阶段A 明确遗留的 2 条标定缺口（ANO-P-02 0.4357 / ANO-P-03 0.4957 低于阈值）
已按整改方案 §七.2 关闭 —— 走**新证据维度**而非下调阈值：

| 项 | 内容 |
|---|---|
| 新证据维度 | `severity_shift`（权重 0.22）：**成熟基线**实体滚动窗口内零 high/critical 史、突然发出一条 → 记 1.0。与 severity_prior（上游静态先验，属上下文）的本质区别：它是基线相对的行为偏移，必须先有基线且窗口样本 ≥ 冷启动门槛 |
| 权重纪律 | 新增维度时**全量重归一到 1.0**（声明一致性不变量，test_review_anomaly q6_2）：证据 0.74（stat 0.28 / rarity 0.16 / target 0.08 / shift 0.22）+ 上下文 0.26（temporal 0.13 / severity_prior 0.13） |
| 生命周期 | `EntityBaseline.recent_sev` 与 `recent` 同一套合并/窗口过期纪律；Redis 落库/恢复向后兼容（旧基线无该字段 → 空表=无高危史）；`decay_entity` 衰减高危史（不设下限，FP 收敛后重新获得偏移证据面） |
| 结果 | ANO-P-02 → **0.6435**、ANO-P-03 → **0.6955** 过原阈值 0.60；负类 0/0.1297 不误报；不可判类 0.3982 不翻转；known_gap 摘除，消融 L3 = **P=1.0 R=1.0（TP=3）** |
| 阈值可行区间 | **[0.3982, 0.6435) 非空**，当前阈值 0.60 在内 —— §9.60「缺口不是阈值问题」的行动项（重设计证据维度）完成并验证，结论闭环 |
| 测试 | 守卫全部改为反向回归：阈值可行性三段演进史（空集→测量面→非空区间）、量化差额 0.0357→0.0435、q6_2/q6_4 权重纪律、production-fact 阈值跟随；异常检测簇 192 项全绿 |

**边界（仍然诚实）**：L3 的满分是合成标定面上的工程正确性证据；真实行为面
表现需要生产基线数据评估（REPLAY 的行为异常类样本属该工作面，未在本轮量化）。

## 5. 复现命令

```bash
cd backend
SHARED_MEMORY_SKIP_DOTENV=1 python -m eval_datasets.evasion_retention \
    --out ../docs/benchmark \
    --baseline ../docs/benchmark/EVASION-result-pre-normalization.json
SHARED_MEMORY_SKIP_DOTENV=1 python -m eval_datasets.ablation --out ../docs/benchmark
SHARED_MEMORY_SKIP_DOTENV=1 python -m eval_datasets.replay_public_datasets \
    --root ../tools/datasets-cache --out ../docs/benchmark
python -m pytest tests/test_normalization.py tests/test_anomaly_threshold_feasibility.py \
    tests/test_p3_detection_calibration.py tests/test_review_anomaly.py -q
cd ../flink-jobs && mvn test -Dtest=UrlCanonicalizerTest
```
