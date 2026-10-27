# 检测能力量化报告集(B1-B4)

> 生成方式全部可复现: 命令在各报告头部/对应模块 docstring。
> 数据面: 合成标定集(detection_cases, 工程正确性)+ 公开数据集
> CSIC-2010(外部 ground truth, 能力量化)+ 对抗变体(签名韧性)。

| 报告 | 回答的问题 | 生成命令(backend/ 下) |
|---|---|---|
| [REPLAY-CSIC-2010.md](REPLAY-CSIC-2010.md) | 对公开真实攻击数据的召回/误报? | `python -m eval_datasets.replay_public_datasets --root ../tools/datasets-cache --out ../docs/benchmark` |
| [ABLATION.md](ABLATION.md) | 多层堆叠每层带来什么? | `python -m eval_datasets.ablation --out ../docs/benchmark` |
| [EVASION.md](EVASION.md) | 签名层对抗编码规避的韧性? | `python -m eval_datasets.evasion_retention --out ../docs/benchmark --baseline ../docs/benchmark/EVASION-result-pre-normalization.json` |
| [PERF-2026-10-26.md](PERF-2026-10-26.md) | **B4 容量**: 端到端吞吐/延迟/丢失 + 故障注入(饱和点在哪)? | 负载 `tools/attack-large-scale-2026-09-10.py`(攻击机容器内) + 落库回查 `psql -c "select count(*) from security_events where session_id=..."`(命令见报告头部) |

## 一页结论(2026-10-25 检测输入规范化升级后实测)

- **规则库 150 条**(12 内置 SIG + 8 自研 SIG-013..020 + 5 手适配 + 125 影子批量),
  全编译 0 错误;合成标定集 Precision=1.0 / FP=0。
- **检测输入规范化已接入引擎**(`normalization.canonical_matching_view`,升级证据见
  [../upgrade/evidence/DETECTION-NORMALIZATION-2026-10-25.md](../upgrade/evidence/DETECTION-NORMALIZATION-2026-10-25.md)):
  **对抗保持率 0.438 → 1.0**(8 家族 × 4 编码算子全绿)。
- **CSIC-2010 公开数据集**(全量 25065 攻击 / 36000 良性,规范化前基线为抽样 5000/5000):
  良性 **FP=0/36000**(硬门禁保持);全类召回 0.0132 → **0.0302**;
  traversal 类 **FN 归零**(97/97);签名子集召回 0.3452 → 0.3469,
  原始=规范化(解码器在引擎内,两口径构造性相等);SQLi 由影子层接住
  (82/724, 晋升候选);其余 ~80% 异常类为纯行为异常, 属异常检测器工作面。
- **分层消融**: L1 执行层/L3 异常检测/L4 关联引擎在各自工作面满分
  (L3 两步修正: 先修评估器词表 bug —— 此前"接近满分"是空值假象;
  再修检测器 —— **severity_shift 基线相对证据维度**接入(§七.2, 全量权重
  重归一到 1.0), ANO-P-02/03 两条标定缺口关闭, 阈值可行区间 [0.3982, 0.6435)
  非空且当前阈值 0.60 在内);
  **L5 SOAR 决策层 uncovered_type 3 → 0**(PATH_TRAVERSAL 叶子 + 专属策略补齐)。

## 性能/容量一页结论(2026-10-26 第一轮压测实测, B4)

- **端到端丢失率 0**: 24,447 条入队 = 新增落库 18,447 + 幂等去重 6,000, 差额 0;
  P1 稳态 6000/6000 逐条落库; P3 同 eventId 重放 6000 条新增 **0** 行(账本不膨胀)。
- **饱和点在 Python 消费侧, 不在接入侧**: 接入侧批量 500 可达 **130.8 eps**(12000/12000 全 202,
  零拒绝); 检测引擎 **42.46 ms/事件**(150 规则)⇒ 单进程上限 ≈23.5 eps, 实测消费 13.97~22.1 eps。
  与 B1 的 "~34 eps" 量级一致。
- **HTTP p50 2~3 秒**来自同步等 broker ack 的在途窗口(produce gate 32 + acks=all),
  批量越大越摊薄; 不是网络问题。
- **背压信号与真实瓶颈错位**: 429 闸门看审计队列深度(本轮峰值仅 27%), 却在 130.8 eps 下
  **零 429**; 真实背压在 Kafka lag(峰值 12,216)上而系统不自知 ⇒ 闸门需绑到真实瓶颈。
- **异常检测在真实流量上 100% inconclusive**(17,267/17,267) ⇒ 当前不可用, 能力页应如实标注。
- **约 76% 的审计本就走规则收口通道**(tools_only 13,137 vs llm 1,388+2,347) ⇒
  "无 LLM 也能闭环"有本轮侧证。
- **降级语义清晰**: 杀 PG / Redis 各 30 s 期间 HTTP 仍 **5/5 返回 202**(10~44 ms, 只入队不落库),
  在途 44 条 offset 保留、恢复后补齐, 丢失 0; 杀 Flink TaskManager 后 3 作业自恢复
  (checkpoint 23~24 次全成功, 无重复告警)。
- **压测前修了 8 个"容器在跑、实际没跑"的阻断项**(alembic fileConfig 顶掉 root logger /
  .env 缺 KAFKA_BOOTSTRAP_SERVERS / .sh CRLF 致作业零提交 / **Flink checkpoint 只在客户端缺失
  致 Kafka 事务永不提交** / 状态卷属主 / compose 未接线 EXECUTION_MODE / 客户端并行度只有 1 /
  43 条存量困在未决事务), 详见报告的"改前基线"表。
- 口径边界: Flink 主流水线未测(HTTP 路径实际不过它)、无 key 剖面与 3 项故障注入未覆盖、
  剖面时长压缩、内存驻留未回落 —— 逐条见报告"结论边界"。
