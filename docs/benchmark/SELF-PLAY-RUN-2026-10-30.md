# SELF-PLAY-RUN 2026-10-30 —— 一次完整对局指标导出（J 清零项）

> 命令：`python -m self_play --rounds 4 --no-persist`（连运行中栈 PG）
> 同名 JSON 为完整原始导出。这是 capabilities `self_play` 注记
> 「缺一次完整对局指标导出」的关闭证据。

## 结果

| 项 | 值 |
|---|---|
| 状态 / 胜方 | completed / **blue** |
| 轮数 | 4 |
| 红方 | attacks=… asr(攻击成功率) 见 JSON |
| 蓝方 | precision=1.0 / recall / fbeta / tp/fp/fn/tn 混淆矩阵齐备 |
| MTTD / MTTC | mttd_ms / mttc_ms（检测/遏制时延） |
| 六维雷达 | coverage=0.75, precision=1.0, mttd=0.27, novelty_response=0.5, compounding=0.5, robustness=0.75 |
| Sigma 命中 / 候选 | sigma_hits / candidate_tp（课程池场景） |

注记边界（如实）：`样本注入生产隔离待修` 项仍在 —— 本局 `--no-persist`
（未写生产库），注入隔离问题不影响指标导出口径。
