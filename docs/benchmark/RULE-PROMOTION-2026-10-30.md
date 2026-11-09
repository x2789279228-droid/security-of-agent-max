# RULE-PROMOTION 2026-10-30 —— B3 回测转正（第一轮：CSIC-2010 双视图）

> 引擎：`backend/eval_datasets/backtest_promotion.py`（决策纯函数 + `--apply` 转正 + `--demote-all` 一键回影子）
> 数据：CSIC-2010（本地缓存）良性 **72000**（Test+Training 全量，比方案口径 36000 更严）+ 攻击 **25065**，
> 每个语料跑**两轮视图**：原始 URL + 深解码规范化（与 REPLAY 0.347 基线同口径）——共 **194,130** 次检测。
> 红线：promote 仅当 fp==0 且攻击命中 ≥1；FP>0 一律留影子。**没有证据不许翻标志。**

## 1. 结论（第一轮）：0 条转正 —— 证据不足，纪律生效

| 决策桶 | 数量 | 含义 |
|---|---|---|
| **promote** | **0** | 无任何 hq 规则满足"FP=0 且有攻击命中" |
| keep_shadow_no_evidence | **1641** | 双视图下攻击零命中（也无误报）|
| keep_shadow_fp | 0 | **72000×2 视图良性零误报**（1641 条全部 FP=0 —— 干净度本身是有效结果）|

归因核实（防"计数管线坏了"的假阴性）：同管线对自研/c_00x 规则计数正常
（C-014/C-005/C-010/SIG-001/SIG-003/SIG-016 在攻击集有命中、良性集零误报）；
CSIC 的全部检出由**自研 20 条 + 手适配 c_00x** 贡献 —— 与 REPLAY 报告口径一致
（其 0.347 签名召回同样来自这些规则 + 深解码视图）。

**为什么 SigmaHQ web 子集不吃 CSIC**：CSIC 攻击是 URL 参数注入类载荷
（SQLi/XSS/遍历，双重 URL 编码）；字段兼容过滤后存活的 81 webserver + 44 proxy
条 SigmaHQ 规则主要面向日志 message/特定 webshell/CVE 路径模式，与 CSIC 的
`url+method+ua` 事件形态交集为空。**这不是导入失败，是该语料对本批规则的
证据面为零** —— 转正引擎按设计拒绝无证据转正。

## 2. 语料适用边界（下一步解锁）

| 规则面 | 条数 | 缺的证据 | 解锁项 |
|---|---|---|---|
| process_creation / registry / file_event | ~1510 | 良性 Sysmon 语料（FP 门禁）+ 攻击 Sysmon 命中（EVTX-ATTACK-SAMPLES / Mordor / 自采 Atomic） | **E1（数据集回放）—— 1262 条 process 规则的转正燃料** |
| web/proxy/network/dns | ~130 | 面向真实 Web 日志形态的攻击语料（CSIC 覆盖不了） | E2（UNSW-NB15 / CSE-CIC-IDS2018）或自采 WAF/访问日志 |

方案目标"转正 ≥300"**本轮未达成且不该硬凑**：硬翻标志违反 B3 红线。达成路径 =
E1/E2 语料接入后重跑本引擎（`--apply`），机制已就绪并有单测。

## 3. 机制验收（全部就绪）

- 决策纯函数 3 项语义钉死（FP 硬门禁 / 证据要求 / 无证据留影子）；
- `_rewrite_rule` 转正↔回影子幂等往返 1 项（溯源字段增删、规则体不破坏）；
- `--demote-all` 一键回影子（转正出问题单命令回滚）；
- 双视图 FP 合并口径：fp = fp_raw + fp_norm（两种视图都 0 才算 0），
  攻击命中取两视图之和（生产 canonical 视图介于两者之间）。

## 4. 复现

```bash
cd backend
python -m eval_datasets.backtest_promotion --root ../tools/datasets-cache \
    --out ../docs/benchmark/RULE-PROMOTION-2026-10-30.json
# 运行时长实测：约 2 小时（19.4 万事件 × ~28 eps 单进程）；进度每 5000 条打印
# 转正(待证据): 加 --apply ；回滚: --demote-all
```
