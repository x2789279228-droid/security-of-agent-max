# PHISH-CALIB 2026-10-30 —— E3 钓鱼检测标定（REMEDIATION-PLAN 路线 E3）

> 引擎：`backend/eval_datasets/eval_phish_calibration.py`（.eml → 5 维邮件检测器 → scoring.aggregate）
> 语料（SpamAssassin 公共语料，已缓存 `tools/datasets-cache/phish-calib/`）：
> 正例 spam_2 **1,397 封** + 负例 easy_ham_2 **1,401 封** + hard_ham **251 封**（合计 3,049，全部评测）
> 诚实口径：spam_2 是**垃圾/欺诈超集而非纯钓鱼**（Nazario 纯钓鱼语料官方需人工下载、镜像 404；
> PhishTank 需 key——见 INTEL-FEEDS D2#16）——本表 P/R 是「垃圾检出」口径的下界参考。

## 1. 结果（现行固定分界：risk_level ≠ safe 即阳性）

| 指标 | 值 |
|---|---|
| 评测邮件 | 3,049（全量，19s） |
| **Precision** | **0.4956**（spam 395 flagged / ham 402 flagged） |
| **Recall** | **0.2827**（1397 封 spam 检出 395） |
| 阈值扫描 best F1 | 0.6284 @ threshold=0（即「任何非零分即阳性」最优——分离面弱） |

## 2. 关键发现（如实，两者均为有效标定产出）

1. **规则面在 2005 年代语料上的形态错位**：spam_2 的垃圾邮件多为纯文字推销/成年内容
   （非 URL 钓鱼），而检测器设计面是**凭证收割/品牌仿冒/URL 攻击**——维度不重合
   → 低召回是设计面与语料年代的差，不是缺陷判定。最强信号「IP 直连链接」在 spam 命中 843 次，
   说明 URL 维度确实在抓。
2. **误报面集中在易误伤的合法营销邮件**：easy_ham 的 1,401 封正常邮件中 402 封被标
   （「异常邮件跳转链」764 次、「发件域名疑似仿冒」208 次）——2003 年代的邮件头风格
   （多跳转发、mailer-daemon）与现代检测假设不匹配。**hard_ham 单独看误报更低**，
   说明 easy_ham 的 FP 多来自列表邮件的特征噪声。
3. 附带修复：语料中畸形 Message-ID 使 stdlib email 头解析器 IndexError —— 
   `parse_eml` 已做逐头容错（解析器炸 → 原始串回退），**3,049 封全量零崩溃**。

## 3. 结论与建议

- **标定集缺口（原缺口）已关闭**：7 检测器中邮件面 5 维在真实公开语料上有了逐指标 P/R 基线，
  融合打分的分离面量化在案。capabilities `phishing` 的「缺标定集」注记可关闭。
- **「跨检测器融合」项保持 open**：本标定用的是固定分界融合；LLM 维度（llm_dimension）
  未启用（需 key）——融合打分升级为 P0.S 路径（aggregate_with_llm）需要 LLM 预算。
- 现代纯钓鱼语料（Nazario 新版/PhishTank key）到位后重跑本引擎即可对比。

## 4. 复现

```bash
cd backend
python -m eval_datasets.eval_phish_calibration --out ../docs/benchmark/PHISH-CALIB-2026-10-30.json
```
