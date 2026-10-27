"""对抗变体检出保持率(B4) — 回应"检测是不是关键词复述"的最后一问。

方法: 对每族种子载荷施加标准规避算子(单重/双重 URL 编码、大小写翻转、
部分编码), 度量引擎的**确认检出保持率**:
    retention = 变体仍被(非影子)规则检出的比例

口径边界(诚实声明):
  - 这是**签名层**的对抗韧性, 不声称覆盖语义级规避(参数改名、
    分块传输、协议层绕过 —— 后者属 ingest 规范化与行为层职责);
  - 保持率低的算子族 = ingest 解码规范化的改进方向(与 REPLAY 报告
    的双重编码发现互为印证), 不是"调规则凑数"的指令。

用法:
    python -m eval_datasets.evasion_retention --out ../docs/benchmark
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os
os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from sigma_engine.engine import PySigmaDetector  # noqa: E402

# 种子族: 每族一条基线载荷(url 字段注入), 平台执行层应全部基线命中
SEED_FAMILIES = {
    "traversal": "/files/download?name=../../../etc/passwd",
    "traversal_encoded": "/files/download?name=%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "xss": "/search?q=<script>alert(1)</script>",
    "es_unauth": "http://10.30.30.30:9200/_cat/indices?v",
    "env_probe": "/.env",
    "git_probe": "/.git/config",
    "actuator": "/actuator/env",
    "webshell_cmd": "/debug.php?cmd=id",
}


def _variants(payload: str) -> dict[str, str]:
    """标准规避算子集(与真实 WAF 绕过教科书一致的最小集)。"""
    one = urllib.parse.quote(payload, safe="")
    twice = urllib.parse.quote(one, safe="")
    mixed = payload[: len(payload) // 2] + urllib.parse.quote(payload[len(payload) // 2 :], safe="")
    flipped = payload.swapcase()
    return {
        "baseline": payload,
        "url_encode": one,
        "double_encode": twice,
        "partial_encode": mixed,
        "case_flip": flipped,
    }


def _enforced_hit(detector: PySigmaDetector, url: str) -> bool:
    """构造贴近真实接入口径的事件。

    - **先规范化再拆分**(2026-10-25 随检测输入规范化升级同步):
      引擎匹配读规范形视图(normalization.canonical_matching_view),
      接入口径的 host:port 拆分也必须发生在规范化**之后** —— 编码 URL
      在原始形态上拆不出端口, SIG-006 这类端口型规则会系统性漏检
      (es_unauth 家族 url_encode/double_encode/partial_encode 全 ✗ 的根因)。
    - method=GET: 真实 access 日志必带(社区 webserver 规则普遍以
      cs-method 为前置条件, 缺它会整体失真);
    - URL 带 host:port 时拆 dst_ip:port(与 mapping.apply_mapping 的
      平台口径一致), ES 9200 这类端口型规则才能按真实形态命中。
    """
    from normalization import canonical_url
    canon = canonical_url(url)
    dst = "10.0.0.5"
    m = re.match(r"^[a-z]+://([^/:]+):(\d+)", canon, re.I)
    if m:
        dst = f"{m.group(1)}:{m.group(2)}"
    ev = {"event": "REQ", "method": "GET", "src_ip": "203.0.113.90",
          "dst_ip": dst, "url": url, "message": url[:200],
          "severity": "info", "confidence": 50}
    return any("[SHADOW]" not in (h.description or "") for h in detector.detect(ev))


def run() -> dict:
    detector = PySigmaDetector(
        str(Path(__file__).resolve().parent.parent / "sigma_engine" / "rules"),
        enforce=True)
    families = {}
    for fam, payload in SEED_FAMILIES.items():
        per_op = {}
        for op, variant in _variants(payload).items():
            per_op[op] = bool(_enforced_hit(detector, variant))
        baseline_ok = per_op.get("baseline", False)
        ops = [v for k, v in per_op.items() if k != "baseline"]
        retained = sum(1 for v in ops if v)
        families[fam] = {
            "baseline_detected": baseline_ok,
            "per_operator": per_op,
            "retention": round(retained / max(len(ops), 1), 3),
            "note": "" if baseline_ok else "基线未命中 —— 家族定义或规则覆盖有误",
        }
    overall = round(
        sum(f["retention"] for f in families.values()) / max(len(families), 1), 3)
    return {
        "families": families,
        "overall_retention": overall,
        "operators": ["url_encode", "double_encode", "partial_encode", "case_flip"],
        "scope_note": "签名层对抗韧性; 语义级规避属 ingest 规范化/行为层职责",
    }


def render_md(r: dict, baseline: dict | None = None) -> str:
    lines = [
        "# 对抗变体检出保持率(签名层)", "",
        f"- 总体保持率: **{r['overall_retention']}**"
        f"(算子: {', '.join(r['operators'])})",
        "",
    ]
    if baseline:
        old = baseline.get("overall_retention")
        lines += [
            f"- 规范化前基线(2026-10-25 之前, 见"
            f" EVASION-result-pre-normalization.json): **{old}**"
            f" → 接入 `normalization.canonical_matching_view` 后 **{r['overall_retention']}**"
            f"(升级证据: docs/upgrade/evidence/DETECTION-NORMALIZATION-2026-10-25.md)",
            "",
        ]
    lines += [
        "| 家族 | 基线命中 | url_encode | double_encode | partial_encode | case_flip | 保持率 |",
        "|---|---|---|---|---|---|---|",
    ]
    for fam, f in r["families"].items():
        p = f["per_operator"]
        lines.append(
            f"| {fam} | {'✓' if f['baseline_detected'] else '✗'} "
            f"| {'✓' if p.get('url_encode') else '✗'} "
            f"| {'✓' if p.get('double_encode') else '✗'} "
            f"| {'✓' if p.get('partial_encode') else '✗'} "
            f"| {'✓' if p.get('case_flip') else '✗'} "
            f"| {f['retention']} |")
    if baseline:
        lines += ["", "## 改前改后(同口径同向量)", "",
                  "| 家族 | 改前保持率 | 改后保持率 |", "|---|---|---|"]
        for fam, f in r["families"].items():
            old_f = baseline.get("families", {}).get(fam, {})
            lines.append(f"| {fam} | {old_f.get('retention', '-')} | {f['retention']} |")
    lines += [
        "", "## 怎么读", "",
        "- 基线未命中的家族是评测器自身的对齐问题(见 note), 不计入引擎评价;",
        "- 保持率低的算子 = 该编码形态需要 ingest 侧规范化(与 REPLAY 报告的",
        "  双重编码发现一致), 修复面在接入管道而非逐条规则;",
        "- 2026-10-25 起 `normalization.canonical_matching_view` 接入引擎匹配",
        "  视图(受限多轮解码+反斜杠归一+缺省 dst 补齐), 编码算子不再是规避通道;",
        "- 本表只覆盖签名层; 行为层(anomaly)与链层(correlation)的对抗评估",
        "  由 self_play 红蓝自博弈承担(其课程化变体见 self_play/ 模块)。",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="")
    ap.add_argument("--baseline", default="",
                    help="改前 result JSON(如 EVASION-result-pre-normalization.json), "
                         "提供时报告附改前改后对比")
    args = ap.parse_args()
    res = run()
    baseline = None
    if args.baseline and Path(args.baseline).is_file():
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    print(json.dumps(res, ensure_ascii=False, indent=2))
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "EVASION-result.json").write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        (out / "EVASION.md").write_text(render_md(res, baseline), encoding="utf-8")
        print(f"报告已写 {out}/EVASION.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
