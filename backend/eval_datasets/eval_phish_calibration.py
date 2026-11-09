"""eval_phish_calibration.py — E3 钓鱼标定（REMEDIATION-PLAN 路线 E3，2026-10-30）。

语料（SpamAssassin 公共语料，Apache 托管，缓存 tools/datasets-cache/phish-calib/）：
  正例 spam_2（1,397 封垃圾/钓鱼混合 — 诚实口径：非纯钓鱼，是"垃圾/欺诈邮件"
        的超集；Nazario 纯钓鱼语料 GitHub 镜像 404、官方需人工下载，已登记）
  负例 easy_ham_2（1,401 封正常邮件）+ hard_ham（251 封"难负例"）

链路：.eml 原文 → headers/sender/subject/body/urls 抽取 →
  phishing_guard.email_detector.detect（7 检测器中的邮件面 5 维：
  sender/urls/attachments/content/headers）→ scoring.aggregate 融合打分。

产出：逐维度命中统计 + 融合 P/R + 阈值扫描（safe/critical 分界在
  _classify 内固定，扫描的是 score 对 spam/ham 的分离面）。

用法：
    cd backend
    python -m eval_datasets.eval_phish_calibration \
        --root ../tools/datasets-cache/phish-calib [--limit N] \
        [--out ../docs/benchmark/PHISH-CALIB-2026-10-30.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from datetime import date
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def parse_eml(path: Path) -> dict:
    """单封 .eml → EmailPhishingRequest 字段。

    垃圾语料里有畸形 Message-ID（email 头解析器 IndexError）——
    逐头解析失败即跳过该头（compat32 原始串回退），不让单封坏样本崩全量。
    """
    try:
        msg = BytesParser(policy=default_policy).parsebytes(
            path.read_bytes())
    except Exception:
        return {}
    headers = ""
    try:
        kept = []
        for k, v in msg.items():
            if k.lower() not in ("received", "from", "to", "subject", "date",
                                 "message-id", "reply-to", "return-path",
                                 "content-type", "x-mailer", "dkim-signature"):
                continue
            try:
                kept.append(f"{k}: {v}")
            except Exception:
                # headerregistry 解析炸(畸形 msg-id 等) → 原始串回退
                raw = msg.get_all(k, [])
                for r in raw:
                    kept.append(f"{k}: {r}")
        headers = "\n".join(kept)
    except Exception:
        headers = ""
    body = ""
    try:
        part = msg.get_body(preferencelist=("plain", "html"))
        if part is not None:
            body = part.get_content() or ""
    except Exception:
        body = msg.get_payload() or "" if not msg.is_multipart() else ""
    if not isinstance(body, str):
        body = ""
    urls = _URL_RE.findall(body) + _URL_RE.findall(headers)
    sender = str(msg.get("From", "") or "")
    subject = str(msg.get("Subject", "") or "")
    atts = []
    try:
        for part in msg.iter_attachments():
            fn = part.get_filename()
            if fn:
                atts.append(fn)
    except Exception:
        pass
    return {"headers": headers[:4000], "sender": sender,
            "subject": subject, "body": body[:8000],
            "attachments": atts, "urls": urls[:30]}


def run_corpus(dirs: list[tuple[str, Path]], limit: int, per_detector: bool):
    from phishing_guard.email_detector import detect
    from phishing_guard.models import EmailPhishingRequest
    from phishing_guard.scoring import aggregate

    stats = {}
    ind_names = Counter()
    scores = {"spam": [], "ham": []}
    t0 = time.time()
    n_done = 0
    for label, d in dirs:
        files = sorted(p for p in d.iterdir() if p.is_file())
        if limit:
            files = files[:limit]
        tp = fp = 0
        score_dist = Counter()
        for p in files:
            fields = parse_eml(p)
            try:
                req = EmailPhishingRequest(**fields)
                inds = detect(req)
            except Exception:
                continue
            v = aggregate("email", fields.get("sender", "?"), inds)
            risky = v.risk_level in ("suspicious", "high_risk", "critical")
            for ind in inds:
                ind_names[f"{label}:{ind.name}"] += 1
            scores[label].append(v.score)
            if risky:
                if label == "spam":
                    tp += 1
                else:
                    fp += 1
            score_dist[f"{label}:{v.risk_level}"] += 1
            n_done += 1
        # 多个 ham 目录合并进同一 label 桶(同名键不覆盖)
        if label in stats:
            prev = stats[label]
            prev["n"] += len(files)
            prev["flagged"] += tp if label == "spam" else fp
            for k, v2 in score_dist.items():
                prev["levels"][k] = prev["levels"].get(k, 0) + v2
        else:
            stats[label] = {
                "n": len(files), "flagged": tp if label == "spam" else fp,
                "levels": dict(score_dist),
            }
    dt = time.time() - t0

    # P/R 以 spam=阳性、ham=阴性
    tp = stats.get("spam", {}).get("flagged", 0)
    fp = stats.get("ham", {}).get("flagged", 0)
    fn = stats["spam"]["n"] - tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    # 阈值扫描: score 直方图上找最佳分离
    def _scan():
        sp = sorted(scores["spam"])
        hm = sorted(scores["ham"])
        best = (0.0, 0.0, 0.0)  # (f1, thr, acc)
        for thr in range(0, 101, 5):
            tp_ = sum(1 for s in sp if s >= thr)
            fp_ = sum(1 for s in hm if s >= thr)
            fn_ = len(sp) - tp_
            prec = tp_ / (tp_ + fp_) if tp_ + fp_ else 0.0
            rec = tp_ / (tp_ + fn_) if tp_ + fn_ else 0.0
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            acc = (tp_ + (len(hm) - fp_)) / (len(sp) + len(hm) or 1)
            if f1 > best[0]:
                best = (f1, float(thr), acc)
        return best

    f1, best_thr, acc = _scan()
    result = {
        "generated_at": date.today().isoformat(),
        "corpus": {
            "spam_dir": "spam_2 (SpamAssassin 2005, 垃圾/欺诈超集 — 非纯钓鱼, 如实)",
            "ham_dirs": ["easy_ham_2", "hard_ham"],
            "files": {k: v["n"] for k, v in stats.items()},
        },
        "elapsed_s": round(dt, 1),
        "evaluated": n_done,
        "fixed_gate": {   # scoring.aggregate 现行分界(risk_level != safe 即阳性)
            "precision": round(precision, 4), "recall": round(recall, 4),
            "spam_flagged": tp, "ham_flagged": fp,
        },
        "threshold_scan": {
            "best_f1": round(f1, 4), "best_threshold": best_thr,
            "accuracy_at_best": round(acc, 4),
            "score_histogram_note":
                "score 直方图明细见 JSON spam/ham 列表(截 200 样本)",
        },
        "top_indicators": {
            k: v for k, v in ind_names.most_common(20)
        },
        "score_samples": {
            "spam": scores["spam"][:200], "ham": scores["ham"][:200],
        },
        "honesty": [
            "spam_2 是垃圾/欺诈超集而非纯钓鱼 —— P/R 是'垃圾检出'下界",
            "Nazario 纯钓鱼语料官方需人工下载(镜像 404 已登记); PhishTank 需 key(D2#16)",
            "LLM 维度(llm_dimension)未启用(需 key) — 本标定为纯规则面",
        ],
    }
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="../tools/datasets-cache/phish-calib")
    ap.add_argument("--limit", type=int, default=0, help="每语料上限, 0=全量")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    root = Path(args.root)
    dirs = []
    spam_d = root / "spam_2"
    if spam_d.is_dir():
        dirs.append(("spam", spam_d))
    for name in ("easy_ham_2", "hard_ham"):
        d = root / name
        if d.is_dir():
            dirs.append(("ham", d))
    if not dirs:
        raise SystemExit("no corpus found under --root")
    res = run_corpus(dirs, args.limit, per_detector=False)
    out = Path(args.out) if args.out else (
        BACKEND / "eval_datasets" / "PHISH-CALIB-latest.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: res[k] for k in
                      ("evaluated", "fixed_gate", "threshold_scan", "elapsed_s")},
                     ensure_ascii=False))
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
