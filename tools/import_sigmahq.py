#!/usr/bin/env python3
"""SigmaHQ 批量导入 → 分层规则库 (优化计划 B1: 内置 16 条 → 150+)

分层接入策略(与 backend/sigma_engine/COMMUNITY_RULES_GUIDE.md 对齐):
    SigmaHQ 原始规则
      → 字段兼容性过滤(平台 schema 没有的字段 = 永不命中的死重, 直接剔除)
      → x-soc-* 适配(x-soc-shadow: true —— 批量导入一律影子模式,
                     只有"记录+告警"权, 没有执行权; 转 enforcement 由
                     nightly-backtest 的 precision 数据说话)
      → pySigma 编译门禁(编译失败剔除并记入 manifest)
      → rules_community_active/hq_*.yml(引擎加载面) + SIGMAHQ_MANIFEST.json

源: https://github.com/SigmaHQ/sigma (Detection Rule License 1.1, 许可与
出处保留在每个文件的 license/author/related 字段与 manifest 中)。

用法:
    # 1) 拉源(或自行解压到 tools/.sigmahq-cache/sigma-master)
    curl -sL -o tools/.sigmahq-cache/sigma.tar.gz \
      https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master
    tar -xzf tools/.sigmahq-cache/sigma.tar.gz -C tools/.sigmahq-cache \
      "sigma-master/rules/web" "sigma-master/rules/proxy" "sigma-master/rules/network"

    # 2) 导入(幂等: 清掉旧 hq_* 后全量重写)
    python tools/import_sigmahq.py --backend-dir backend
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import shutil
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
SIGMA_ROOT_DEFAULT = REPO / "tools" / ".sigmahq-cache" / "sigma-master"

# ── 平台 schema 经 mapping.py 别名后可用的 Sigma 字段(白名单) ──
# 与 backend/sigma_engine/mapping.py 的 PLATFORM_TO_SIGMA 保持同步。
COMPAT_FIELDS = {
    # 平台原生
    "event", "event.category", "category", "src_ip", "source.ip", "client-ip", "c-ip",
    "dst_ip", "destination.ip", "dest_ip", "dst", "url", "http.url", "http.url_original",
    "message", "details", "dst_port", "destination.port", "dest_port", "protocol",
    "network.protocol", "server", "destination.hostname", "host",
    # web/proxy 高频
    "http.method", "cs-method", "c-method", "method",
    "http.response.status_code", "sc-status", "c-status", "status",
    "http.user_agent", "cs-user-agent", "c-useragent", "UserAgent", "cs-UserAgent",
    "user_agent",
    "http.referrer", "cs-referer", "c-referer", "referer",
    "cs-uri-query", "cs-uri-stem", "c-uri", "cs-uri", "c-uri-query",
    "UriPath", "UriQuery", "cs-host", "c-host", "Hostname",
    # 2026-10-27 路线 4: DNS 查询域(mapping.py dns_query 别名, 同步)
    "dns_query", "dns.query", "dns.query.name", "dns.question.name",
    "query", "rrname",
    # 2026-10-27 路线 4 预铺: 文件哈希(mapping.py file_hash 别名, 同步)。
    # 当前类别无 hash 规则, 第二批(Sysmon 数据源)到位后生效。
    "file_hash", "file.hash.sha256", "file.hash.md5", "file.hash.sha1",
    "sha256", "sha1", "md5",
}

CATEGORIES = {"webserver", "proxy", "network", "dns"}
ID_START = 101          # C-101 起, 避开手策展的 C-001..C-005
PREFIX = "hq_"
LEVEL_TO_CONF = {"critical": "high", "high": "high", "medium": "medium",
                 "low": "low", "informational": "low"}


def _detection_fields(detection: dict) -> set:
    fields = set()
    for k, v in (detection or {}).items():
        if k == "condition" or not isinstance(v, dict):
            continue
        for fk in v:
            fields.add(fk.split("|", 1)[0])
    return fields


def _attack_type(rule: dict, category: str) -> str:
    """从 ATT&CK tag 推一个粗 attack_type; 无 tag 时按 logsource 兜底。"""
    tag_map = {
        "initial-access": "web_attack", "execution": "malware",
        "persistence": "malware", "privilege-escalation": "privilege_escalation",
        "command-and-control": "c2_communication", "exfiltration": "data_exfiltration",
        "credential-access": "brute_force", "discovery": "info_disclosure",
        "lateral-movement": "lateral_movement", "impact": "malware",
        "collection": "data_exfiltration", "defense-evasion": "malware",
    }
    for t in rule.get("tags") or []:
        if str(t).startswith("attack."):
            tactic = str(t).split(".", 1)[1].split(".", 1)[0]
            if tactic in tag_map:
                return tag_map[tactic]
    return {"webserver": "web_attack", "proxy": "web_attack"}.get(category, "network_anomaly")


def _rule_disqualify_reasons(d: dict) -> list[str]:
    """与平台引擎/事件形态不兼容的规则类别(实测教训, 缺一个就带病上岗):

    - `|re` 修饰符: 自研 SQLite 后端无 REGEXP 函数 → 每条事件刷执行错误
      (2026-10-25 实测 C-110/C-203/C-204/C-211/C-214/C-228);
    - 空字符串字面量: "字段为空"语义在稀疏合成事件上 = "字段缺失也算空"
      → 良性事件全量误报(实测 C-117 Empty-User-Agent ×10/10 良性样本)。
    """
    reasons = []
    det = d.get("detection") or {}
    text = yaml.safe_dump(det)
    if re.search(r"\|(?:re|re:[a-z-]+)\b", text):
        reasons.append("re_modifier_unsupported")
    def _walk(v):
        if isinstance(v, str):
            if v == "":
                reasons.append("empty_string_literal")
            return
        if isinstance(v, list):
            for x in v:
                _walk(x)
        elif isinstance(v, dict):
            for x in v.values():
                _walk(x)
    _walk(det)
    return sorted(set(reasons))


def collect_rules(sigma_root: Path) -> list[dict]:
    """扫描 + 过滤, 返回可适配的规则列表(带剔除原因)。"""
    out: list[dict] = []
    for sub in ("web", "proxy", "network", "rules-emerging-threats"):
        base = sigma_root / "rules" / sub if sub != "rules-emerging-threats" \
            else sigma_root / sub
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*.yml")):
            rel = str(f.relative_to(sigma_root))
            try:
                d = yaml.safe_load(f.read_text(encoding="utf-8"))
            except Exception as e:
                out.append({"file": rel, "data": None, "reason": f"yaml_parse: {e}"})
                continue
            if not isinstance(d, dict) or not d.get("detection"):
                out.append({"file": rel, "data": None, "reason": "no_detection"})
                continue
            cat = (d.get("logsource") or {}).get("category", "")
            if cat not in CATEGORIES:
                out.append({"file": rel, "data": None, "reason": f"category:{cat or 'none'}"})
                continue
            fields = _detection_fields(d["detection"])
            unknown = fields - COMPAT_FIELDS
            if unknown:
                out.append({"file": rel, "data": None,
                            "reason": f"fields_absent:{','.join(sorted(unknown))[:120]}"})
                continue
            disq = _rule_disqualify_reasons(d)
            if disq:
                out.append({"file": rel, "data": None,
                            "reason": f"incompatible:{','.join(disq)}"})
                continue
            out.append({"file": rel, "data": d, "reason": ""})
    return out


def adapt(rule: dict, seq: int) -> dict:
    """注入 x-soc-* 适配层。影子模式 + 仅告警是批量导入的安全底线。"""
    d = dict(rule)
    level = str(d.get("level", "medium")).lower()
    d["x-soc-id"] = f"C-{ID_START + seq}"
    d["x-soc-shadow"] = True
    d["x-soc-action"] = "alert"
    d["x-soc-confidence"] = LEVEL_TO_CONF.get(level, "medium")
    d["x-soc-attack_type"] = _attack_type(d, (d.get("logsource") or {}).get("category", ""))
    d["x-soc-severity"] = level if level in ("critical", "high", "medium", "low") else "medium"
    d["x-soc-source"] = "SigmaHQ"
    d["x-soc-sigmahq-id"] = d.get("id", "")
    d["x-soc-version"] = 1
    return d


def compile_gate(candidates: list[dict], workdir: Path) -> tuple[list[dict], list[dict]]:
    """pySigma 编译门禁: 编译失败的规则不进 active。返回 (通过, 失败)。"""
    sys.path.insert(0, str(REPO / "backend"))
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)
    ok, failed = [], []
    # 逐条编译(每条一个临时目录) —— 失败定位到文件, 而不是整批报废
    from sigma_engine.engine import PySigmaDetector
    for i, item in enumerate(candidates):
        d = item["data"]
        single = workdir / f"c{i}.yml"
        safe = {k: v for k, v in d.items() if k != "id"}
        single.write_text(yaml.safe_dump(safe, allow_unicode=True, sort_keys=False),
                          encoding="utf-8")
        try:
            det = PySigmaDetector(str(workdir), enforce=True)
            # rules() 返回 meta 字典的平铺元组(每条规则一个元素) ——
            # 不是 (列表, ...) 嵌套结构
            metas = det.rules()
            n = sum(1 for m in (metas or [])
                    if isinstance(m, dict) and m.get("rule_id"))
            if n >= 1:
                ok.append(item)
            else:
                failed.append({"file": item["file"], "reason": "compiled_empty"})
        except Exception as e:
            failed.append({"file": item["file"],
                           "reason": f"compile: {str(e)[:160]}"})
        single.unlink(missing_ok=True)
    return ok, failed


def _existing_active_titles(active_dir: Path) -> set:
    """active 目录里非 hq 批量规则(title 小写规范化)—— 用于标题去重:
    手适配的 C-001..C-005 等本就源自 SigmaHQ 同名规则, 重复导入会让
    同一条检测出现两份(影子/执行混跑, 污染 precision 统计)。"""
    titles = set()
    for f in active_dir.glob("*.yml"):
        if f.name.startswith(PREFIX):
            continue
        try:
            d = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(d, dict) and d.get("title"):
            titles.add(str(d["title"]).strip().lower())
    return titles


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma-root", default=str(SIGMA_ROOT_DEFAULT))
    ap.add_argument("--backend-dir", default=str(REPO / "backend"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    sigma_root = Path(args.sigma_root)
    active_dir = Path(args.backend_dir) / "sigma_engine" / "rules_community_active"
    if not sigma_root.is_dir():
        print(f"[FAIL] SigmaHQ 源不存在: {sigma_root} — 先按文件头注释拉源", file=sys.stderr)
        return 2

    print(f"[1/4] 扫描 {sigma_root}")
    all_rules = collect_rules(sigma_root)
    # 标题去重: 手适配的 active 规则(非 hq_*)已覆盖的同名 SigmaHQ 规则跳过
    known_titles = _existing_active_titles(active_dir)
    compatible = []
    title_dupes = 0
    for r in all_rules:
        if r["data"] is None:
            continue
        title = str(r["data"].get("title", "")).strip().lower()
        if title and title in known_titles:
            title_dupes += 1
            continue
        compatible.append(r)
    print(f"      扫描 {len(all_rules)} 条, 字段兼容 {len(compatible)} 条"
          f" (标题去重 {title_dupes}, 其余剔除明细见 manifest)")

    print("[2/4] x-soc 适配(影子模式)")
    adapted = [{"file": r["file"], "data": adapt(r["data"], i)}
               for i, r in enumerate(compatible)]

    print("[3/4] pySigma 编译门禁")
    ok, failed = compile_gate(adapted, active_dir / ".compile_workdir")
    shutil.rmtree(active_dir / ".compile_workdir", ignore_errors=True)
    print(f"      编译通过 {len(ok)} / 失败剔除 {len(failed)}")

    if args.dry_run:
        print("[dry-run] 不写文件。编译通过样例:",
              [r["file"] for r in ok[:5]])
        return 0

    print("[4/4] 写入 active(shadow) + manifest")
    for old in active_dir.glob(f"{PREFIX}*.yml"):
        old.unlink()
    written = 0
    for item in ok:
        target = active_dir / f"{PREFIX}{Path(item['file']).stem}.yml"
        target.write_text(
            yaml.safe_dump(item["data"], allow_unicode=True, sort_keys=False, width=100),
            encoding="utf-8",
        )
        written += 1

    manifest = {
        "source": "https://github.com/SigmaHQ/sigma",
        "license": "Detection Rule License (DRL) 1.1",
        "imported_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "sigma_root_ref": "master",
        "total_scanned": len(all_rules),
        "field_compatible": len(compatible),
        "compiled_ok": len(ok),
        "written": written,
        "shadow_mode": True,
        "id_range": f"C-{ID_START}+",
        "dropped": [
            {"file": r["file"], "reason": r["reason"]}
            for r in all_rules if r["data"] is None
        ] + failed,
    }
    (Path(args.backend_dir) / "sigma_engine" / "SIGMAHQ_MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"完成: active 目录 hq_* 规则 {written} 条(全部 x-soc-shadow=true)")
    print(f"     manifest: {args.backend_dir}/sigma_engine/SIGMAHQ_MANIFEST.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
