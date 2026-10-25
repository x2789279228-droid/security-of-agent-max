#!/usr/bin/env python3
"""live 真机演练编排器 — 攻防封禁全链路证据采集。

在【攻击机】上运行。完整链路:
    本机(攻击源) --SSH爆破--> 目标机(真实 sshd)
        --rsyslog/UDP514--> syslog-adapter --> 平台(SIG-012 原始文本聚合)
        --POL-DRILL-BRUTE(auto)--> block_ip(live)
        --SSH--> 目标机 iptables DROP 攻击源
        --TTL 3min--> 自动解封 --> 攻击源恢复连通

证据全部落 demo/live-drill/evidence/<ts>/:
    probe_baseline.json / attack.json / events_seen.json / response_action.json
    firewall_rules.json / probe_blocked.json / probe_after_ttl.json / report.md

用法(在攻击机, python3>=3.9):
    export SOC_BASE=http://<平台IP>:8001
    export SOC_USER=admin SOC_PASS=***
    export DRILL_TARGET=<目标机IP>            # 自己名下实验机
    python3 run_live_drill.py                 # 全链路
    python3 run_live_drill.py --skip-attack   # 攻击手动发起时只做观测+取证

安全断言(不满足即拒跑): 目标必须 RFC1918 私网; baseline 必须可达;
平台必须 execution_mode=live 且 SSH 通道 connect 成功。
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOC_BASE = os.environ.get("SOC_BASE", "http://127.0.0.1:8001").rstrip("/")
SOC_USER = os.environ.get("SOC_USER", "admin")
SOC_PASS = os.environ.get("SOC_PASS", "")
DRILL_TARGET = os.environ.get("DRILL_TARGET", "")
DRILL_TARGET_PORT = int(os.environ.get("DRILL_TARGET_PORT", "22"))
ATTEMPTS = int(os.environ.get("ATTEMPTS", "8"))
BLOCK_WAIT_S = int(os.environ.get("BLOCK_WAIT_S", "120"))     # 等待自动封禁出现
TTL_WAIT_S = int(os.environ.get("TTL_WAIT_S", "300"))         # 等待 TTL 自动解封
EVIDENCE_ROOT = Path(__file__).parent / "evidence"
DRILL_POLICY = "POL-DRILL-BRUTE"
DRILL_ALLOW_PUBLIC = os.environ.get("DRILL_ALLOW_PUBLIC", "0") == "1"

_ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
EV = EVIDENCE_ROOT / _ts

report_lines: list[str] = []


def log(msg: str) -> None:
    line = f"[drill {datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    report_lines.append(line)


def die(msg: str) -> None:
    log(f"FATAL: {msg}")
    write_report("FATAL")
    sys.exit(1)


# ── 平台 API ──
_token = ""


def api(method: str, path: str, body: dict | None = None, timeout: int = 20) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(SOC_BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if _token:
        req.add_header("Authorization", f"Bearer {_token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "null")
        except Exception:  # noqa: BLE001
            return e.code, None


def login() -> None:
    global _token
    rc, body = api("POST", "/api/auth/login",
                   {"username": SOC_USER, "password": SOC_PASS})
    if rc != 200 or not isinstance(body, dict) or "access_token" not in body:
        die(f"登录失败 rc={rc} — 检查 SOC_USER/SOC_PASS ({str(body)[:120]})")
    _token = body["access_token"]
    log(f"登录 OK user={SOC_USER}")


# ── 连通性探测 (攻击源视角, 证据核心) ──
def probe(n: int = 3) -> dict:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((DRILL_TARGET, DRILL_TARGET_PORT), timeout=3)
            s.close()
            samples.append({"ok": True, "ms": round((time.perf_counter() - t0) * 1000)})
        except OSError as e:
            samples.append({"ok": False, "ms": round((time.perf_counter() - t0) * 1000),
                            "err": str(e)[:80]})
        time.sleep(0.2)
    ok = sum(1 for x in samples if x["ok"])
    return {"target": f"{DRILL_TARGET}:{DRILL_TARGET_PORT}", "samples": samples, "ok_count": ok}


def save(name: str, obj: object) -> Path:
    p = EV / name
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((DRILL_TARGET, DRILL_TARGET_PORT))
    ip = s.getsockname()[0]
    s.close()
    return ip


# ── 演练策略启用/复位 (trap 语义: finally 必复位) ──
_drill_policy_enabled = False


def enable_drill_policy() -> None:
    global _drill_policy_enabled
    rc, body = api("PUT", "/api/response/policies",
                   {"name": DRILL_POLICY, "enabled": True,
                    "change_summary": "live-drill 临时启用(run_live_drill.py, 结束自动复位)"})
    if rc != 200:
        die(f"启用 {DRILL_POLICY} 失败 rc={rc} {str(body)[:150]} (需要 admin 角色)")
    rc, rows = api("GET", "/api/response/policies")
    pol = next((p for p in (rows or []) if p.get("name") == DRILL_POLICY), None)
    if not pol or not pol.get("enabled"):
        die(f"{DRILL_POLICY} 启用后未生效: {str(pol)[:150]}")
    if pol.get("priority", 0) <= 80:
        die(f"{DRILL_POLICY} priority={pol.get('priority')} 必须 > 80 才能压过 POL-BRUTE-FORCE")
    _drill_policy_enabled = True
    log(f"{DRILL_POLICY} 已启用 (priority={pol['priority']}, TTL=3min)")


def disable_drill_policy() -> None:
    global _drill_policy_enabled
    if not _drill_policy_enabled:
        return
    rc, _ = api("PUT", "/api/response/policies",
                {"name": DRILL_POLICY, "enabled": False,
                 "change_summary": "live-drill 复位(自动)"})
    _drill_policy_enabled = False
    log(f"{DRILL_POLICY} 已复位为 disabled (rc={rc})")


# ── 平台侧观测 ──
def find_events(my_ip: str, since_epoch: float) -> list[dict]:
    rc, rows = api("GET", "/api/logs/events?limit=200")
    if rc != 200 or not isinstance(rows, list):
        return []
    out = []
    for r in rows:
        msg = str(r.get("message") or "")
        ts_raw = r.get("timestamp") or r.get("created_at") or 0
        try:
            ts = float(ts_raw) if float(ts_raw) > 1e12 else float(ts_raw)
        except (TypeError, ValueError):
            ts = 0
        if "Failed password" in msg and (r.get("src_ip") == my_ip or my_ip in msg):
            if ts >= since_epoch - 60:
                out.append(r)
    return out


def find_block_action(my_ip: str) -> dict | None:
    for path in ("/api/response/actions?limit=100", "/api/response/logs?limit=100"):
        rc, rows = api("GET", path)
        if rc != 200 or not isinstance(rows, list):
            continue
        for r in rows:
            blob = json.dumps(r, ensure_ascii=False)
            if "block_ip" in blob and my_ip in blob:
                return r
    return None


def wait_for(predicate, timeout_s: int, interval: int, what: str):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        got = predicate()
        if got:
            log(f"{what} ✓ (等待 {time.time()-t0:.0f}s)")
            return got
        time.sleep(interval)
    return None


def write_report(status: str) -> None:
    md = ["# live 演练运行记录", "",
          f"- 状态: **{status}**",
          f"- 时间: {_ts}",
          f"- 平台: {SOC_BASE}",
          f"- 目标: {DRILL_TARGET}:{DRILL_TARGET_PORT}",
          "", "## 时间线", ""]
    md += [f"- {ln}" for ln in report_lines]
    md += ["", "> 本文件为运行时记录; 正式演练报告模板见 REPORT-TEMPLATE.md",
           "> (人工补充拓扑图、截图与 GRep 时间线后归档 docs/drill/)。"]
    (EV / "report.md").write_text("\n".join(md), encoding="utf-8")


# ── 主流程 ──
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-attack", action="store_true",
                    help="不本地发起爆破(攻击由外部手动发起), 只观测+取证")
    args = ap.parse_args()

    if not SOC_PASS:
        die("必须设置 SOC_PASS")
    if not DRILL_TARGET:
        die("必须设置 DRILL_TARGET (目标机 IP, 限自己名下实验机)")
    if not DRILL_ALLOW_PUBLIC and not ipaddress.ip_address(DRILL_TARGET).is_private:
        die(f"目标 {DRILL_TARGET} 不是私网地址 — 演练仅限自有实验网"
            " (确要公网目标需 DRILL_ALLOW_PUBLIC=1 且另附授权说明)")
    EV.mkdir(parents=True, exist_ok=True)
    log(f"证据目录 {EV}")

    # P0 preflight
    rc, health = api("GET", "/api/health")
    rc == 200 or die(f"平台不可达 rc={rc}")
    login()
    rc, body = api("POST", "/api/firewall/connect")
    log(f"firewall/connect rc={rc} {str(body)[:120]}")
    rc, fw = api("GET", "/api/firewall/status")
    fw = fw or {}
    if fw.get("execution_mode") != "live":
        die(f"execution_mode={fw.get('execution_mode')!r} — 演练要求 .env 设 "
            "SHARED_MEMORY_EXECUTION_MODE=live 后重启 backend (fail-closed 设计, 拒绝假设)")
    if not fw.get("enabled"):
        die(f"SSH 防火墙未启用: {str(fw)[:150]} — 检查 FW_SSH_HOST/USER/KEY 配置")
    log(f"preflight OK: mode=live, fw host={fw.get('host')}")

    my_ip = local_ip()
    log(f"攻击源本机 IP = {my_ip}")

    try:
        # P1 启用演练策略
        enable_drill_policy()

        # P2 baseline 连通性 (封禁前必须可达)
        base = probe()
        save("probe_baseline.json", base)
        if base["ok_count"] == 0:
            die("baseline 全部探测失败 — 目标不可达, 无法演练")
        log(f"baseline: {base['ok_count']}/{len(base['samples'])} 可达")

        # P3 发起攻击 / 或等待外部攻击
        since = time.time()
        if not args.skip_attack:
            env = dict(os.environ, DRILL_ATTACK_LOG=str(EV / "attack.json"))
            p = subprocess.run([sys.executable, str(Path(__file__).parent / "attacker-bruteforce.py")],
                               env=env)
            log(f"攻击进程结束 rc={p.returncode}")

        # P4 平台可见性 + 检出
        ev_rows = wait_for(lambda: find_events(my_ip, since),
                           BLOCK_WAIT_S, 4, "平台收到原始 Failed password 事件")
        save("events_seen.json", ev_rows or [])
        if not ev_rows:
            die(f"{BLOCK_WAIT_S}s 内平台未见事件 — 检查 rsyslog 转发/syslog-adapter/事件查询API")
        first_ev_ts = ev_rows[-1].get("timestamp") or since

        # P5 自动封禁出现
        action = wait_for(lambda: find_block_action(my_ip),
                          BLOCK_WAIT_S, 4, "block_ip 动作落账")
        save("response_action.json", action or {})
        if not action:
            die("自动 block_ip 未出现 — 检查 POL-DRILL-BRUTE 是否命中 / orchestrator 日志")

        # P6 封禁中的连通性 (必须全断 — 金证据)
        blocked = probe()
        save("probe_blocked.json", blocked)
        tries = 0
        while blocked["ok_count"] > 0 and tries < 3:
            log(f"封禁未生效? 重试 {tries+1}/3 (规则下发可能有秒级延迟)")
            time.sleep(5)
            blocked = probe()
            save("probe_blocked.json", blocked)
            tries += 1
        if blocked["ok_count"] > 0:
            die(f"封禁后仍可连通 {blocked['ok_count']}/3 — live 封禁未真实生效, 检查 execution_mode/iptables")
        log("封禁生效: 3/3 探测全部失败 (iptables DROP 真实生效)")

        # P7 防火墙规则留痕
        rc, rules = api("GET", "/api/firewall/rules")
        save("firewall_rules.json", {"rc": rc, "rules": rules})

        # P8 TTL 自动解封
        def unblocked() -> bool:
            return probe(1)["ok_count"] > 0
        t0 = time.time()
        if wait_for(unblocked, TTL_WAIT_S, 5, "TTL 到期自动解封"):
            after = probe()
            save("probe_after_ttl.json", after)
            log(f"自动解封确认 (耗时 {time.time()-t0:.0f}s), 复测 {after['ok_count']}/3 可达")
        else:
            log(f"WARN: {TTL_WAIT_S}s 内未自动解封 — 记录为异常, 检查 ttl_manager")

        write_report("PASS" if blocked["ok_count"] == 0 else "PARTIAL")
        log(f"完成。证据在 {EV}")
    finally:
        disable_drill_policy()


if __name__ == "__main__":
    main()
