#!/usr/bin/env python3
"""live 演练 — 攻击机侧 SSH 爆破器 (授权实验环境专用)。

在【自己的】攻击 VM 上运行, 对【自己的】目标 VM 发起真实 SSH 认证尝试,
每条失败认证都会在目标机 /var/log/auth.log 留下原始 "Failed password" 行,
经 rsyslog → syslog-adapter 进入平台, 由 SIG-012 对原始文本聚合检出。

仅支持弱构造(单线程、固定错误口令、可随时 Ctrl-C), 只用于自家实验网:
    授权范围 = DRILL_TARGET 指向的自己名下虚拟机。禁止对任何
    非自有主机使用 —— 合规边界见 docs/competition-materials/02-合规声明.md。

用法:
    DRILL_TARGET=10.0.0.30 ATTEMPTS=8 bash attacker-bruteforce.py
    # 或 python3 attacker-bruteforce.py (读同样环境变量)

实现: 优先 sshpass+ssh (无依赖、每连接独立), 回退 paramiko。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

TARGET = os.environ.get("DRILL_TARGET", "")
PORT = int(os.environ.get("DRILL_TARGET_PORT", "22"))
USER = os.environ.get("DRILL_SSH_USER", "root")          # 目标机存在的用户名
ATTEMPTS = int(os.environ.get("ATTEMPTS", "8"))
DELAY = float(os.environ.get("DELAY", "0.8"))
WRONG_PASS = os.environ.get("DRILL_WRONG_PASS", "drill-wrong-pass-#2026")
OUT = os.environ.get("DRILL_ATTACK_LOG", "")

if not TARGET:
    raise SystemExit("必须设置 DRILL_TARGET (目标机 IP, 须为自己名下实验机)")

results: list[dict] = []


def record(i: int, method: str, ok_banner: bool, auth_failed: bool, err: str, ms: float):
    row = {
        "seq": i, "ts": time.time(), "method": method,
        "banner": ok_banner, "auth_failed": auth_failed, "error": err, "ms": round(ms),
    }
    results.append(row)
    print(f"[attack {i}/{ATTEMPTS}] banner={ok_banner} auth_failed={auth_failed}"
          f" {ms:.0f}ms {err[:60]}")


def via_sshpass(i: int) -> None:
    t0 = time.perf_counter()
    p = subprocess.run(
        ["sshpass", "-p", WRONG_PASS, "ssh",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=5", "-o", "NumberOfPasswordPrompts=1",
         "-o", "PreferredAuthentications=password,keyboard-interactive",
         "-p", str(PORT), f"{USER}@{TARGET}", "true"],
        capture_output=True, text=True, timeout=20,
    )
    ms = (time.perf_counter() - t0) * 1000
    # 认证失败: Permission denied; 连接被防火墙拒: timeout /Connection refused
    denied = "permission denied" in (p.stderr + p.stdout).lower()
    record(i, "sshpass+ssh", True, denied, p.stderr.strip(), ms)


def via_paramiko(i: int) -> None:
    import paramiko  # 回退依赖: pip install paramiko
    t0 = time.perf_counter()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(TARGET, port=PORT, username=USER, password=WRONG_PASS,
                  timeout=5, allow_agent=False, look_for_keys=False)
        record(i, "paramiko", True, False, "auth unexpectedly SUCCEEDED", (time.perf_counter() - t0) * 1000)
    except paramiko.AuthenticationException:
        record(i, "paramiko", True, True, "authentication failed", (time.perf_counter() - t0) * 1000)
    except Exception as e:  # noqa: BLE001 — 演练工具, 任何失败都要落证据
        record(i, "paramiko", False, False, str(e), (time.perf_counter() - t0) * 1000)
    finally:
        c.close()


def main() -> None:
    print(f"[attack] target={TARGET}:{PORT} user={USER} attempts={ATTEMPTS} delay={DELAY}s")
    use_sshpass = shutil.which("sshpass") is not None
    if not use_sshpass:
        try:
            import paramiko  # noqa: F401
        except ImportError:
            raise SystemExit("需要 sshpass 或 paramiko 之一 (apt install sshpass)")
    for i in range(1, ATTEMPTS + 1):
        try:
            (via_sshpass if use_sshpass else via_paramiko)(i)
        except subprocess.TimeoutExpired:
            record(i, "sshpass+ssh", False, False, "connection timed out (可能已被封禁→停止攻击)", 5000)
            break
        time.sleep(DELAY)
    if OUT:
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump({"target": TARGET, "attempts": results}, f, ensure_ascii=False, indent=2)
        print(f"[attack] 证据已写 {OUT}")


if __name__ == "__main__":
    main()
