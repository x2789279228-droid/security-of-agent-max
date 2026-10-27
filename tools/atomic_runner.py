"""atomic-runner.py — Atomic Red Team 执行编排器(路线 1)。

目的: 把"检测是复述模拟器标签"修成"检测面对真实攻击行为"。
Atomic Red Team(GitHub: redcanaryco/atomic-red-team)按 ATT&CK 技术编号
提供几百个真实攻击测试, 每个 Atomic 在测试 VM 上产生**真实系统事件**
(Sysmon 进程/网络/注册表), 平台据此被检验。

安全铁律(写死在本工具里, 不可配置绕过):
  1. 默认 plan 模式 —— 只打印执行计划, 不执行任何命令;
  2. local 模式必须同时满足: --execute-local 显式给出 + 环境变量
     ATOMIC_I_AM_ON_A_TEST_VM=yes(自我声明在测试虚机上) + 本机不是
     生产形态(无 .env 或 .env 含 SHARED_MEMORY_SKIP_DOTENV=1);
  3. remote 模式只**生成** PowerShell 脚本(用官方 invoke-atomicredteam
     模块), 由人工拷贝到测试 VM 执行 —— 平台侧永远不碰真实系统;
  4. 每个 run 记录时间窗/主机/预期可见事件, 供 evaluate_attack_coverage
     做检出对账; 快照回滚纪律见 docs/upgrade/ATOMIC-REDTEAM-RUNBOOK.md。

用法:
    python tools/atomic-runner.py --manifest tools/atomic/manifest.json            # plan
    python tools/atomic-runner.py --manifest ... --mode remote --out ./atomic-out  # 生成 PS1
    # 测试 VM 上(仅当上面两条确认后):
    python tools/atomic-runner.py --manifest ... --mode local --execute-local --out ./atomic-out
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_PRODUCTION_MARKERS = ("SHARED_MEMORY_ADMIN_PASSWORD=", "SHARED_MEMORY_LLM_API_KEY=sk-")
_VM_MARKER_ENV = "ATOMIC_I_AM_ON_A_TEST_VM"


def load_manifest(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    runs = data.get("runs", data if isinstance(data, list) else [])
    for r in runs:
        for key in ("technique", "atomic", "executor"):
            if not r.get(key):
                raise SystemExit(f"manifest 条目缺 {key}: {r!r}")
    return runs


def plan_lines(runs: list[dict]) -> list[str]:
    lines = []
    for r in runs:
        lines.append(
            f"- [{r['technique']}] atomic#{r['atomic']} via {r['executor']}: "
            f"{r.get('description', '')[:80]}"
        )
    return lines


def render_remote_script(runs: list[dict]) -> str:
    """生成 invoke-atomicredteam 执行脚本(人工拷到测试 VM 跑)。"""
    tids = sorted({r["technique"] for r in runs})
    by_tech: dict[str, list[dict]] = {}
    for r in runs:
        by_tech.setdefault(r["technique"], []).append(r)
    lines = [
        "# 由 tools/atomic-runner.py --mode remote 生成 —— 仅在测试虚机执行!",
        "# 前置: Install-Module -Name invoke-atomicredteam -Scope CurrentUser",
        "#       Invoke-AtomicRunner 初始化(见 ATOMIC-REDTEAM-RUNBOOK.md)",
        f"# 技术: {', '.join(tids)}",
        "$ErrorActionPreference = 'Continue'",
        "$runs = @(",
    ]
    for r in runs:
        cmd = str(r.get("command", "")).replace('"', '`"')
        lines.append(
            f'  @{{ technique="{r["technique"]}"; atomic={r["atomic"]}; '
            f'executor="{r["executor"]}"; command="{cmd}" }},'
        )
    lines += [
        ")",
        "foreach ($r in $runs) {",
        "  $start = (Get-Date).ToUniversalTime().ToString('o')",
        "  Write-Host \"[RUN] $($r.technique) atomic#$($r.atomic)\"",
        "  # 官方模块执行(会真实改动测试 VM! 快照先行!):",
        "  Invoke-AtomicTest -Technique $r.technique -TestNumbers $r.atomic -KeepPrereqs",
        "  $end = (Get-Date).ToUniversalTime().ToString('o')",
        "  @{technique=$r.technique; atomic=$r.atomic; executor=$r.executor;",
        "    start=$start; end=$end; host=$env:COMPUTERNAME} |",
        "    ConvertTo-Json -Compress | Add-Content \"./ground-truth.jsonl\"",
        "}",
        "Write-Host 'ground-truth.jsonl 已生成 —— 拷回平台侧跑 evaluate_attack_coverage'",
    ]
    return "\n".join(lines) + "\n"


def run_local(runs: list[dict], out_dir: Path) -> int:
    """local 模式: 本机执行(仅测试 VM!)。产出 ground-truth JSONL。"""
    if os.environ.get(_VM_MARKER_ENV) != "yes":
        print(f"[拒绝] 缺 {_VM_MARKER_ENV}=yes 自我声明 —— 请确认你在测试虚机上", file=sys.stderr)
        return 4
    env_file = Path(".env")
    if env_file.exists():
        head = env_file.read_text(encoding="utf-8", errors="replace")[:4000]
        for marker in _PRODUCTION_MARKERS:
            if marker in head:
                print(f"[拒绝] 本机 .env 含生产形态标记({marker[:30]}...)", file=sys.stderr)
                return 4

    out_dir.mkdir(parents=True, exist_ok=True)
    gt_path = out_dir / "ground-truth.jsonl"
    print(f"[危险] 即在本机真实执行 {len(runs)} 个 Atomic —— 确认已做 VM 快照!")
    import subprocess

    for r in runs:
        start = datetime.now(timezone.utc).isoformat()
        try:
            subprocess.run(r["command"], shell=True,
                           timeout=int(r.get("timeout_s", 120)), check=False)
        except Exception as e:
            print(f"[warn] {r['technique']}#{r['atomic']} 执行异常: {e}", file=sys.stderr)
        end = datetime.now(timezone.utc).isoformat()
        rec = {
            "run_id": f"{r['technique']}-{r['atomic']}-{start[:19]}",
            "technique": r["technique"], "atomic": r["atomic"],
            "executor": r["executor"], "host": os.environ.get("COMPUTERNAME", "test-vm"),
            "start": start, "end": end,
            "expected_visibility": r.get("expected_visibility", []),
            "description": r.get("description", ""),
        }
        with gt_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"[done] {r['technique']}#{r['atomic']} → {gt_path.name}")
    print(f"ground truth 已写 {gt_path} —— 拷回平台侧跑 evaluate_attack_coverage")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--manifest", default=str(Path(__file__).parent / "atomic" / "manifest.json"))
    ap.add_argument("--mode", default="plan", choices=["plan", "remote", "local"])
    ap.add_argument("--out", default="./atomic-out")
    ap.add_argument("--execute-local", action="store_true",
                    help="local 模式的显式执行开关(plan/remote 忽略)")
    args = ap.parse_args()

    runs = load_manifest(Path(args.manifest))
    out_dir = Path(args.out)

    if args.mode == "plan":
        print(f"执行计划({len(runs)} 个 Atomic —— plan 模式不执行任何命令):")
        print("\n".join(plan_lines(runs)))
        print("\nremote 生成脚本: --mode remote --out <dir>")
        return 0
    if args.mode == "remote":
        out_dir.mkdir(parents=True, exist_ok=True)
        script = out_dir / "invoke-atomics.ps1"
        script.write_text(render_remote_script(runs), encoding="utf-8-sig")
        print(f"PowerShell 脚本已生成: {script}")
        print("人工拷贝到测试虚机执行(前置见 ATOMIC-REDTEAM-RUNBOOK.md), "
              "产出 ground-truth.jsonl 后拷回, 跑 evaluate_attack_coverage")
        return 0
    # local
    if not args.execute_local:
        print("[拒绝] local 模式必须显式 --execute-local(防误伤开发机)", file=sys.stderr)
        return 4
    return run_local(runs, out_dir)


if __name__ == "__main__":
    sys.exit(main())
