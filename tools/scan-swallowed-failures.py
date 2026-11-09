# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""系统扫描：「失败被吞成一行日志、且没有任何计数」的地方。

§9.34 命中的形态：自动化动作失败 → `except Exception` → 只 `logger.warning`
→ 没有指标 → 失败与「不需要做」在指标上同形。

本脚本把这一形态在全仓扫出来，供**人工分诊**：
哪些是「运营决策路径」（该有计数），哪些是「尽力而为的清理」（吞掉无妨）。

口径：
  · 排除 tests/；
  · 只看 `except Exception` / `except BaseException` 这类**宽异常**；
  · 判定「有计数」：handler 体内出现 `.inc()` / `record_*` / `observe_*` /
    `inc_*` / `set_*` 之类的指标调用；
  · 同时标出「handler 直接返回一个假值」（None / False / [] / {}）——
    那是最隐蔽的一类：调用方无法区分「失败」与「没有该做」。
"""
import ast
import io
import os
import re
import sys

# 相对脚本位置解析仓库 backend/ — 不允许硬编码本机绝对路径：
# 2026-10-29 复审 P0-1：写死 Windows 路径后在 Linux CI 上 os.walk 空迭代、
# 退出 0，"扫描没跑"与"扫出零结果"同形（假门禁）。
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "backend"))
sys.stdout.reconfigure(encoding="utf-8")

SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git",
             "frontend", "dist", "build", ".pytest_cache", "event_archive",
             "prompt_templates"}

# 指标调用特征
METRIC_PAT = re.compile(
    r"\.inc\(|record_\w+\(|observe_\w+\(|inc_\w+\(|set_\w+\(|"
    r"log_process\(|evaluate_core_alerts\(|add_alert\(")

# 认定为「运营决策路径」的关键字（函数/模块名里出现即高亮）
OPS_HINT = re.compile(
    r"dispatch|auto_|alert|block|isolate|respond|escalat|notif|"
    r"create_case|create_order|work_order|submit|enqueue|persist|"
    r"commit|remind|quarantine|kill_|close_case|resolve", re.I)

results = []
scanned_files = 0
for dirpath, dirnames, filenames in os.walk(REPO):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in filenames:
        if not fn.endswith(".py"):
            continue
        scanned_files += 1
        p = os.path.join(dirpath, fn)
        rel = os.path.relpath(p, REPO).replace("\\", "/")
        if rel.startswith("tests/") or "/tests/" in rel:
            continue
        try:
            src = io.open(p, encoding="utf-8").read()
            tree = ast.parse(src)
        except (OSError, SyntaxError):
            continue
        lines = src.splitlines()

        # 建立 函数名 → 节点 的映射
        func_of = {}

        def walk(node, cur=""):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_of[child] = child.name
                    walk(child, child.name)
                else:
                    walk(child, cur)
        walk(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            t = node.type
            names = []
            if isinstance(t, ast.Name):
                names = [t.id]
            elif isinstance(t, ast.Tuple):
                names = [e.id for e in t.elts if isinstance(e, ast.Name)]
            if not any(n in ("Exception", "BaseException") for n in names):
                continue
            body_src = "\n".join(lines[node.lineno - 1: (node.end_lineno or node.lineno)])
            has_log = re.search(r"logger\.(warning|error|exception|info)", body_src)
            has_metric = bool(METRIC_PAT.search(body_src))
            # 直接返回假值？
            returns_falsy = False
            for st in ast.walk(node):
                if isinstance(st, ast.Return) and st.value is not None:
                    v = st.value
                    if isinstance(v, ast.Constant) and v.value in (None, False, 0, "", [], {}):
                        returns_falsy = True
            if not has_log and not returns_falsy:
                continue
            if has_metric:
                continue
            # 找所在函数
            fn = None
            for f, name in func_of.items():
                if f.lineno <= node.lineno <= (f.end_lineno or f.lineno):
                    if fn is None or f.lineno > fn.lineno:
                        fn = f
            fname = func_of.get(fn, "?") if fn else "?"
            results.append({
                "file": rel, "line": node.lineno, "func": fname,
                "log": bool(has_log), "falsy": returns_falsy,
                "ops": bool(OPS_HINT.search(fname) or OPS_HINT.search(rel)),
                "snippet": lines[node.lineno - 1].strip()[:90],
            })

# ── 空扫描自检（P0-1 防复发）：扫描了 0 个文件 = 目标不存在 = 假门禁，
#    必须失败而非产出空报告。退出码 2 = "扫描未执行"，1 = "无命中"。
if scanned_files == 0:
    print("[scan-swallowed-failures] FATAL: 未扫描到任何 .py 文件 — 目标目录不存在: %r"
          % REPO, file=sys.stderr)
    sys.exit(2)

print("宽异常处理器（except Exception/BaseException）里「只记日志、无计数」："
      " %d 处（扫描 %d 个文件）\n" % (len(results), scanned_files))

print("=== A. 运营决策路径（优先处理）===")
a = [r for r in results if r["ops"]]
for r in sorted(a, key=lambda x: (x["file"], x["line"])):
    flags = []
    if r["log"]:
        flags.append("记日志")
    if r["falsy"]:
        flags.append("返回假值")
    print("  %-42s:%-5d %-34s %s" % (r["file"], r["line"], r["func"],
                                       "/".join(flags)))
print("  → %d 处" % len(a))

print()
print("=== B. 其它（多为尽力而为的清理，需人工确认）===")
b = [r for r in results if not r["ops"]]
for r in sorted(b, key=lambda x: (x["file"], x["line"])):
    flags = []
    if r["log"]:
        flags.append("记日志")
    if r["falsy"]:
        flags.append("返回假值")
    print("  %-42s:%-5d %-34s %s" % (r["file"], r["line"], r["func"],
                                       "/".join(flags)))
print("  → %d 处" % len(b))
