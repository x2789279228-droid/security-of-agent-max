# -*- coding: utf-8 -*-
"""扫「**活着的**模块里，哪些一条测试都没有」。

整改方案 §十三「全量回归」行的隐含前提是：测试能覆盖到生产路径。
本脚本量的是这个前提**成立到什么程度**。

## 口径

* **活**：被**包外**的生产代码（非 `tests/`）import 过。
  判据按 (被 import 的模块路径, **导入方所在的包**) 逐对判定 ——
  模块被**自己包内**的兄弟模块 import **不算**「活」：
  像 `stabilizer` 这种整体没有外部引用的包，它的内部文件
  其实是**休眠**的，算成「活跃」会让结论虚高。
* **零覆盖**：全仓 `tests/` 里既没有 import 它，也没有任何文件在**代码**里
  引用它的标识符（同样用 AST，不靠文本）。

## 这个扫描器自己踩过的坑（如实记录）

1. v1 只认「import 的模块路径」，认不出 `from pkg import mod` ——
   `mcp_guard/permission_manager.py` 与 `response_engine/policy_store.py`
   都被误报成「零覆盖」（45 → 24）。
2. v1.1 认出了 `from pkg import mod`，但**别名**把原名遮住 ——
   `from mcp_guard import permission_manager as pm` 只记了 `pm`。
3. v2 的第一版把「模块路径在生产 import 集合里」直接当成「活」，
   没考虑**是谁** import 的 → 同包内引用仍然被算成活跃。
   是 v3（按 (模块, 导入方包) 逐对判定）修掉的。

前两次都是**已知答案自检**抓到的，不是事后看出来的。
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, os.pardir, "backend"))
TESTS = os.path.join(BACKEND, "tests")


def py_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ("__pycache__", ".git", "node_modules", "venv")]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def module_name(path, root):
    rel = os.path.relpath(path, root)
    if rel.endswith("__init__.py"):
        # ⚠ 包的 __init__ 就是**包名本身**，不能再切尾巴 ——
        # 那 3 个字符本来是 ".py"，此时已经被换掉了。
        # 切错的后果：rag/__init__.py → ""、asset/__init__.py → "as"。
        return os.path.dirname(rel).replace(os.sep, ".")
    return rel[:-3].replace(os.sep, ".")


def package_of(modname: str) -> str:
    return modname.rsplit(".", 1)[0] if "." in modname else ""


#: HTTP 入口层：这些模块通常由**端点级测试**覆盖，
#: 而测试文件从不 import 路由模块 → 静态判据对它们**结构性失效**。
#: 所以它们**单列**，不混进「零覆盖」结论。
ENTRYPOINT_PACKAGES = ("routers",)


def is_entrypoint(modname: str) -> bool:
    pkg = package_of(modname)
    return pkg in ENTRYPOINT_PACKAGES


#: 解析失败的文件（**必须显式报出来**，不能静默降级）
PARSE_FAILURES: list = []


def collect(path, root):
    """返回 (edges, binds, attrs)；后两者都带「导入方所在包」。"""
    edges, binds, attrs = [], [], []
    imp_pkg = package_of(module_name(path, root))
    try:
        with open(path, "rb") as fh:
            # ⚠ 必须用 `utf-8-sig`：带 BOM 的文件（如 `app.py`）
            # 用 utf-8 解码会留下 U+FEFF → ast.parse 抛 SyntaxError →
            # **整个文件被静默跳过** → 它的 import 全部不可见。
            # 而 `app.py` 恰恰是 `protocol_parser.dissector` 等模块
            # **唯一的包外引用方**。
            tree = ast.parse(fh.read().decode("utf-8-sig"))
    except (SyntaxError, UnicodeDecodeError, OSError) as e:
        PARSE_FAILURES.append((path, f"{type(e).__name__}: {e}"))
        return edges, binds, attrs
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                edges.append((a.name, imp_pkg))
                binds.append((a.asname or a.name.split(".")[0], imp_pkg, a.name))
        elif isinstance(node, ast.ImportFrom):
            src = node.module or ""
            edges.append((src, imp_pkg))
            for a in node.names:
                # 原名和别名**都要记**：
                # `from mcp_guard import permission_manager as pm`
                # 只记 `pm` 会把 `permission_manager` 误判成零覆盖。
                binds.append((a.name, imp_pkg, src))
                binds.append((a.asname or a.name, imp_pkg, src))
        elif isinstance(node, ast.Attribute):
            attrs.append((node.attr, imp_pkg))
    return edges, binds, attrs


def scan(root, skip_tests=False):
    edges, binds, attrs = [], [], []
    files = []
    for p in py_files(root):
        if skip_tests and os.path.abspath(p).startswith(os.path.abspath(TESTS)):
            continue
        files.append(p)
        e, b, a = collect(p, root)
        edges += e
        binds += b
        attrs += a
    return edges, binds, attrs, files


def active_modules():
    all_mods = {}
    for p in py_files(BACKEND):
        all_mods[module_name(p, BACKEND)] = p
    p_edges, p_binds, p_attrs, _ = scan(BACKEND, skip_tests=True)
    t_edges, t_binds, t_attrs, test_files = scan(TESTS)

    def is_active(modname):
        pkg = package_of(modname)
        base = modname.rsplit(".", 1)[-1]
        for mp, ipkg in p_edges:
            if ipkg == pkg:          # 同包内引用 → 不算「活」
                continue
            if mp == modname or mp.startswith(modname + "."):
                return True
        for mp, ipkg in p_edges:
            if ipkg == pkg or mp != pkg:
                continue
            # `from pkg import mod` / `import pkg` + `pkg.mod.xxx`
            if any(bn == base and bpkg != pkg for bn, bpkg, _s in p_binds):
                return True
            if any(an == base and apkg != pkg for an, apkg in p_attrs):
                return True
        return False

    def is_covered(modname):
        base = modname.rsplit(".", 1)[-1]
        if any(mp == modname or mp.startswith(modname + ".") for mp, _p in t_edges):
            return True
        if any(bn == base for bn, _p, _s in t_binds):
            return True
        if any(an == base for an, _p in t_attrs):
            return True
        return False

    active, zero, entry = [], [], []
    for modname, path in sorted(all_mods.items()):
        if modname.startswith("tests") or modname in ("setup", "conftest"):
            continue
        if not is_active(modname):
            continue
        active.append(modname)
        if is_covered(modname):
            continue
        if is_entrypoint(modname):
            entry.append(modname)
        else:
            zero.append(modname)
    return active, zero, all_mods, len(test_files), entry


#: 已知答案自检：(模块, 期望是否被测试覆盖)
SELFCHECK = [
    ("mcp_guard.permission_manager", True),
    ("response_engine.policy_store", True),
    ("encrypted_traffic.session_collector", True),
    ("response_engine.human_approval", True),
    ("core_metrics", True),
    # 活跃且已被测试覆盖的（2026-10-21: ttl_manager 已接线并覆盖）
    ("response_engine.ttl_manager", True),
    # 活跃且零覆盖的（必须是 False）
    ("protocol_parser.tls_parser", False),
    ("phishing_guard.drill_manager", False),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    args = ap.parse_args()

    active, zero, all_mods, n_tests, entry = active_modules()

    # 空扫描自检（P0-1 防复发，与 scan-swallowed-failures 同规）：
    # 0 个模块 = 目标目录不存在 = 假门禁，必须失败而非产出"零结果"报告。
    if not all_mods:
        print("[scan-active-zero-coverage] FATAL: 未扫描到任何模块 — 目标目录不存在: %r"
              % BACKEND, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({
            "total_modules": len(all_mods),
            "test_files": n_tests,
            "active_modules": len(active),
            "zero_coverage": zero,
            "zero_coverage_entrypoints": entry,
            "parse_failures": len(PARSE_FAILURES),
        }, ensure_ascii=False, indent=2))
        return 0

    print("backend 模块总数        :", len(all_mods))
    print("测试文件数              :", n_tests)
    print("解析失败的文件数        :", len(PARSE_FAILURES),
          "（**必须为 0** —— 解析失败的文件会被静默跳过，"
          "它的 import 全部不可见，结论会虚高）")
    for p, why in PARSE_FAILURES[:5]:
        print("     !", os.path.relpath(p, BACKEND), why)
    print("被**包外**生产代码引用的模块数:", len(active))
    print("其中**零测试覆盖**的    :", len(zero),
          "（非入口层的叶子模块）")
    print("入口层同样没被 import 的:", len(entry),
          "（HTTP 入口，静态判据结构性失效 —— 单列，不据此下结论）")
    print()
    total = 0
    for modname in zero:
        path = all_mods[modname]
        size = os.path.getsize(path)
        total += size
        print("   %-52s %6d 字节" % (os.path.relpath(path, BACKEND), size))
    print()
    print("这些模块合计 %d 字节（%.0f KB）" % (total, total / 1024.0))
    if entry:
        print()
        print("入口层（单列，不据此下结论）:")
        for modname in entry:
            print("   %-52s %6d 字节" % (
                os.path.relpath(all_mods[modname], BACKEND),
                os.path.getsize(all_mods[modname])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
