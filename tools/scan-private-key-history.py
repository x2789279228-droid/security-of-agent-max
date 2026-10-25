#!/usr/bin/env python3
"""Git 历史完整 PEM 私钥块扫描 (leak-gate 第三步的实现)。

为什么是"块"而不是"行":
    naive 正则 `BEGIN (OPENSSH|RSA|...) PRIVATE KEY` 会把审计报告里
    对泄露事实的【文字引用】也当成密钥 (docs/AUDIT-2026-10-03 的表格),
    而 git 历史无法不重写就清除旧文案 —— 该误报一旦产生就永远红。
    真私钥必然是完整 PEM 块: BEGIN 行 + base64 密文体 + END 行;
    文档引用只有孤立一行。因此以"40 行内出现配套 END 行"判定为真块。

判定的不变量: git 历史中不得存在任何完整 PEM 私钥块。
被交付 zip 泄露过、仅存在于工作区/归档的密钥不在此扫描范围
(那由 tools/release.sh 与工作区文件名扫描负责)。

用法:
    python tools/scan-private-key-history.py [--self-test]

退出码: 0=干净  1=检出完整私钥块  2=自检失败(分类器自身损坏)
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

BEGIN_RE = re.compile(
    r"BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY"
)
END_RE = re.compile(
    r"END (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY"
)
COMMIT_RE = re.compile(r"^commit ([0-9a-f]{40})")

# BEGIN 行之后在此窗口内找到 END 行才算完整块 (PEM 最大块远小于此)
BLOCK_WINDOW = 40

# ── 已知答案自检样本 ──
# 样本的 PEM 结构标记必须【运行时拼装】: 本文件自身会进入 git 历史,
# 而历史扫描扫的就是这些字面量 —— 2026-10-25 实测, 以字面量入库的自检
# 样本让检测器"抓到了自己"(完整块命中自己的提交)。拼装后源码中任意
# 单行都不含完整块结构, 自检语义不变。
def _pem_mark(kind: str, algo: str) -> str:
    tail = " ".join(["PRIVATE", "KEY"])          # 源码中不得出现完整字面量
    return f"-----{kind} {algo} {tail}-----"


_SAMPLE_BODY = (
    "dGVzdC1ub3QtYS1yZWFsLWtleSB0ZXN0LW5vdC1hLXJlYWwta2V5IHRlc3Qtbm90LWE\n"
    "cmVhbC1rZXkgdGVzdC1ub3QtYS1yZWFsLWtleSB0ZXN0LW5vdC1hLXJlYWwta2V5IA=="
)
# 完整块样本: 语法上合法但内容为占位符的假钥匙 (仅用于验证分类器能识别块结构)
SAMPLE_FULL_BLOCK = "\n".join([
    _pem_mark("BEGIN", "OPENSSH"),
    _SAMPLE_BODY,
    _pem_mark("END", "OPENSSH"),
])
# 文档引用样本: 审计报告式的孤立格式头提及, 不应命中
SAMPLE_DOC_MENTION = (
    "| `config/ssh/firewall_key` (411 B) | **OpenSSH 私钥**"
    "（BEGIN OPENSSH PRIVATE KEY 格式头, 内容已略去） |"
)
# 跨行扩散样本: BEGIN 之后 40 行内无 END → 不应命中 (截断/损坏块按存疑不算数,
# 由文件名与发布包扫描兜底)
SAMPLE_TRUNCATED = _pem_mark("BEGIN", "RSA") + "\n" + "line\n" * 60


def _scan_lines(lines: list[str]) -> list[tuple[int, str]]:
    """返回命中的 (行号, 触发行)。与 git 无关, 供扫描与自检共用。"""
    hits: list[tuple[int, str]] = []
    begin_at: int | None = None
    for i, raw in enumerate(lines):
        if BEGIN_RE.search(raw):
            begin_at = i
        elif END_RE.search(raw):
            if begin_at is not None and i - begin_at <= BLOCK_WINDOW:
                hits.append((begin_at, lines[begin_at].rstrip()))
            begin_at = None
    return hits


def scan_history() -> list[str]:
    """扫 git 全量历史, 返回人类可读的命中描述列表。"""
    proc = subprocess.run(
        ["git", "log", "--all", "-p"],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        print(f"[FAIL] git log 执行失败: {proc.stderr[:300]}", file=sys.stderr)
        raise SystemExit(2)

    lines = proc.stdout.splitlines()
    hits = _scan_lines(lines)
    if not hits:
        return []

    # 把每个命中映射回所属 commit, 报告才可执行
    commit_of_line: list[str] = []
    current = "(unknown)"
    for raw in lines:
        m = COMMIT_RE.match(raw)
        if m:
            current = m.group(1)[:12]
        commit_of_line.append(current)

    out = []
    for lineno, line in hits:
        out.append(f"commit {commit_of_line[lineno]}: {line.strip()[:100]}")
    return out


def self_test() -> None:
    """已知答案自检: 检出能力与不误报能力都坏了就退出 2 (崩了 ≠ 查过了)。"""
    full = SAMPLE_FULL_BLOCK.splitlines()
    assert _scan_lines(full), "自检失败: 分类器识别不了完整 PEM 块"
    assert not _scan_lines(SAMPLE_DOC_MENTION.splitlines()), (
        "自检失败: 文档孤立格式头引用被误判为私钥块"
    )
    assert not _scan_lines(SAMPLE_TRUNCATED.splitlines()), (
        "自检失败: 无 END 的截断块不应命中"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="只跑已知答案自检 (CI 在正式扫描前先跑, 防分类器静默损坏)",
    )
    args = ap.parse_args()

    self_test()
    if args.self_test:
        print("[leak-gate] 私钥块分类器自检通过")
        return 0

    hits = scan_history()
    if hits:
        print(
            f"::error::Git 历史中检出 {len(hits)} 处完整 PEM 私钥块"
            " —— 视为已泄露，请轮换并清理历史",
            file=sys.stderr,
        )
        for h in hits:
            print(f"    {h}", file=sys.stderr)
        return 1
    print("[leak-gate] Git 历史中未检出完整 PEM 私钥块")
    return 0


if __name__ == "__main__":
    sys.exit(main())
