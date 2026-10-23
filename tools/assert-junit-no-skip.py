#!/usr/bin/env python3
"""断言某次 pytest 运行**真的执行了**测试，而不是把它们跳过了。

## 为什么需要这个脚本

`pytest` 的退出码**不区分「通过」和「全部跳过」** —— 两种情况都是 0。
一个只跑 `pytest` 的 CI 步骤，在工具链缺失时是绿的：

    test_flink_jobs_compile  →  skipif(MVN is None)
    窗口层真执行 17 条      →  fixture 里 pytest.skip(...)

于是一条「门禁」可能连续几个月什么都没验，却一直显示通过。
这正是仓库里 `mcp-arg-injection` / `security-scan` 两个 job
当初踩过的同一个坑（它们恒绿且不可能失败）。

所以 CI 步骤在跑完 pytest 之后，必须回来核对 JUnit XML：

- 有 `<skipped>` → 失败
- 执行条数低于门槛 → 失败（否则删掉测试也能让门禁变绿）

## 用法

    python tools/assert-junit-no-skip.py report.xml --min-tests 60

## 已知豁免：`--allow-skip-file`

主测试套件（CI 的 `backend-test` job）不装 Maven，因此
`test_sigma_aggregation_action_chain.py` 的 18 条窗口层真执行断言
必然跳过。那 18 条由**另一个** job（`flink-verification`）装上 Maven
后用「0 跳过 + ≥60 条」严格校验，两边合起来是完整的。

于是在主套件这一侧，需要的不是「一条都不许跳」，而是
**「除了这个已知文件，不许有任何用例跳过」**：

    python tools/assert-junit-no-skip.py full.xml \
        --min-tests 2000 --allow-skip-file test_sigma_aggregation_action_chain

这样任何**新**文件开始静默跳过时，门禁仍然会红。
没有这个参数时，脚本会把已知的 18 条一起判红，只能靠注释豁免 ——
而注释豁免不会被机器执行，正是 §十一 说的那类「文档承诺」。

## 退出码

0 = 通过；1 = 断言失败（消息打印到 stdout，便于 CI 收集）。
"""
from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET


def analyze(xml_path: str) -> tuple[int, list[str], int]:
    """返回 (用例总数, 真跳过清单, xfail 数)。

    ## 这里修掉的一个真缺陷

    pytest 的 JUnit XML 里，**xfail 和 skip 都写成 `<skipped>` 元素**，
    只靠 `type` 属性区分：

        <skipped type="pytest.xfail" message="已知缺口：..."/>   ← 已知缺口
        <skipped type="pytest.skip"  message="未安装 Maven..."/> ← 没在验

    本工具第一版用 `root.findall(".//skipped")` 一视同仁，
    于是**已登记的已知缺口被当成「这条门禁什么都没验」**。
    实测：主套件 71 条 `<skipped>` = 18 条真 skip + 53 条 xfail。

    它在 `flink-verification` job 上一直没出事，只是因为那个文件
    恰好一个 xfail 都没有 —— **不是因为判据对**。
    把这个工具接到主套件上，它会因 53 条 xfail 永久变红，
    而那条红与「工具链缺失导致静默不验」毫无关系。

    「已知的、会失败的、被人盯着的东西」和「因为环境缺失所以没在验」
    必须分开 —— 否则门禁要么恒红，要么恒绿，永远不可能在验任何东西。
    """
    try:
        root = ET.parse(xml_path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise SystemExit(f"无法解析 JUnit XML: {xml_path}: {exc}")

    # JUnit XML 有 <testsuites> 根和 <testsuite> 根两种布局，都要能读。
    cases = root.findall(".//testcase")
    skips: list[str] = []
    xfails = 0
    for c in cases:
        node = c.find("skipped")
        if node is None:
            continue
        kind = node.get("type") or ""
        if kind == "pytest.xfail":
            xfails += 1
        else:
            skips.append((c.get("classname") or "") + "::" + (c.get("name") or ""))
    return len(cases), skips, xfails


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("xml", help="pytest --junitxml 产出的文件")
    ap.add_argument(
        "--min-tests", type=int, default=1,
        help="至少要真实执行这么多条用例，低于此值视为门禁被掏空")
    ap.add_argument(
        "--allow-skip-file", action="append", default=[],
        help="允许跳过的用例所属文件（子串匹配 classname），可重复。"
             "用于「这一份文件由另一个 job 用完整工具链单独校验」。")
    ap.add_argument(
        "--max-xfail", type=int, default=-1,
        help="允许的 xfail 上限；-1 表示不设限。xfail 是已登记的已知缺口，"
             "数量突然增长说明有人在用 xfail 掩盖新问题。")
    args = ap.parse_args(argv)

    total, skips, xfails = analyze(args.xml)

    offenders = [n for n in skips
                 if not any(f in n for f in args.allow_skip_file)]
    allowed = len(skips) - len(offenders)

    if offenders:
        head = "\n  ".join(offenders[:15])
        more = f"\n  … 另有 {len(offenders) - 15} 条" if len(offenders) > 15 else ""
        print(f"::error::有 {len(offenders)} 条用例被跳过（共 {len(skips)} 条跳过，"
              f"{xfails} 条 xfail 不计入）—— 这条门禁没有在验任何东西："
              f"\n  {head}{more}")
        return 1

    if args.max_xfail >= 0 and xfails > args.max_xfail:
        print(f"::error::xfail 数量 {xfails} 超过上限 {args.max_xfail} —— "
              "新增的已知缺口必须先登记，不能靠 xfail 悄悄带过")
        return 1

    if total < args.min_tests:
        print(f"::error::只执行了 {total} 条用例（门槛 {args.min_tests}），"
              "疑似测试被删除或未被收集")
        return 1

    extra = f"，{allowed} 条按 --allow-skip-file 豁免（由别的 job 校验）" \
        if allowed else ""
    print(f"[assert-junit-no-skip] {total} 条用例真实执行，"
          f"{len(skips)} 条跳过{extra}，{xfails} 条已知缺口(xfail)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
