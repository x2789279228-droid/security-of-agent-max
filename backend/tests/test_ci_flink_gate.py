"""守卫：Flink 验证在 CI 里必须**真的执行**，而不是静默跳过。

## 这批测试为什么存在

本轮给 Flink 聚合窗口加了进程外真执行验证（见
`test_sigma_aggregation_action_chain.py` 的 4c 节）。但那批测试的跳过
条件是「找不到 Maven / 本地仓库没有 Flink 依赖就 skip」。

而 CI 的 `backend-test` job **没有装 JDK/Maven**，`~/.m2` 是空的 ——
于是这 17 条断言加上 `test_flink_jobs_compile`，在 CI 上会**全部静默跳过**，
而 pytest 的退出码在「全部跳过」和「全部通过」两种情况下**都是 0**。

也就是说：一个只在本地跑过一次的验证，在 CI 上是个恒绿的门禁。
这与仓库里 `mcp-arg-injection`（`|| echo` 吞退出码）和 `security-scan`
（`continue-on-error: true`）当初踩的是同一个坑。

所以这里不测业务逻辑，只测两件事：

1. CI 里确实存在一个**带真实工具链**、专门跑 Flink 验证的 job；
2. 该 job 在跑完 pytest 之后**回头核对 JUnit XML**，
   并且这个核对脚本本身的行为是对的。

> 第 2 条很重要：一个只写了「跑 pytest」的 CI 步骤，
> 和一个「跑 pytest 并断言没跳过」的步骤，在界面上看起来一模一样。
"""
from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GUARDED_TEST = "tests/test_sigma_aggregation_action_chain.py"
GUARD_SCRIPT = REPO_ROOT / "tools" / "assert-junit-no-skip.py"


# ══════════════════════════════════════════════════════════════
# 1. CI 配置本身
# ══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def ci() -> dict:
    assert CI_YML.is_file(), f"CI 工作流不存在: {CI_YML}"
    return yaml.safe_load(CI_YML.read_text(encoding="utf-8"))


def _job_running_guarded_tests(ci: dict) -> tuple[str, dict]:
    """找出真正跑那条聚合测试文件的 job。

    按**内容**找而不是按名字找 —— job 改名不该让守卫误报，
    但「没人跑这条测试」必须让它变红。
    """
    for name, job in (ci.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            run = step.get("run")
            if run and GUARDED_TEST in run:
                return name, job
    pytest.fail(
        f"CI 里没有任何 job 运行 {GUARDED_TEST} —— "
        "这条测试链在 CI 上从未被执行")


def test_ci_has_a_job_for_flink_verification(ci):
    name, job = _job_running_guarded_tests(ci)
    assert job.get("steps"), f"{name} 没有 steps"
    # 必须能装出工具链，否则那些测试进去就 skip
    uses = " ".join(s.get("uses", "") for s in job["steps"])
    assert "actions/setup-java" in uses, (
        f"{name} 跑 Flink 验证却没装 JDK —— "
        "`_jdk_bin()` 返回 None，测试会全部静默跳过")


def test_ci_flink_job_warms_the_maven_cache(ci):
    """必须有一步联网把 Flink 依赖灌进 ~/.m2。

    测试里的 Maven 调用是 ``-o`` 离线模式。冷缓存下离线编译必然失败，
    而失败分支的兜底是 ``pytest.skip``（本机仓库空时）——
    于是「没装依赖」和「验证通过」在 CI 界面上无法区分。
    """
    name, job = _job_running_guarded_tests(ci)
    runs = [s.get("run") or "" for s in job["steps"]]
    warmups = [r for r in runs
               if "mvn" in r and "flink-jobs" in r and "pytest" not in r]
    assert warmups, (
        f"{name} 没有预热 Maven 缓存（未见对 flink-jobs 执行 mvn）—— "
        "离线模式会解析不到 Flink 依赖，验证会被静默跳过")
    # dependency-plugin 必须一并预取：窗口 harness 要导出依赖 classpath，
    # 该插件不在默认插件集里，冷缓存下离线解析不到。
    assert any("dependency-plugin" in r for r in warmups), (
        f"{name} 未预取 maven-dependency-plugin —— "
        "导出 classpath 的那一步在冷缓存下会失败")


def test_ci_flink_job_asserts_tests_were_not_skipped(ci):
    """跑完 pytest 必须**回头核对**，不能就这么结束。

    pytest 的退出码在「全部通过」和「全部跳过」两种情况下都是 0。
    少这一步，这个 job 就是另一个恒绿门禁。
    """
    name, job = _job_running_guarded_tests(ci)
    runs = [s.get("run") or "" for s in job["steps"]]
    assert any("--junitxml" in r for r in runs), (
        f"{name} 没有产出 JUnit XML，无法核对是否跳过")
    guard = [r for r in runs if "assert-junit-no-skip" in r]
    assert guard, (
        f"{name} 没有调用核对脚本 —— "
        "pytest「全部跳过」时退出码仍是 0，此步骤会恒绿")
    m = re.search(r"--min-tests\s+(\d+)", guard[0])
    assert m, "核对脚本没给 --min-tests 门槛（删掉测试也能让门禁变绿）"
    assert int(m.group(1)) >= 10, \
        f"--min-tests={m.group(1)} 过低，删到只剩个别用例也不会被发现"


def test_guard_script_exists():
    assert GUARD_SCRIPT.is_file(), f"核对脚本缺失: {GUARD_SCRIPT}"


# ══════════════════════════════════════════════════════════════
# 2. 核对脚本自身的逻辑
# ══════════════════════════════════════════════════════════════
#
# 一个从没被测过的守卫脚本，本身就可能一直是错的 ——
# 那比没有守卫更糟：它会给出「已验证」的假信号。

_XML_HEAD = ('<?xml version="1.0" encoding="utf-8"?>\n'
             '<testsuites><testsuite name="pytest" tests="{n}">')


def _xml(n_pass: int, n_skip: int = 0) -> str:
    body = "".join(f'<testcase classname="t" name="pass{i}"/>'
                   for i in range(n_pass))
    body += "".join(f'<testcase classname="t" name="skip{i}">'
                    f'<skipped type="pytest.skip" message="no mvn"/>'
                    f'</testcase>' for i in range(n_skip))
    return _XML_HEAD.format(n=n_pass + n_skip) + body + "</testsuite></testsuites>"


@pytest.fixture(scope="module")
def guard():
    spec = importlib.util.spec_from_file_location("assert_junit_no_skip",
                                                  GUARD_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_guard_flags_a_fully_skipped_run(guard, tmp_path):
    """全部跳过 → 必须失败。**这正是当前 CI 缺工具链时的状态。**"""
    f = tmp_path / "r.xml"
    f.write_text(_xml(0, 5), encoding="utf-8")
    assert guard.main([str(f), "--min-tests", "1"]) == 1, \
        "全部跳过却判为通过 —— 这个守卫等于没有"


def test_guard_flags_a_vanished_suite(guard, tmp_path):
    """用例被删到只剩几条 → 必须失败（否则门禁可被掏空而无人察觉）。"""
    f = tmp_path / "r.xml"
    f.write_text(_xml(3, 0), encoding="utf-8")
    assert guard.main([str(f), "--min-tests", "60"]) == 1


def test_guard_passes_a_real_run(guard, tmp_path):
    """真的跑了且一条没跳过 → 通过。"""
    f = tmp_path / "r.xml"
    f.write_text(_xml(76, 0), encoding="utf-8")
    assert guard.main([str(f), "--min-tests", "60"]) == 0


def test_guard_reads_both_junit_layouts(guard, tmp_path):
    """`<testsuite>` 与 `<testsuites>` 两种根布局都要能读。

    pytest 的 `--junitxml` 默认写 `<testsuites>`，但某些插件/版本写
    `<testsuite>`。只认一种的话，换个 pytest 版本守卫就静默失效 ——
    而静默失效的守卫正是这个文件要防的东西。
    """
    body = '<testcase classname="t" name="a"/><testcase classname="t" name="b"><skipped/></testcase>'
    f = tmp_path / "r.xml"
    f.write_text('<?xml version="1.0"?><testsuite name="x" tests="2">'
                 + body + "</testsuite>", encoding="utf-8")
    total, skips, xfails = guard.analyze(str(f))
    assert (total, len(skips), xfails) == (2, 1, 0)
    assert skips and skips[0].endswith("::b"), skips


# ── xfail 与 skip 必须分开（本轮修掉的真缺陷）─────────────────
#
# pytest 的 JUnit XML 把两者都写成 `<skipped>`，只靠 `type` 区分。
# 第一版用 `.//skipped` 一视同仁，于是**已登记的已知缺口被当成
# 「这条门禁什么都没验」**。它在 flink-verification 上一直没出事，
# 只是因为那个文件恰好零 xfail —— 不是因为判据对。

def _xml_with_xfails(n_pass: int, n_xfail: int) -> str:
    body = "".join(f'<testcase classname="t" name="pass{i}"/>'
                   for i in range(n_pass))
    body += "".join(
        f'<testcase classname="t" name="xf{i}">'
        f'<skipped type="pytest.xfail" message="已知缺口"/>'
        f'</testcase>' for i in range(n_xfail))
    n = n_pass + n_xfail
    return _XML_HEAD.format(n=n) + body + "</testsuite></testsuites>"


def test_guard_does_not_count_xfail_as_a_skip(guard, tmp_path):
    """全是 xfail 的运行**必须判为通过**。

    主套件现有 53 条 strict xfail（全是我们主动登记的已知缺口）。
    把它们当成 skip 会让门禁恒红，而那条红与「工具链缺失导致没在验」
    毫无关系 —— 门禁一旦恒红，就等于没有门禁。
    """
    f = tmp_path / "r.xml"
    f.write_text(_xml_with_xfails(200, 53), encoding="utf-8")
    assert guard.main([str(f), "--min-tests", "200"]) == 0, \
        "xfail 被当成 skip —— 接到主套件上会永久变红"


def test_guard_still_flags_real_skips_alongside_xfails(guard, tmp_path):
    """有 xfail 也有真 skip 时，真 skip 仍必须报出来。"""
    body = "".join(
        f'<testcase classname="t" name="xf{i}">'
        f'<skipped type="pytest.xfail"/></testcase>' for i in range(3))
    body += '<testcase classname="t" name="s0"><skipped type="pytest.skip"/></testcase>'
    f = tmp_path / "r.xml"
    f.write_text(_XML_HEAD.format(n=4) + body + "</testsuite></testsuites>",
                 encoding="utf-8")
    assert guard.main([str(f), "--min-tests", "1"]) == 1


def test_guard_allow_skip_file_only_exempts_that_file(guard, tmp_path):
    """`--allow-skip-file` 不能变成一把万能钥匙。

    用主套件的真实形态验：18 条 Maven 跳过放行，
    但任何**别的文件**新出现的跳过仍然必须报出来。
    """
    body = "".join(
        f'<testcase classname="tests.test_sigma_aggregation_action_chain" '
        f'name="flink{i}"><skipped type="pytest.skip"/></testcase>'
        for i in range(18))
    body += "".join(
        f'<testcase classname="tests.test_detection_metrics" name="d{i}"/>'
        for i in range(50))
    f = tmp_path / "r.xml"
    f.write_text(_XML_HEAD.format(n=68) + body + "</testsuite></testsuites>",
                 encoding="utf-8")
    assert guard.main([str(f), "--min-tests", "60",
                       "--allow-skip-file",
                       "test_sigma_aggregation_action_chain"]) == 0

    # 同一个文件里换成别的文件跳过 → 必须红
    body2 = body.replace("tests.test_sigma_aggregation_action_chain",
                         "tests.test_something_else")
    g = tmp_path / "g.xml"
    g.write_text(_XML_HEAD.format(n=68) + body2 + "</testsuite></testsuites>",
                 encoding="utf-8")
    assert guard.main([str(g), "--min-tests", "60",
                       "--allow-skip-file",
                       "test_sigma_aggregation_action_chain"]) == 1


def test_guard_max_xfail_pins_the_known_gap_surface(guard, tmp_path):
    """xfail 数量必须能被钉住 —— 它是「已知缺口」账本，不是自由字段。"""
    f = tmp_path / "r.xml"
    f.write_text(_xml_with_xfails(200, 54), encoding="utf-8")
    assert guard.main([str(f), "--min-tests", "200", "--max-xfail", "53"]) == 1
    g = tmp_path / "g.xml"
    g.write_text(_xml_with_xfails(200, 53), encoding="utf-8")
    assert guard.main([str(g), "--min-tests", "200", "--max-xfail", "53"]) == 0


def test_guard_reports_a_broken_xml_instead_of_passing(guard, tmp_path):
    """XML 损坏/文件不存在 → 必须失败，不能当成「0 条、0 跳过」。"""
    f = tmp_path / "missing.xml"
    with pytest.raises(SystemExit):
        guard.analyze(str(f))
    g = tmp_path / "broken.xml"
    g.write_text("<not-xml", encoding="utf-8")
    with pytest.raises(SystemExit):
        guard.analyze(str(g))
