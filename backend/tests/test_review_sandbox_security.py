"""提交 B（P0-5 / P0-6）整改回归测试：沙箱安全入口与任务状态机。

整改方案 §五 / §十。

**修复前**（2026-10-18 审查实测）：
  - `submit_url` 对 URL 零校验，`file:///etc/passwd`、
    `http://169.254.169.254/latest/meta-data/`、`gopher://127.0.0.1:6379/_INFO`、
    `not a url`、`http://10.0.0.1/admin` 全部原样转发并返回 task_id；
  - `task_id="../../v1/admin"` 会把带 Bearer 头的请求打到 CAPE 其他端点；
  - `{"task_id": null}` → `str(None)` → 字面量字符串 `"None"` 通过真值检查，
    落库成永久悬空任务；
  - `analyze(None)` 与真实干净样本逐字段相同（`verdict="clean", score=0.0`）；
  - 连接被拒 / HTTP 404 / 真实超时三者返回**完全相同的** `None`。

**修复后**：URL / task_id 显式校验，状态语义分离，故障不再是 clean。
"""
import asyncio
import socket

import pytest

os_env = {"SHARED_MEMORY_SKIP_DOTENV": "1"}

import zeroday_detect.sandbox_status as sandbox_status  # noqa: E402
from zeroday_detect.sandbox_status import (  # noqa: E402
    ST_COMPLETED,
    ST_FAILED,
    ST_NO_RESULT,
    ST_PENDING,
    ST_RUNNING,
    ST_TIMEOUT,
    ST_UNAVAILABLE,
    ST_UNKNOWN,
    TaskIdRejected,
    UrlRejected,
    SandboxOutcome,
    map_cape_status,
    validate_submittable_url,
    validate_task_id,
)


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ══════════════════════════════════════════════════════════════
# URL 安全校验
# ══════════════════════════════════════════════════════════════

class TestUrlValidation:
    @pytest.mark.parametrize("bad,reason", [
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("gopher://127.0.0.1:6379/_INFO", "scheme_not_allowed"),
        ("ftp://example.com/x", "scheme_not_allowed"),
        ("not a url", "scheme_not_allowed"),
        ("", "url_empty"),
        ("http://127.0.0.1/admin", "loopback_not_allowed"),
        ("http://127.0.0.1:8000/x", "loopback_not_allowed"),
        ("http://10.0.0.1/admin", "private_not_allowed"),
        ("http://192.168.1.1/", "private_not_allowed"),
        ("http://172.16.0.5/", "private_not_allowed"),
        ("http://169.254.169.254/latest/meta-data/", "cloud_metadata_blocked"),
        ("http://[::1]/x", "loopback_not_allowed"),
        ("http://metadata.google.internal/", "cloud_metadata_blocked"),
        ("http://user:pw@example.com/", "userinfo_not_allowed"),
        ("http://example.com/\npath", "url_control_chars"),
        ("http://" + "a" * 3000 + ".com/", "url_too_long"),
    ])
    def test_q12_1_rejected_urls(self, bad, reason):
        with pytest.raises(UrlRejected) as ei:
            validate_submittable_url(bad)
        assert ei.value.reason == reason, (bad, ei.value.reason)

    def test_q12_2_public_http_https_allowed(self):
        """公共 http/https 放行。

        判定必须**不依赖实时 DNS**：`resolve_dns` 默认 True，函数会真的做一次
        `socket.getaddrinfo`；本机/离线 CI 上解析失败时它按
        「查不到就不放行」拒绝（`dns_resolve_failed`）——
        那时红的是**环境**，不是被测代码（2026-10-19 全量回归时确实红过一次，
        单独跑又通过）。

        所以「公网 http/https 放行」用 `resolve_dns=False` 断言；
        DNS 相关语义由下面三条**打桩**的用例单独覆盖。
        """
        assert validate_submittable_url(
            "http://example.com/x", resolve_dns=False) == "http://example.com/x"
        assert validate_submittable_url(
            "https://example.com/x", resolve_dns=False) == "https://example.com/x"

    def test_q12_2b_dns_resolved_public_ip_is_allowed(self, monkeypatch):
        """DNS 解析到**公网** IP → 放行（打桩，不依赖真实 DNS）。"""
        monkeypatch.setattr(
            sandbox_status.socket, "getaddrinfo",
            lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                              ("93.184.216.34", 0))])
        assert validate_submittable_url("http://example.com/x") == \
            "http://example.com/x"

    def test_q12_2c_dns_resolved_private_ip_is_rejected(self, monkeypatch):
        """DNS 解析到**私网** IP → 拒绝（整改方案 §五.2「防 DNS 变更绕过」）。

        这一条此前**完全没有测试覆盖** —— 而它正是「域名解析后的 IP 重新校验」
        这条安全性质的落点。打桩，不依赖真实 DNS。
        """
        monkeypatch.setattr(
            sandbox_status.socket, "getaddrinfo",
            lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                              ("10.0.0.1", 0))])
        with pytest.raises(UrlRejected) as ei:
            validate_submittable_url("http://example.com/x")
        assert ei.value.reason == "private_not_allowed", ei.value.reason

    def test_q12_2d_dns_failure_fails_closed(self, monkeypatch):
        """DNS 解析失败 → **拒绝**（fail closed）。

        「查不到」不等于「安全」—— 解析失败时必须拒绝，而不是放行。
        """
        def _boom(*a, **k):
            raise socket.gaierror("simulated DNS failure")

        monkeypatch.setattr(sandbox_status.socket, "getaddrinfo", _boom)
        with pytest.raises(UrlRejected) as ei:
            validate_submittable_url("http://example.com/x")
        assert ei.value.reason == "dns_resolve_failed", ei.value.reason

    def test_q12_3_internal_url_requires_explicit_opt_in(self):
        """默认拒绝内网；确有需求时必须显式开启（隔离环境 + 授权）。"""
        with pytest.raises(UrlRejected):
            validate_submittable_url("http://10.0.0.1/admin")
        # 显式授权后放行（整改方案 §五.2 的例外机制）
        assert validate_submittable_url(
            "http://10.0.0.1/admin", allow_private=True) == "http://10.0.0.1/admin"

    def test_q12_4_loopback_still_blocked_even_with_opt_in(self):
        """allow_private 只放行私有段，不放行 loopback / 元数据。"""
        for bad, reason in (("http://127.0.0.1/x", "loopback_not_allowed"),
                            ("http://[::1]/x", "loopback_not_allowed"),
                            ("http://169.254.169.254/", "cloud_metadata_blocked"),
                            ("http://metadata.google.internal/",
                             "cloud_metadata_blocked")):
            with pytest.raises(UrlRejected) as ei:
                validate_submittable_url(bad, allow_private=True)
            assert ei.value.reason == reason, (bad, ei.value.reason)
        # 私有段在显式授权后确实放行
        assert validate_submittable_url(
            "http://10.0.0.1/admin", allow_private=True)


# ══════════════════════════════════════════════════════════════
# task_id 校验（路径注入）
# ══════════════════════════════════════════════════════════════

class TestTaskIdValidation:
    @pytest.mark.parametrize("bad", [
        "../../v1/admin",
        "..%2f..%2fadmin",
        "abc?admin=1",
        "x#frag",
        "a/b",
        "a b",
        "task\nid",
        "",
        "a" * 200,
        "../../",
    ])
    def test_q12_5_rejected_task_ids(self, bad):
        with pytest.raises(TaskIdRejected):
            validate_task_id(bad)

    @pytest.mark.parametrize("good", ["task-1", "abc123", "A_b-9", "x"])
    def test_q12_6_accepted_task_ids(self, good):
        assert validate_task_id(good) == good


# ══════════════════════════════════════════════════════════════
# 任务状态映射（不再用 None 表达四种语义）
# ══════════════════════════════════════════════════════════════

class TestSandboxStatusMachine:
    @pytest.mark.parametrize("raw,expected", [
        ("pending", ST_PENDING),
        ("running", ST_RUNNING),
        ("processing", ST_RUNNING),
        ("starting", ST_RUNNING),
        ("completed", ST_COMPLETED),
        ("reported", ST_COMPLETED),
        ("recovered", ST_COMPLETED),
        ("failed_analysis", ST_FAILED),
        ("failed_processing", ST_FAILED),
        ("", ST_UNKNOWN),
        (None, ST_UNKNOWN),
        ("garbage", ST_UNKNOWN),
    ])
    def test_q12_7_cape_status_mapping(self, raw, expected):
        assert map_cape_status(raw) == expected

    def test_q12_8_verdict_only_capable_on_completed(self):
        assert SandboxOutcome(status=ST_COMPLETED).verdict_capable is True
        for st in (ST_PENDING, ST_NO_RESULT, ST_UNAVAILABLE, ST_TIMEOUT,
                   ST_FAILED, ST_UNKNOWN):
            assert SandboxOutcome(status=st).verdict_capable is False, st

    def test_q12_9_terminal_vs_recoverable(self):
        for st in (ST_COMPLETED, ST_NO_RESULT, ST_FAILED, ST_UNAVAILABLE,
                   ST_TIMEOUT):
            assert SandboxOutcome(status=st).terminal is True, st
        for st in (ST_PENDING,):
            assert SandboxOutcome(status=st).terminal is False, st

    def test_q12_10_unknown_status_rejected(self):
        with pytest.raises(ValueError):
            SandboxOutcome(status="clean")


# ══════════════════════════════════════════════════════════════
# 连接器行为（不依赖真实 CAPE）
# ══════════════════════════════════════════════════════════════

def _mk_connector(**over):
    from config import settings
    from zeroday_detect.sandbox_connector import SandboxConnector

    settings.sandbox_enabled = True
    settings.sandbox_api_url = over.get("api_url", "http://127.0.0.1:1")  # 不可达
    settings.sandbox_api_key = ""
    settings.sandbox_timeout = 5
    settings.sandbox_auto_submit = over.get("auto_submit", True)
    settings.sandbox_auto_threshold = 0.8
    settings.sandbox_type = "cape"
    if "allow_internal_url" in over:
        settings.sandbox_allow_internal_url = over["allow_internal_url"]
    return SandboxConnector()


class TestConnectorSafety:
    def test_q12_11_submit_url_rejects_unsafe_before_any_http(self):
        """非法 URL 必须在发出 HTTP 之前就被拒（原实测：全部原样转发）。"""
        conn = _mk_connector()
        for bad in ("file:///etc/passwd",
                    "http://169.254.169.254/latest/meta-data/",
                    "gopher://127.0.0.1:6379/_INFO",
                    "http://10.0.0.1/admin"):
            outcome = run(conn.submit_url_outcome(bad))
            assert outcome.status == ST_FAILED, (bad, outcome.status)
            assert outcome.error_code.startswith("url_rejected:"), outcome.error_code
            assert outcome.task_id == "", "非法 URL 竟然拿到了 task_id"

    def test_q12_12_poll_rejects_path_injection_task_id(self):
        conn = _mk_connector()
        for bad in ("../../v1/admin", "abc?admin=1", "x#frag", "a/b"):
            outcome = run(conn.poll_outcome(bad))
            assert outcome.status == ST_FAILED, (bad, outcome.status)
            assert outcome.error_code.startswith("task_id_rejected:"), \
                outcome.error_code

    def test_q12_13_report_rejects_path_injection_task_id(self):
        conn = _mk_connector()
        outcome = run(conn.fetch_report_outcome("../../v1/admin"))
        assert outcome.status == ST_FAILED
        assert outcome.error_code.startswith("task_id_rejected:")

    def test_q12_14_empty_sample_is_failed_not_silently_none(self):
        conn = _mk_connector()
        outcome = run(conn.submit_file_outcome(b"", filename="x.bin"))
        assert outcome.status == ST_FAILED
        assert outcome.error_code == "empty_sample"

    def test_q12_15_zero_poll_interval_cannot_hang_forever(self):
        """修复前 `poll_interval=0` → `elapsed += 0` → 永不退出。"""
        conn = _mk_connector()
        outcome = run(conn.wait_outcome("task-1", poll_interval=0))
        assert outcome.status == ST_FAILED
        assert outcome.error_code == "invalid_poll_interval"

    def test_q12_16_auto_submit_without_artifact_is_logged_and_typed(self):
        """修复前这里返回裸 None 且完全无日志。"""
        conn = _mk_connector(auto_submit=True)
        outcome = run(conn.auto_submit_outcome({"severity": "critical"}))
        assert outcome.status == ST_FAILED
        assert outcome.error_code == "no_submittable_artifact"

    def test_q12_17_auto_submit_below_threshold_is_explicit(self):
        conn = _mk_connector(auto_submit=True)
        outcome = run(conn.auto_submit_outcome(
            {"confidence": 0.1, "severity": "low", "url": "http://example.com/a"}))
        assert outcome.status == ST_FAILED
        assert outcome.error_code == "below_threshold"

    def test_q12_18_sample_hash_is_recorded_for_traceability(self):
        """修复前 sha256 算了就丢，SandboxTask.sample_hash 从未被赋值。"""
        conn = _mk_connector()
        # 沙箱不可达 → 提交失败，但样本指纹仍应留痕
        outcome = run(conn.submit_file_outcome(b"MZ-fake-pe"))
        assert outcome.sample_hash, "sample_hash 未被记录"
        assert len(outcome.sample_hash) == 64
        assert conn.lookup_by_hash(outcome.sample_hash) is outcome

    def test_q12_19_get_status_exposes_last_outcome(self):
        conn = _mk_connector()
        conn._finish(SandboxOutcome(status=ST_UNAVAILABLE,
                                    error_code="probe", error_message="m"))
        st = conn.get_status()
        assert st["last_outcome"]["status"] == ST_UNAVAILABLE
        assert st["last_outcome"]["error_code"] == "probe"
        assert st["allow_internal_url"] is False


# ══════════════════════════════════════════════════════════════
# 报告缺失 ≠ 样本安全
# ══════════════════════════════════════════════════════════════

class TestNoResultIsNotClean:
    def test_q12_20_missing_report_never_yields_clean(self):
        from zeroday_detect.behavior_analyzer import behavior_analyzer

        for report in (None, {}, {"signatures": []} and {}):
            r = behavior_analyzer.analyze(report)
            assert r.verdict == "unavailable", (report, r.verdict)
            assert r.score is None, report
            assert r.analyzed is False
            assert r.is_negative is False

    def test_q12_21_real_zero_score_report_is_still_clean(self):
        """阳性对照：真正分析过且得分为 0 的样本仍然是 clean。"""
        from zeroday_detect.behavior_analyzer import behavior_analyzer

        r = behavior_analyzer.analyze(
            {"signatures": [], "network": {}, "behavior": {},
             "info": {"score": 0}})
        assert r.verdict == "clean"
        assert r.score == 0.0
        assert r.analyzed is True
        assert r.is_negative is True

    def test_q12_22_no_result_status_is_not_verdict_capable(self):
        outcome = SandboxOutcome(status=ST_NO_RESULT)
        assert outcome.verdict_capable is False
        assert outcome.is_failure is False     # 不是引擎故障
        assert outcome.terminal is True


# ══════════════════════════════════════════════════════════════════════════
# §五.1 越界 CAPE 评分的处理：把「不对称」显式钉住
#
# 实测（2026-10-19）：`_normalize_cape_score` 对四类越界输入的处理并不一致：
#
#   raw = -1    → (None, ['cape_score_out_of_range:-1.0']) → verdict=error
#   raw = '8.0' → (None, ['cape_score_type:str'])           → verdict=error
#   raw = True  → (None, ['cape_score_bool:True'])          → verdict=error
#   raw = inf   → (10.0, ['cape_score_inf_clamped'])        → verdict=error
#   raw = 99    → (10.0, [])                                → verdict=malicious
#
# 最后一行的差别是**刻意**的（源码注释：「上界截断，方向安全」），
# 且方向上确实安全：文档点名要避免的是「非法输入默默变成 0 分 = 判干净」，
# 而 99 变成的是满分，方向相反。
#
# 但要注意两点，否则后人会在不知情的情况下"顺手修好"它：
#   1. `analyze()` 里**任何**非空 `input_errors` 都会短路成 `error`+`score=None`，
#      所以给 99 补一个错误码 = 把 `malicious` 翻成 `error` = **关掉检测**。
#      这是收紧型改动，属于决策而非修 bug（见待决项 19），不得擅自改。
#   2. `inf` 与 99 是同一类越界输入，一个披露一个不披露，这个不对称目前
#      **没有任何测试钉住** —— 它是「碰巧如此」还是「刻意如此」从外面看不出来。
# 本节的作用就是把现状固化成显式契约：改之前先知道自己在改什么。
# ══════════════════════════════════════════════════════════════════════════

class TestOutOfRangeCapeScoreContract:
    """越界 CAPE 评分的处理现状 —— 改之前请先读上面的说明。"""

    @staticmethod
    def _rep(raw):
        return {"signatures": [], "network": {}, "behavior": {},
                "info": {"score": raw}}

    @pytest.mark.parametrize("raw", [-1, "8.0", True, None, float("nan")])
    def test_invalid_low_or_wrong_type_scores_are_errors(self, raw):
        from zeroday_detect.behavior_analyzer import behavior_analyzer
        r = behavior_analyzer.analyze(self._rep(raw))
        assert r.verdict == "error", r
        assert r.score is None, r
        assert r.analyzed is False, r
        assert r.input_errors, f"{raw!r} 是非法输入却没有任何 input_errors 记录"

    def test_infinite_score_is_clamped_and_disclosed(self):
        from zeroday_detect.behavior_analyzer import behavior_analyzer
        r = behavior_analyzer.analyze(self._rep(float("inf")))
        assert "cape_score_inf_clamped" in r.input_errors, r
        assert r.verdict == "error", r

    def test_finite_over_max_is_clamped_silently_by_design(self):
        """现状：**静默**截断且不记错误。

        这是刻意行为（方向安全），但它与上面 inf 的处理不对称。
        若有人改成记录错误码，本用例会红 —— 那是对的，本用例的作用是让这个
        改动**必须是一次有意识的决定**（并同步更新待决项 19），而不是无意的。
        """
        from zeroday_detect.behavior_analyzer import behavior_analyzer
        r = behavior_analyzer.analyze(self._rep(99))
        assert r.input_errors == [], (
            "有限的越界分数现在会记 input_errors —— 这会把 verdict 从 malicious "
            "翻成 error（关掉检测）。若确为有意，请同步更新本用例与待决项 19：\n"
            f"{r}")
        assert r.score == 1.0, r
        assert r.verdict == "malicious", r

    def test_legal_zero_score_is_still_a_definitive_negative(self):
        """前提守卫：合法 0 分必须仍是 clean 且可当作阴性。

        没有这条，上面几条断言可能在「凡有分数就判 error」的坏实现下全绿。
        """
        from zeroday_detect.behavior_analyzer import behavior_analyzer
        r = behavior_analyzer.analyze(self._rep(0))
        assert (r.verdict, r.score, r.analyzed, r.is_negative) == (
            "clean", 0.0, True, True), r
        assert r.input_errors == [], r
# ══════════════════════════════════════════════════════════════
# 重定向目标必须重新过安全限制（整改方案 §五.2）
# ══════════════════════════════════════════════════════════════

class TestRedirectTargetRevalidation:
    """重定向目标必须重新过一遍限制（整改方案 §五.2）。

    原文：
      「对域名解析后的 IP 与**重定向后的目标**重新做限制，
        避免 DNS 变更和重定向绕过」
      「对外部 API 请求**禁用非预期重定向**，使用固定服务端点」

    修复前 `_safe_redirect_target()` 只挡 **scheme 混淆** 与 **控制字符**，
    于是**云元数据 / loopback / 跨主机**的重定向目标全部放行 ——
    平台会带着 `self._headers()` 里的 **Bearer 沙箱 API key**
    去请求那些地址 = SSRF + 凭据外泄。

    另一处：控制字符那道检查原本查的是 `urljoin` **之后**的串，
    而 `urljoin` 会把控制字符**剥掉** —— 于是那道检查等于没有。

    这一组性质此前**没有任何回归**（全仓 `tests/` 搜 `redirect` → 零命中）。
    """

    BASE = "http://sandbox.internal:8000/tasks/create/url"

    def _conn(self):
        from zeroday_detect.sandbox_connector import SandboxConnector
        return SandboxConnector()

    @pytest.mark.parametrize("location, reason", [
        ("http://169.254.169.254/latest/meta-data/", "redirect_host_not_allowed"),
        ("http://metadata.google.internal/computeMetadata/v1/",
         "redirect_host_not_allowed"),
        ("http://127.0.0.1:6379/_INFO", "redirect_host_not_allowed"),
        ("http://evil.example.com/steal", "redirect_host_not_allowed"),
        ("file:///etc/passwd", "redirect_host_not_allowed"),
    ])
    def test_dangerous_redirect_targets_are_rejected(self, location, reason):
        """【已修复】云元数据 / loopback / 跨主机 / scheme 混淆 → 一律拒绝。"""
        with pytest.raises(UrlRejected) as ei:
            self._conn()._safe_redirect_target(self.BASE, location)
        assert ei.value.reason == reason, (location, ei.value.reason)

    def test_control_chars_are_checked_before_urljoin_strips_them(self):
        """【已修复】控制字符必须在**原始 Location** 上检查。

        `urljoin` 会把控制字符剥掉，所以事后检查归一化后的串等于没检查。
        """
        with pytest.raises(UrlRejected) as ei:
            self._conn()._safe_redirect_target(
                self.BASE, "http://sandbox.internal:8000/a\nb")
        assert ei.value.reason == "redirect_control_chars", ei.value.reason

    def test_empty_location_is_rejected(self):
        """【已修复】空 Location 不得被当成「重定向到当前地址」而空转。"""
        with pytest.raises(UrlRejected) as ei:
            self._conn()._safe_redirect_target(self.BASE, "")
        assert ei.value.reason == "redirect_target_empty", ei.value.reason

    def test_same_host_relative_redirect_is_still_allowed(self):
        """【正向对照】同主机的正常重定向不得被误伤。"""
        got = self._conn()._safe_redirect_target(self.BASE, "/other/path")
        assert got == "http://sandbox.internal:8000/other/path", got
# ══════════════════════════════════════════════════════════════
# 缺失 task_id ⇒ 提交失败（整改方案 §十.1）
# ══════════════════════════════════════════════════════════════

class TestMissingTaskIdIsSubmissionFailure:
    """沙箱返回 200 但没有可用 task_id → 必须视为**提交失败**。

    整改方案 §十.1 原文：
      「提交成功必须返回有效的外部任务 ID；**缺失 ID 应当视为提交失败**」

    修复前：`str(result.get("task_id", ...))` 会把 `None` 变成字面量字符串
    `"None"` —— 真值检查放行 → 落库成**永久悬空任务**
    （`SandboxTask.status="pending"` 再也不会被推进）。

    这一条此前**没有任何回归**（全仓 `tests/` 搜 `missing_task_id` → 零命中）。

    ⚠ 用例里的 URL 用 **IP 字面量**而不是域名：域名会触发
    `validate_submittable_url` 的实时 DNS 解析 → 结论由环境决定
    （这正是本轮刚修掉的 §9.16 那个坑，不要再犯一次）。
    """

    URL = "http://93.184.216.34/x"          # 公网 IP 字面量 → 不需要 DNS

    @pytest.mark.parametrize("payload", [
        {"task_id": None},
        {"task_id": ""},
        {"task_id": "   "},
        {},
        {"task_ids": []},
        {"other": "x"},
    ])
    def test_missing_task_id_is_treated_as_submission_failure(
            self, payload, monkeypatch):
        conn = _mk_connector()

        async def _fake_request(method, url, **kw):
            return (200, dict(payload), "", "")

        monkeypatch.setattr(conn, "_request", _fake_request)
        outcome = run(conn.submit_url_outcome(self.URL))
        assert outcome.status == ST_FAILED, (payload, outcome.status)
        assert outcome.error_code == "missing_task_id", (payload, outcome.error_code)
        assert outcome.task_id == "", (payload, outcome.task_id)

    def test_valid_task_id_is_accepted(self, monkeypatch):
        """【正向对照】有可用 task_id → 提交成功（ST_PENDING），别把好路径堵死。"""
        conn = _mk_connector()

        async def _fake_request(method, url, **kw):
            return (200, {"task_id": "abc-123"}, "", "")

        monkeypatch.setattr(conn, "_request", _fake_request)
        outcome = run(conn.submit_url_outcome(self.URL))
        assert outcome.status == ST_PENDING, outcome.status
        assert outcome.task_id == "abc-123", outcome.task_id
        assert outcome.external_task_id == "abc-123", outcome.external_task_id

    def test_task_ids_list_takes_the_first_usable_entry(self, monkeypatch):
        """【正向对照】`task_ids` 列表取第一个可用项。"""
        conn = _mk_connector()

        async def _fake_request(method, url, **kw):
            return (200, {"task_ids": ["t-1", "t-2"]}, "", "")

        monkeypatch.setattr(conn, "_request", _fake_request)
        outcome = run(conn.submit_url_outcome(self.URL))
        assert outcome.status == ST_PENDING, outcome.status
        assert outcome.task_id == "t-1", outcome.task_id
