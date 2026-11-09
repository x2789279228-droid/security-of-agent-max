# -*- coding: utf-8 -*-
"""活跃模块的**零测试覆盖面**必须被显式登记（整改方案 §十三「全量回归」行，§9.44）。

## 这个缺口有多大

```
backend 模块总数        : 508
测试文件数              : 197
解析失败的文件数        : 0        ← 必须为 0
被**包外**生产代码引用的模块数: 192
其中**零测试覆盖**的    : 23        （非入口层的叶子模块，合计 188 KB）
入口层同样没被 import 的: 8        （HTTP 入口，单列，不据此下结论）
```

「零覆盖」的判据：全仓 `tests/` 里既没有 import 它，
也没有任何文件在**代码**里引用它的标识符 —— 两项都用 **AST** 判，不用文本。

这 23 个里包括：

* `response_engine/ttl_manager.py` —— 响应动作的 TTL
  （TTL 过期后是否仍会执行，**无回归**）
* `protocol_parser/tls_parser.py` / `dissector.py` —— **C2 会话证据的来源**
* `phishing_guard/drill_manager.py` —— 钓鱼演练（演练触发的是**真实响应动作**）
* `rag/seeder.py`（44 KB，全仓最大）/ `qdrant_store.py`（19 KB）—— 检索链的两块大件
* `stabilizer/stabilizer.py` —— 输入稳定化主流程
  （**且整条管线没有生产调用方**，见 §9.44.5）

§9.43 挖出的「C2 证据在高峰期被静默丢弃」就藏在其中一个模块里
（`encrypted_traffic/session_collector.py`，已被 §9.43 补上测试并移出清单）。

## 口径边界（必须写清，否则会把结论说过头）

1. **入口层单列**：`routers/` 下的 HTTP 入口**结构性**不会被测试 import
   （它们由端点级测试覆盖），所以静态判据对它们失效 → 单列，不据此下结论。
2. 判据是「**没有测试引用**」，不是「测试质量差」——
   有测试但没测到关键路径的模块，这份清单**看不见**。
3. 判据是**静态**的：它回答「测试里连名字都没出现过」，
   不回答「行为有没有被测到」。

## 本守卫盯什么

1. 实测的零覆盖清单**必须**与显式登记表**双向相等** ——
   新增一个没被覆盖的活跃模块 → 转红；
   给某个模块补了测试 → **也**转红（必须同步登记表）。
2. 登记表里每一条都必须**写明理由**（不能只列名字）。
3. **安全关键**的那几条必须**在**登记表里（不能被悄悄删掉）。
4. 扫描器自身的**已知答案自检**必须通过。
5. **解析失败的文件数必须为 0** —— 解析失败的文件会被**静默跳过**，
   它的 import 全部不可见，结论会虚高（`app.py` 带 BOM 就是这个坑）。
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(BACKEND)
sys.path.insert(0, BACKEND)

SCANNER = os.path.join(REPO, "tools", "scan-active-zero-coverage.py")


def _load_scanner():
    spec = importlib.util.spec_from_file_location("scan_active_zero_coverage", SCANNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


#: 显式登记表：模块 → 理由。键的顺序即优先级（先列安全关键的）。
REGISTERED: dict[str, str] = {
    # 2026-10-21: `response_engine.ttl_manager` 已由
    # tests/test_m1_response_boundary.py 覆盖，并从零覆盖登记表移除。
    # 2026-10-30 H 路线收口: `zeroday_detect.llm_behavior` 已有接线测试
    # 覆盖(挂 log_ingestion 异步解读) —— 但接线≠覆盖, 实测它仍在零覆盖面,
    # 如实登记(见下方条目)。
    "zeroday_detect.llm_behavior":
        "LLM 沙箱行为解读 —— 2026-10-30 H 接线(log_ingestion 异步)后仍零测试覆盖",
    "protocol_parser.tls_parser":
        "TLS 协议解析（C2 会话证据的来源）—— 零覆盖",
    "protocol_parser.dissector":
        "协议解析入口（TLS 会话收集器的输入源）—— 零覆盖",
    "phishing_guard.drill_manager":
        "钓鱼演练编排 —— 零覆盖（演练触发的是**真实响应动作**）",
    "traffic_capture.pcap_store":
        "PCAP 落盘（流量证据）—— 零覆盖",
    "rag.seeder":
        "RAG 规则播种（44 KB，全仓最大）—— 零覆盖",
    # 2026-10-20（§9.50）：`qdrant_store` **已不在**这份清单里 ——
    # 它被 §9.50 的降级产物守卫覆盖了（双向相等守卫因此转红，要求同步）。
    # 修复前它**在**这份清单里（它正是「降级产物入库」那条路的所在）。
    "stabilizer.stabilizer":
        "输入稳定化主流程 —— 零覆盖（**且整条管线没有生产调用方**，见 §9.44.5）",
    "stabilizer.json_repair":
        "JSON 修复 —— 零覆盖（畸形输入路径无回归）",
    "memory_tree":
        "记忆树（11 KB）—— 零覆盖",
    "protocol_parser.http_parser":
        "HTTP 协议解析 —— 零覆盖",
    "protocol_parser.dns_parser":
        "DNS 协议解析 —— 零覆盖",
    "protocol_parser.smb_parser":
        "SMB 协议解析 —— 零覆盖",
    "protocol_parser":
        "协议解析包入口 —— 零覆盖",
    "rag.context_builder":
        "RAG 上下文拼装 —— 零覆盖",
    "traffic_capture.flow_aggregator":
        "流量聚合 —— 零覆盖",
    "asset.asset_history":
        "资产历史 —— 零覆盖",
    "context_stream":
        "上下文流 —— 零覆盖",
    "dependency_health":
        "依赖健康检查 —— 零覆盖",
    "eval_service":
        "评估服务 —— 零覆盖",
    "observability.stage_events":
        "阶段事件 —— 零覆盖",
    "stats_counter":
        "统计计数 —— 零覆盖",
    # 2026-10-29 (R7): user_store 补了事件循环阻塞测试(test_auth_no_event_loop_block)
    # → 已移出零覆盖登记表
    # 2026-10-27: ip2region 官方绑定 (vendored 第三方, Apache-2.0) —
    # 由 geo_ip 动态导入的离线 IP 地理库, 第三方检索器不纳入测试覆盖度量
    "ip2region":
        "ip2region 绑定包入口 (vendored 第三方) —— 零覆盖",
    "ip2region.searcher":
        "ip2region xdb 检索器 (vendored 第三方) —— 零覆盖",
}

#: 安全关键的那几条（不能被悄悄从登记表里删掉）
SECURITY_CRITICAL = {
    "protocol_parser.tls_parser",
    "protocol_parser.dissector",
    "phishing_guard.drill_manager",
    "traffic_capture.pcap_store",
}


@pytest.fixture(scope="module")
def scanner():
    if not os.path.exists(SCANNER):
        pytest.skip("扫描器不在仓库里")
    return _load_scanner()


class TestTheZeroCoverageListIsRegistered:
    def test_the_measured_list_equals_the_registry(self, scanner):
        """实测清单与登记表**双向相等**。

        * 新增一个没被覆盖的活跃模块 → 转红（不能悄悄扩大缺口）；
        * 给某个模块补了测试 → **也**转红（必须同步登记表）。
        """
        _active, zero, _all, _tests, _entry = scanner.active_modules()
        measured = set(zero)
        registered = set(REGISTERED)
        assert measured == registered, (
            "零覆盖清单与登记表不一致。\n"
            f"  实测多出: {sorted(measured - registered)}\n"
            f"  实测缺少: {sorted(registered - measured)}\n"
            "  补了测试要同步登记表；新增缺口也要登记（不能悄悄扩大）。")

    def test_every_registered_entry_has_a_reason(self):
        """登记表里每一条都必须**写明理由**（不能只列名字）。"""
        missing = [k for k, v in REGISTERED.items() if not v.strip()]
        assert not missing, f"这些条目没有写理由：{missing}"

    def test_the_security_critical_ones_are_still_registered(self):
        """安全关键的那几条**必须**在登记表里（不能被悄悄删掉）。"""
        missing = sorted(SECURITY_CRITICAL - set(REGISTERED))
        assert not missing, (
            f"安全关键的模块从登记表里消失了：{missing} —— "
            "这条守卫就是防止「把最该补测的先删掉」")


class TestTheScannerItselfIsSound:
    def test_the_known_answers(self, scanner):
        """扫描器自身的**已知答案自检**必须通过。

        这个扫描器错了**五次**（`from pkg import mod` 认不出；别名遮住原名；
        「活跃」没区分包内/包外；带 BOM 的 `app.py` 被静默跳过；
        包的 `__init__.py` 模块名被多切 3 个字符）——
        五次都是**自检**抓到的，不是事后看出来的。
        """
        _active, zero, _all, _tests, _entry = scanner.active_modules()
        zero_set = set(zero)
        for modname, expect_covered in scanner.SELFCHECK:
            covered = modname not in zero_set
            assert covered == expect_covered, (
                f"扫描器对 {modname} 的判定是 {covered}，"
                f"预期 {expect_covered} —— 量具坏了，结论不能用")

    def test_no_file_failed_to_parse(self, scanner):
        """**解析失败的文件数必须为 0**。

        解析失败的文件会被**静默跳过** → 它的 import 全部不可见 →
        「活跃」的判定失真、结论虚高。
        `app.py` 带 BOM 就是这个坑（`utf-8` 解码 → U+FEFF → SyntaxError）。
        """
        assert not scanner.PARSE_FAILURES, (
            "有文件解析失败（它们被静默跳过，结论会虚高）："
            f"{[(os.path.basename(p), why) for p, why in scanner.PARSE_FAILURES[:5]]}")

    def test_the_scan_does_not_depend_on_the_cwd(self, scanner):
        """扫描结果与**当前工作目录**无关（否则 CI 与本机会给出不同答案）。"""
        _a, zero, _all, _t, _e = scanner.active_modules()
        cwd = os.getcwd()
        try:
            os.chdir(os.path.dirname(BACKEND))
            _a2, zero2, _all2, _t2, _e2 = scanner.active_modules()
        finally:
            os.chdir(cwd)
        assert zero == zero2, "扫描结果随工作目录变了 —— 判据不稳"


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
