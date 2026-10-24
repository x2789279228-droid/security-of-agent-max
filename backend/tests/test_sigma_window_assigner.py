# -*- coding: utf-8 -*-
"""RuleTimeframeWindows 真执行回归 —— P0-1 最核心的"按规则 timeframe 建窗"语义。

## 背景（2026-10-24 评审 §五.2）

`SigmaWindowHarness` 只覆盖窗口**函数**；窗口**分配器**（自定义
`WindowAssigner` 的 assignWindows）此前零执行验证。分配器写错的后果是
聚合永远不触发（窗口盖不住事件时间戳）或阈值虚高（宽度/对齐取错），
且编译与源码断言都看不出来。

本文件用真实 JVM 进程外执行 `RuleTimeframeWindows.assignWindows`
（元素经真实 `SigmaHit.fromString` 解析），钉住：
宽度=声明值、slide=宽度/5、start 对齐 slide 网格、窗口覆盖事件时间戳、
缺省回退 5m、字符串("1m"/"90s")与毫秒(timeframe_ms)两种声明等价。
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

REPO_ROOT = Path(__file__).resolve().parents[2]
FLINK_DIR = REPO_ROOT / "flink-jobs"
HARNESS_MAIN = "com.soc.job.RuleTimeframeHarness"
HARNESS_SOURCE = (
    FLINK_DIR / "src" / "test" / "java" / "com" / "soc" / "job"
    / "RuleTimeframeHarness.java"
)

MVN = shutil.which("mvn") or shutil.which("mvn.cmd")


def _jdk_bin(name: str):
    home = os.environ.get("JAVA_HOME")
    if home:
        for cand in (Path(home) / "bin" / name,
                     Path(home) / "bin" / (name + ".exe")):
            if cand.is_file():
                return str(cand)
    return shutil.which(name)


def _m2_has_flink() -> bool:
    home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or ""
    return (Path(home) / ".m2" / "repository" / "org" / "apache" / "flink").is_dir()


@pytest.fixture(scope="module")
def assigner_runner():
    """一次性构建: mvn 编译主类 + 导出依赖 classpath + javac 编译 harness。"""
    java, javac, mvn = _jdk_bin("java"), _jdk_bin("javac"), MVN
    if not java or not javac or mvn is None:
        pytest.skip("未找到 JDK/Maven，跳过窗口分配器真执行验证")
    assert HARNESS_SOURCE.is_file(), f"harness 缺失: {HARNESS_SOURCE}"

    proj = Path(tempfile.mkdtemp(prefix="flinktf-"))
    try:
        shutil.copytree(FLINK_DIR / "src", proj / "src",
                        ignore=shutil.ignore_patterns("target"))
        shutil.copy2(FLINK_DIR / "pom.xml", proj / "pom.xml")

        def _mvn(args):
            return subprocess.run([mvn, "-B", "-o", *args], cwd=str(proj),
                                  capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=900)

        proc = _mvn(["-DskipTests", "compile"])
        if proc.returncode != 0 and not _m2_has_flink():
            pytest.skip("Maven 本地仓库没有 Flink 依赖，离线编译无法进行")
        assert proc.returncode == 0, proc.stdout[-3000:]

        cp_file = proj / "cp.txt"
        proc = _mvn(["-q", "org.apache.maven.plugins:maven-dependency-plugin"
                     ":3.6.1:build-classpath", f"-Dmdep.outputFile={cp_file}"])
        assert cp_file.is_file(), "依赖 classpath 导出失败"

        cp = (cp_file.read_text(encoding="utf-8").strip()
              + os.pathsep + str(proj / "target" / "classes"))
        out_classes = proj / "target" / "test-classes"
        out_classes.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [javac, "-J-Dsun.stderr.encoding=UTF-8", "-encoding", "UTF-8",
             "-nowarn", "-cp", cp, "-d", str(out_classes), str(HARNESS_SOURCE)],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=300)
        assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]

        full_cp = cp + os.pathsep + str(out_classes)

        def run(payloads: list[dict]) -> list[dict]:
            stdin = "".join(json.dumps(p) + "\n" for p in payloads)
            proc = subprocess.run(
                [java, "-cp", full_cp, HARNESS_MAIN],
                input=stdin, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=120, cwd=str(FLINK_DIR))
            assert proc.returncode == 0, proc.stderr[-2000:]
            return [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]

        yield run
    finally:
        shutil.rmtree(proj, ignore_errors=True)


def _hit(**kw):
    base = {
        "src_ip": "10.0.0.5", "rule_id": "SIG-001", "threshold": 5,
        "timestamp": 1_700_000_040_000,   # 4 分 0 秒, 落在 slide 网格中间
    }
    base.update(kw)
    return base


# ── 宽度 / slide / 对齐 ──────────────────────────────────────

def test_declared_5m_window_shape(assigner_runner):
    """backend 载荷(timeframe_ms=300000): 5 个窗口、宽 5m、slide 1m。"""
    r = assigner_runner([_hit(timeframe_ms=300_000)])[0]
    assert r["declared_ms"] == 300_000
    assert r["window_count"] == 5
    assert r["size"] == 300_000
    assert r["slide"] == 60_000
    assert r["covers_ts"] is True, "分配出的窗口必须覆盖事件时间戳"
    # start 对齐 slide 网格: first_start ≡ 0 (mod 60000)
    assert r["first_start"] % 60_000 == 0


def test_declared_1m_window_shape(assigner_runner):
    """timeframe: 1m → 宽 60s / slide 12s —— 不再被硬编码 5m 吞掉。"""
    r = assigner_runner([_hit(timeframe_ms=60_000, timeframe="1m")])[0]
    assert r["declared_ms"] == 60_000
    assert r["window_count"] == 5
    assert r["size"] == 60_000
    assert r["slide"] == 12_000
    assert r["covers_ts"] is True


def test_string_only_timeframe_90s(assigner_runner):
    """只有 timeframe 字符串("90s", 无 timeframe_ms) → 90s 窗 / 18s slide。"""
    r = assigner_runner([_hit(timeframe="90s")])[0]
    assert r["declared_ms"] == 90_000
    assert r["window_count"] == 5
    assert r["size"] == 90_000
    assert r["slide"] == 18_000


def test_bare_number_timeframe_is_seconds(assigner_runner):
    """Sigma 规范: 裸数字按秒 → "300" = 5 分钟。"""
    r = assigner_runner([_hit(timeframe="300")])[0]
    assert r["declared_ms"] == 300_000
    assert r["size"] == 300_000


def test_missing_timeframe_falls_back_to_default_5m(assigner_runner):
    """旧版本候选(无任何 timeframe 声明)回退默认 5m —— 与 backend 常量一致。"""
    r = assigner_runner([_hit()])[0]
    assert r["declared_ms"] == 0  # SigmaHit 解析为 0
    assert r["window_count"] == 5
    assert r["size"] == 300_000
    assert r["covers_ts"] is True


def test_timestamp_alignment_is_deterministic(assigner_runner):
    """last_start = timestamp - (timestamp % slide): 对齐必须精确可复算。"""
    ts = 1_700_000_040_000
    r = assigner_runner([_hit(timeframe_ms=300_000, timestamp=ts)])[0]
    expected_first = ts - (ts % 300_000) - 4 * 60_000
    assert r["first_start"] == expected_first
    assert (ts - r["first_start"]) < 300_000


def test_seconds_timestamp_is_normalized_before_windowing(assigner_runner):
    """秒级 timestamp(≈1.7e9)必须先归一成毫秒再建窗 —— 否则事件时间
    落在 1970 年, 窗口照分配但计数永远等不到 watermark。"""
    r = assigner_runner([_hit(timeframe_ms=300_000, timestamp=1_700_000_040)])[0]
    assert r["timestamp"] == 1_700_000_040_000, "秒级时间戳未 ×1000 归一"
    assert r["covers_ts"] is True
