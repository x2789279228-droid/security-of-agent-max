"""
Sigma 聚合告警的**动作链路**回归。

## 这批测试为什么存在

上一轮把「单事件阶段拿不充分的证据下执行动作」修掉了：带
``x-soc-aggregation`` 的规则命中降级为 ``partial`` + ``alert``。
但修完立刻暴露一个**由该修复引入的回归**：

> 规则声明 ``action: block_ip``，降级后单事件阶段只发 ``alert``；
> 真正该封禁的时机变成「聚合窗口超阈值之后」。
> 而聚合窗口当时发的告警里**一个动作字段都没有** ——
> 于是 SIG-001/007 的封禁能力**静默消失**了。

这类回归不会报错、不会让任何测试变红，它只是让一个功能不再发生。
所以这里对**链路上每一层**都钉一条断言：任何一层把字段丢了，
测试立刻变红，而不是等到生产上发现「暴力破解不再封 IP」。

## 链路与断言的对应

| 层 | 文件 | 断言 |
|---|---|---|
| 1 单事件判定 | `sigma_engine/engine.py` | 带聚合的规则不发执行类动作 |
| 1b **接线** | `sigma_engine/engine.py::detect` | 命中聚合规则时**确实**发布候选（不能只测载荷函数） |
| 2 候选载荷 | `sigma_engine/engine.py::_agg_payload` | 载荷带规则**声明的**动作/严重度/置信度 |
| 3 Kafka 白名单 | `kafka_producer.py::publish_sigma_hit` | 白名单放行上述字段 |
| 4 Flink 窗口 | `SigmaThresholdAggregationJob.java` | **真执行**（4c）+ **真编译**（4b）+ 字段静态断言（4a） |

⚠️ 第 6 层是**踩过一次坑之后补上的**。第 5 层修完时链路看着是通的，
但消费端只用 `anomalyScore` 算置信度，而 Sigma 聚合告警根本没有这个字段
→ 实算 confidence=0.0 → 策略「暴力破解自动阻断」要求 `min_confidence=0.5`
→ `NO_ACTION`。**allow_blocking 判对了也永远不封禁。**
链路上每多一层，就多一次「字段在这条边界上被丢掉」的机会。
| 5 告警消费 | `kafka_consumer.py::_allow_blocking_for` | 阻断门槛由动作派生 |
| 6 策略匹配 | `kafka_consumer.py::_handle_alert` | 置信度能从 `confidence` 取到，**否则匹配不到策略** |

⚠️ 第 4 层现在有**真编译**（4b）与**真执行**（4c）两层验证了。
4b：装了 Maven 3.9.9 + JDK 21，``mvn -B -DskipTests compile`` 在
``flink-jobs/`` 下 ``BUILD SUCCESS``，15 个源文件全部编译通过，
产出 ``SigmaThresholdAggregationJob{,$SigmaHit,$ThresholdWindowFunction}.class``。

4c 再往前一步：编译只能告诉你「有没有语法/类型错」，源码断言只能告诉你
「字段名还在不在」，两者都**回答不了**「阈值比较方向对不对」「取最严动作
真的取了吗」「两个语言之间的键名还对得上吗」。4c 用真实 JVM 驱动真实的
``ThresholdWindowFunction.process``，喂真实载荷（含 ``_agg_payload``
真产出），17 条断言，并已验证在修复前的 Java 上是红的。

⚠️ 仍未验证：**作业没在真实 Flink 集群上跑过**。进程外执行验证的是
窗口函数本身的逻辑，不是窗口算子的运行语义（5m/1m 滑动窗口的边界分配、
同 key 并发、水位线、处理时间 vs 事件时间）。
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from kafka_consumer import _allow_blocking_for          # noqa: E402
from sigma_engine.engine import (                       # noqa: E402
    ENFORCEMENT_ACTIONS, SIGMA_CONFIDENCE_NUM,
    PySigmaDetector,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FLINK_DIR = REPO_ROOT / "flink-jobs"
FLINK_JOB = (
    FLINK_DIR / "src" / "main" / "java" / "com" / "soc" / "job"
    / "SigmaThresholdAggregationJob.java"
)

ENFORCEMENT = {"block_ip", "block", "quarantine", "isolate",
               "deny", "drop", "kill"}


def _meta(**kw):
    base = {
        "rule_id": "SIG-001", "name": "登录接口高频访问",
        "severity": "high", "attack_type": "brute_force",
        "confidence": "high",
        "action_recommend": "block_ip", "shadow_mode": False,
    }
    base.update(kw)
    return base


# ══════════════════════════════════════════════════════════════
# 1b. 接线：detect() 必须真的发布候选
# ══════════════════════════════════════════════════════════════

def test_detect_actually_schedules_publish_for_aggregation_rule(monkeypatch):
    """命中带 x-soc-aggregation 的规则时，``detect()`` 必须真的发布候选。

    ⚠️ 这条补的是**上一版测试的洞**：当时只测了 ``_agg_payload`` 这个纯函数，
    没有任何断言证明 ``detect()`` 会调用它。把
    ``if requires_agg: self._schedule_publish_agg(...)`` 整段删掉，
    31 条断言照样全绿 —— 而候选再也发不出去，封禁链彻底静默失效。

    这就是「测函数」与「测接线」的区别：前者保证函数对，
    后者保证它被调到。链路越长，两者越不能互相替代。
    """
    det = PySigmaDetector("sigma_engine/rules")
    published = []
    monkeypatch.setattr(
        det, "_schedule_publish_agg",
        lambda meta, ev, agg: published.append((meta.get("rule_id"), dict(agg))),
    )

    # SIG-001：url 判据 /api/auth/login，声明了 x-soc-aggregation
    det.detect({"event": "BRUTE_FORCE", "url": "/api/auth/login",
                "src_ip": "10.1.2.3", "dst_ip": "10.0.0.9"})

    assert published, ("detect() 没有发布任何聚合候选 —— "
                       "候选发不出去，聚合窗口就永远不会超阈值")
    rule_ids = [r for r, _ in published]
    assert "SIG-001" in rule_ids, f"未发布 SIG-001 候选，实际发布了 {rule_ids}"
    agg = dict(next(a for r, a in published if r == "SIG-001"))
    assert int(agg.get("threshold") or 0) > 0, \
        f"发布的阈值必须为正，否则窗口会退化成单事件告警: {agg}"


def test_detect_does_not_publish_for_non_aggregation_rules(monkeypatch):
    """不带 x-soc-aggregation 的规则命中**不得**发布聚合候选。

    反向约束：不是所有命中都该进窗口。否则 SIG-003（路径遍历，
    单事件即可定性）也会被发去计数，窗口里混进不该计的噪声。
    """
    det = PySigmaDetector("sigma_engine/rules")
    published = []
    monkeypatch.setattr(
        det, "_schedule_publish_agg",
        lambda meta, ev, agg: published.append(meta.get("rule_id")),
    )

    det.detect({"event": "PATH_TRAVERSAL", "url": "/../../etc/passwd",
                "src_ip": "10.1.2.4", "dst_ip": "10.0.0.9"})

    assert "SIG-003" not in published, \
        f"SIG-003 不是聚合规则却被发布成候选: {published}"


# ══════════════════════════════════════════════════════════════
# 2. 候选载荷：必须带规则声明的动作
# ══════════════════════════════════════════════════════════════

def test_agg_payload_carries_declared_action_not_downgraded():
    """载荷里的动作是规则**声明的** block_ip，不是降级后的 alert。

    这是整条链路的枢纽。单事件阶段禁止处置，所以「窗口超阈值后
    按规则处置」是唯一能产生封禁的时机；载荷若在这里丢了动作，
    后面三层再正确也没用 —— 而且不会报错。
    """
    p = PySigmaDetector._agg_payload(
        _meta(), {"src_ip": "10.1.2.3"}, {"threshold": 5})
    assert p["action_recommend"] == "block_ip"
    assert p["severity"] == "high"
    assert p["attack_type"] == "brute_force"
    assert p["rule_id"] == "SIG-001" and p["threshold"] == 5
    assert p["src_ip"] == "10.1.2.3"


def test_agg_payload_respects_shadow_mode():
    """灰度规则即便声明 block_ip 也只能出 alert —— 与 detect() 同口径。

    口径不一致会有两种后果：灰度期真的封了用户（安全侧事故），
    或者 detect() 降级了而这里没降级（能力不一致、难排查）。
    """
    p = PySigmaDetector._agg_payload(
        _meta(shadow_mode=True), {"src_ip": "1.1.1.1"}, {"threshold": 5})
    assert p["action_recommend"] == "alert"


def test_agg_payload_defaults_are_conservative():
    """缺字段时必须落到**保守值**，不能落到「允许阻断」。

    `or` 的默认值方向很重要：动作回落到 alert、严重度回落到 medium，
    都不会凭空放行处置。反过来（回落到 block_ip）就是凭空封人。
    """
    p = PySigmaDetector._agg_payload(
        {"rule_id": "SIG-X"}, {}, {})
    assert p["action_recommend"] == "alert"
    assert p["severity"] == "medium"
    assert p["attack_type"] == "custom"
    assert p["threshold"] == 0


def test_enforcement_actions_contains_expected_set():
    """动作分类表本身要钉住 —— 消费端和降级端共用这一份。

    两处若各写一份清单，迟早漂移；漂移的方向通常是「新动作漏进清单」
    （漏出才是安全的），但反过来「误把 require_confirmation 列进去」
    就会让人工确认直接变成自动封禁。
    """
    assert ENFORCEMENT == ENFORCEMENT_ACTIONS
    assert "require_confirmation" not in ENFORCEMENT_ACTIONS
    assert "alert" not in ENFORCEMENT_ACTIONS


# ══════════════════════════════════════════════════════════════
# 2b. 置信度：缺了它聚合告警匹配不到任何策略
# ══════════════════════════════════════════════════════════════

def test_agg_payload_carries_numeric_confidence():
    """载荷必须带**数值** confidence。

    这是第 6 层断链的根因：消费端拿 confidence 做策略门槛
    （「暴力破解自动阻断」min_confidence=0.5），而聚合告警不带
    anomalyScore → 实算 0.0 → NO_ACTION → 永不封禁。
    """
    p = PySigmaDetector._agg_payload(
        _meta(confidence="high"), {"src_ip": "1.1.1.1"}, {"threshold": 5})
    assert isinstance(p["confidence"], float)
    assert p["confidence"] == pytest.approx(0.85)
    assert p["confidence"] >= 0.5, \
        "SIG-001 这类规则的置信度必须够得着 min_confidence=0.5 的门槛"


@pytest.mark.parametrize("declared,expected", [
    ("high", 0.85), ("medium", 0.65), ("low", 0.45),
    ("HIGH", 0.85), ("  high  ", 0.85),
])
def test_agg_payload_confidence_mapping(declared, expected):
    p = PySigmaDetector._agg_payload(
        _meta(confidence=declared), {"src_ip": "1.1.1.1"}, {"threshold": 5})
    assert p["confidence"] == pytest.approx(expected)


@pytest.mark.parametrize("declared", ["", None, "unknown", "banana", 1])
def test_agg_payload_confidence_falls_back_to_conservative(declared):
    """认不出的 confidence 必须落到**最低档 0.45**，不能落到高值。

    默认值方向就是安全边界：往低了落，最坏结果是策略不匹配（不处置）；
    往高了落，一条拼错的规则就能凭空获得封禁资格。
    """
    p = PySigmaDetector._agg_payload(
        _meta(confidence=declared), {"src_ip": "1.1.1.1"}, {"threshold": 5})
    assert p["confidence"] == pytest.approx(0.45)
    assert p["confidence"] == min(SIGMA_CONFIDENCE_NUM.values())


def test_sigma_confidence_scale_matches_audit_pipeline():
    """聚合链路的置信度刻度必须与审计链路一致。

    ``audit_triage._fused_confidence`` 与 ``ingest_pipeline`` 里各自写了一份
    ``{"high": 0.85, "medium": 0.65, "low": 0.45}``。同一条 Sigma 证据，
    审计链路算 0.85、聚合链路算别的数，两条处置路径的门槛就对不上了。

    这里用源码断言把三处钉在一起 —— 与其抽公共模块让两个热路径多一层
    import，不如先保证它们不会各自漂移。
    """
    assert SIGMA_CONFIDENCE_NUM == {"high": 0.85, "medium": 0.65, "low": 0.45}

    backend = Path(__file__).resolve().parents[1]
    literal = '"high": 0.85, "medium": 0.65, "low": 0.45'
    for mod in ("audit_triage.py", "ingest_pipeline.py"):
        src = (backend / mod).read_text(encoding="utf-8")
        assert literal in src, (
            f"{mod} 的 sigma confidence 刻度与 sigma_engine 不一致；"
            f"三处必须同一把尺，否则审计链路与聚合链路的处置门槛对不上")


# ══════════════════════════════════════════════════════════════
# 3. Kafka 白名单：不能把动作字段剥掉
# ══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_publish_sigma_hit_preserves_action_fields(monkeypatch):
    """producer 的字段白名单必须放行动作字段。

    这层最容易踩：上游 `payload` 里明明塞了 `action_recommend`，
    这里按白名单重建 dict，没列到的键就**静默丢弃**。
    结果与「上游没塞」完全一样，但排查方向会指向错误的地方。
    """
    import json as _json

    from kafka_producer import kafka_producer

    sent = {}

    async def fake_send(topic, key, value, headers=None):
        sent.update({"topic": topic, "key": key, "body": _json.loads(value)})

    monkeypatch.setattr(kafka_producer, "_started", True, raising=False)
    monkeypatch.setattr(kafka_producer, "_send_bounded", fake_send)

    await kafka_producer.publish_sigma_hit({
        "src_ip": "10.1.2.3",
        "rule_id": "SIG-001",
        "threshold": 5,
        "timestamp": 1700000000000,
        "action_recommend": "block_ip",
        "severity": "high",
        "attack_type": "brute_force",
        # 上游可能带的额外字段，确认白名单行为稳定
        "__internal_debug": "should_not_leak",
    })

    body = sent["body"]
    assert body["action_recommend"] == "block_ip", (
        "action_recommend 被 producer 白名单剥掉了")
    assert body["severity"] == "high"
    assert body["attack_type"] == "brute_force"
    assert body["rule_id"] == "SIG-001" and body["threshold"] == 5
    assert "__internal_debug" not in body, "白名单失效：非约定字段被透传"


@pytest.mark.asyncio
async def test_publish_sigma_hit_defaults_to_non_blocking(monkeypatch):
    """上游没给动作时，payload 必须落到 alert 而不是缺字段。

    缺字段会让消费端把「没声明」和「声明了非执行动作」混为一谈，
    从而放行阻断 —— 这正是 `_allow_blocking_for` 口径 1/2 要分开的理由。
    """
    import json as _json

    from kafka_producer import kafka_producer

    sent = {}

    async def fake_send(topic, key, value, headers=None):
        sent["body"] = _json.loads(value)

    monkeypatch.setattr(kafka_producer, "_started", True, raising=False)
    monkeypatch.setattr(kafka_producer, "_send_bounded", fake_send)

    await kafka_producer.publish_sigma_hit(
        {"src_ip": "1.1.1.1", "rule_id": "SIG-007", "threshold": 3})

    assert sent["body"]["action_recommend"] == "alert"
    assert sent["body"]["severity"] == "medium"
    assert sent["body"]["confidence"] == pytest.approx(0.45)


@pytest.mark.asyncio
@pytest.mark.parametrize("raw,expected", [
    (0.85, 0.85), ("0.65", 0.65), (None, 0.45), ("", 0.45),
    ("high", 0.45),        # 字符串刻度不该被悄悄当成数字放行
    (float("nan"), 0.45),  # NaN 会让所有比较为 False，策略永不匹配
    (float("inf"), 0.45),
])
async def test_publish_sigma_hit_confidence_is_always_numeric(
        raw, expected, monkeypatch):
    """confidence 必须以**有限数值**上网。

    消费端会直接 ``float()``；非数值会让整条告警处理抛异常，
    NaN 更阴 —— 所有比较都为 False，策略永不匹配且不报错。
    """
    import json as _json

    from kafka_producer import kafka_producer

    sent = {}

    async def fake_send(topic, key, value, headers=None):
        sent["body"] = _json.loads(value)

    monkeypatch.setattr(kafka_producer, "_started", True, raising=False)
    monkeypatch.setattr(kafka_producer, "_send_bounded", fake_send)

    await kafka_producer.publish_sigma_hit(
        {"src_ip": "1.1.1.1", "rule_id": "SIG-001",
         "threshold": 5, "confidence": raw})

    c = sent["body"]["confidence"]
    assert isinstance(c, float) and c == c and abs(c) != float("inf")
    assert c == pytest.approx(expected)


# ══════════════════════════════════════════════════════════════
# 5. 告警消费：阻断门槛由动作派生
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("action", sorted(ENFORCEMENT))
def test_allow_blocking_true_for_enforcement_actions(action):
    allow, got = _allow_blocking_for({"action_recommend": action})
    assert allow is True, f"{action} 应当允许阻断"
    assert got == action


@pytest.mark.parametrize("action", ["alert", "require_confirmation",
                                    "send_alert", "", "   "])
def test_allow_blocking_false_for_non_enforcement_actions(action):
    """非执行类动作 —— 包括**显式声明为空** —— 一律不允许阻断。

    「显式声明为空」与「根本没这个字段」必须区别对待：
    前者是规则作者说了「不要处置」，后者是这条链路不涉及动作判定
    （CEP / 行为基线等其它告警源）。合并两者会让一句空声明放行封禁。
    """
    allow, got = _allow_blocking_for({"action_recommend": action})
    assert allow is False, f"{action!r} 不应允许阻断"
    # 空白/空串归一为 ""，其余原样带回（供日志与 threat_info 留痕）
    assert got == action.strip()


def test_allow_blocking_true_when_field_absent():
    """字段缺失 → 保持既有行为 True（不因本次改动改变其它告警源）。"""
    allow, got = _allow_blocking_for({"severity": "high", "src_ip": "9.9.9.9"})
    assert allow is True
    assert got == ""


def test_allow_blocking_is_fail_safe_when_classification_unavailable(monkeypatch):
    """动作分类不可用时必须 fail-safe（不阻断），而不是 fail-open。

    fail-open 意味着「导入失败 = 全量放行封禁」，一次依赖故障就会
    把所有规则声明的执行动作一次性打开。
    """
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name == "sigma_engine.engine":
            raise ImportError("boom")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    allow, got = _allow_blocking_for({"action_recommend": "block_ip"})
    assert allow is False, "分类不了却放行阻断 —— 这是 fail-open"
    assert got == "block_ip"


# ══════════════════════════════════════════════════════════════
# 4. Flink 窗口：静态源码断言（非编译）
# ══════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════
# 4b. Flink 作业真编译（本轮新增）
# ══════════════════════════════════════════════════════════════

#: 找不到 mvn 就跳过而不是失败 —— CI/开发机上没装 Maven 不该红。
#: 但**曾经编不过**这件事必须被记住，所以单独有一个
#: 「本地仓库里有依赖却编不过」的硬失败分支。
MVN = shutil.which("mvn") or shutil.which("mvn.cmd")


def _m2_has_flink() -> bool:
    home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or ""
    repo = Path(home) / ".m2" / "repository" / "org" / "apache" / "flink"
    return repo.is_dir()


@pytest.mark.skipif(MVN is None, reason="未安装 Maven，跳过真编译验证")
def test_flink_jobs_compile():
    """``mvn compile`` 必须真的通过，且产出本作业的 class。

    ## 为什么必须是编译而不是源码字符串匹配

    源码断言只能回答「字段名还在不在」。它回答不了：
    类型写错、`cf.asDouble()` 不存在、`m.put` 的 Map 泛型不匹配 ——
    这些都是**只有编译才能发现**的错误，而它们会让整条封禁链在
    部署时直接起不来。

    ## 为什么用 -o（离线）

    ``-o`` 让 Maven 只用本地仓库。首次解析依赖需要联网且很慢
    （本轮实测拉了约 600 个 jar / 266MB）；一旦本地仓库有了依赖，
    离线编译只要几秒。代价是换台没缓存的机器会因缺依赖而失败 ——
    那时删掉 ``-o`` 重跑一次即可，会自动补齐缓存。

    ## 编译整个模块而不是只编这一个文件

    只编单文件会漏掉跨文件的类型不一致（例如 ``KafkaConfig`` 的常量
    改名）。整模块编译才是部署时会发生的那件事。
    """
    proj = Path(tempfile.mkdtemp(prefix="flinkjobs-"))
    try:
        shutil.copytree(
            FLINK_DIR / "src", proj / "src",
            ignore=shutil.ignore_patterns("target"))
        shutil.copy2(FLINK_DIR / "pom.xml", proj / "pom.xml")

        cmd = [MVN, "-B", "-o", "-DskipTests", "compile"]
        proc = subprocess.run(
            cmd, cwd=str(proj), capture_output=True, text=True, timeout=900)

        if proc.returncode != 0 and not _m2_has_flink():
            pytest.skip(
                "Maven 本地仓库没有 Flink 依赖，离线编译无法进行；"
                "联网重跑一次（去掉 -o）即可补齐缓存后启用本测试。\n"
                f"输出尾部:\n{proc.stdout[-800:]}")

        assert proc.returncode == 0, (
            "Flink 作业编译失败 —— 本轮对 SigmaThresholdAggregationJob 的"
            "改动没有通过 javac。\n"
            f"{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}")

        classes = proj / "target" / "classes" / "com" / "soc" / "job"
        for name in ("SigmaThresholdAggregationJob",
                     "SigmaThresholdAggregationJob$SigmaHit",
                     "SigmaThresholdAggregationJob$ThresholdWindowFunction"):
            assert (classes / f"{name}.class").is_file(), \
                f"编译通过但没有产出 {name}.class"
    finally:
        shutil.rmtree(proj, ignore_errors=True)


# ══════════════════════════════════════════════════════════════
# 4a. Flink 窗口：源码字段断言（补充，定位用）
# ══════════════════════════════════════════════════════════════

def test_flink_job_source_is_present():
    """先确认这条静态断言真的在断言一个存在的文件。

    路径写错时，`read_text()` 会抛 FileNotFoundError 而看起来像
    「断言失败」，两种问题必须能区分开 —— 否则会把改路径当成改逻辑。
    """
    assert FLINK_JOB.is_file(), f"Flink 作业源码不在预期位置: {FLINK_JOB}"
    src = FLINK_JOB.read_text(encoding="utf-8")
    assert "SigmaThresholdAggregationJob" in src


@pytest.mark.parametrize("token, why", [
    ('n.get("action_recommend")', "POJO 必须解析动作字段"),
    ('n.get("severity")', "POJO 必须解析严重度字段"),
    ('n.get("attack_type")', "POJO 必须解析攻击类型字段"),
    ('n.get("confidence")', "POJO 必须解析置信度字段"),
    ('m.put("action_recommend"', "告警必须带出动作字段"),
    ('m.put("confidence"', "告警必须带出置信度，否则消费端实算 0.0 匹配不到策略"),
    ('m.put("alertType"', "必须发消费端真正读的 alertType"),
    ('m.put("eventType"', "必须发 eventType，否则 threat_type 退化成 UNKNOWN"),
    ('m.put("reasons"', "必须带出 reasons，供复盘与人工核对"),
])
def test_flink_window_emits_action_fields(token, why):
    """窗口输出必须带上动作/严重度/置信度，且字段名与消费端对得上。

    ⚠️ 这是**源码字符串断言**，保留是因为它比编译/运行更省、且能直接
    指出「少了哪个字段」。它挡不住逻辑错误 —— 4a 的这一段曾经全绿，
    而当时 ``worseAction`` 早已被改成「取最后一条」、``severity``
    仍硬编码 ``"high"``。真执行验证见 4c。
    """
    src = FLINK_JOB.read_text(encoding="utf-8")
    assert token in src, f"Flink 聚合窗口缺少 {token} —— {why}"


def test_consumer_reads_confidence_not_only_anomaly_score():
    """消费端必须 ``anomalyScore or confidence``，不能只读前者。

    只读 ``anomalyScore`` 是第 6 层断链的直接原因：Sigma 聚合告警
    没有这个字段 → 置信度实算 0.0 → 策略门槛永不满足。
    """
    src = (Path(__file__).resolve().parents[1] / "kafka_consumer.py").read_text(
        encoding="utf-8")
    assert 'alert.get("anomalyScore") or alert.get("confidence")' in src, \
        "消费端未从 confidence 回退取置信度"


# ══════════════════════════════════════════════════════════════
# 6. 端到端：聚合告警真的能匹配到带 block_ip 的策略
# ══════════════════════════════════════════════════════════════

def _simulated_aggregation_alert(confidence: float) -> dict:
    """按 Flink 作业的输出契约构造一条聚合告警（字段名与 Java 侧一致）。"""
    return {
        "source": "sigma_aggregation",
        "rule_id": "SIG-001", "src_ip": "10.1.2.3",
        "count": 6, "threshold": 5,
        "window_start": 1, "window_end": 2,
        "severity": "high", "type": "SIGMA_AGGREGATE",
        "alertType": "SIGMA_AGGREGATE",
        "eventType": "brute_force",
        "action_recommend": "block_ip",
        "confidence": confidence,
        "reasons": ["sigma_aggregate:SIG-001", "count=6 threshold=5"],
    }


def test_aggregation_alert_reaches_block_ip_policy():
    """端到端：一条合法的聚合告警必须匹配到带 ``block_ip`` 的策略。

    前面每条断言都在测「某一层带对了字段」，这条测的是**合起来有没有用**。
    第 5 层修完时它就已经是红的 —— 动作和 allow_blocking 都对，
    但置信度 0.0 让策略匹配返回 ``NO_ACTION``，照样不封禁。

    ⚠️ 本测试用 Python 复刻了「消费端取置信度 + 策略匹配」这段逻辑，
    与 Flink 作业无关；Flink 那一侧仍是源码静态断言。
    """
    from correlation_engine import infer_threat_classification
    from response_engine.response_policies import policy_engine

    alert = _simulated_aggregation_alert(0.85)

    # 复刻 _handle_alert 的置信度取法
    score = float(alert.get("anomalyScore") or alert.get("confidence") or 0.0)
    allow_blocking, action = _allow_blocking_for(alert)
    leaf, category = infer_threat_classification(alert.get("eventType", ""))

    assert action == "block_ip" and allow_blocking is True
    assert leaf == "BRUTE_FORCE", f"事件名未被识别为暴力破解: {leaf!r}"

    m = policy_engine.match(threat_type=leaf, category=category,
                            confidence=min(1.0, score * 1.2),
                            severity=alert["severity"])
    acts = [(a.get("name") or a.get("action"))
            for a in (getattr(m, "actions", None) or [])]
    assert "block_ip" in acts, (
        f"聚合告警未匹配到含 block_ip 的策略（match_status="
        f"{getattr(m, 'match_status', '?')}）—— 封禁链在策略匹配处断开")


def test_aggregation_alert_without_confidence_matches_nothing():
    """对照组：没有 confidence 的旧版聚合告警**确实**匹配不到策略。

    这条是上面那条的**反向证明**。没有它，「能封禁」可能是因为别的什么
    宽松改动导致的，而不是真的修好了置信度这一层。
    """
    from correlation_engine import infer_threat_classification
    from response_engine.response_policies import policy_engine

    alert = _simulated_aggregation_alert(0.85)
    del alert["confidence"]          # 还原成修复前的 Flink 输出

    score = float(alert.get("anomalyScore") or alert.get("confidence") or 0.0)
    leaf, category = infer_threat_classification(alert.get("eventType", ""))
    m = policy_engine.match(threat_type=leaf, category=category,
                            confidence=min(1.0, score * 1.2),
                            severity=alert["severity"])
    acts = [(a.get("name") or a.get("action"))
            for a in (getattr(m, "actions", None) or [])]
    assert score == 0.0
    assert "block_ip" not in acts, \
        "缺 confidence 却仍匹配到封禁策略 —— min_confidence 门槛可能已失效"


def test_alert_only_action_is_filtered_when_blocking_denied():
    """``allow_blocking=False`` 时策略动作被过滤，只剩 send_alert。

    这是双轨门槛本身的行为，钉在这里是为了确认「降级」是真的在起作用：
    良性聚合告警走到这里时不能留下 block_ip。
    """
    from response_engine.response_orchestrator import ALERT_ONLY_ACTIONS

    assert ALERT_ONLY_ACTIONS == frozenset({"send_alert"})
    allow_blocking, action = _allow_blocking_for(
        _simulated_aggregation_alert(0.85) | {"action_recommend": "alert"})
    assert action == "alert" and allow_blocking is False


def test_flink_window_no_longer_hardcodes_severity():
    """禁止把 severity 硬编码成 "high"。

    硬编码意味着规则声明的严重度在聚合边界上被改写：一条
    ``x-soc-severity: medium`` 的聚合规则超阈值后会被当成高危送去
    响应引擎。这是「规则意图丢失」的典型形态，且不会报任何错。
    """
    src = FLINK_JOB.read_text(encoding="utf-8")
    assert not re.search(r'm\.put\(\s*"severity"\s*,\s*"high"\s*\)', src), \
        "severity 仍被硬编码为 high，规则声明的严重度会被改写"


def test_flink_window_requires_positive_threshold():
    """threshold<=0 时不得当成「计数 1 就超阈值」。

    ``threshold=0`` 配任何比较符都容易退化成单事件告警 ——
    恰好是本作业存在的意义所反对的。P0-1 之后比较符由规则声明
    （op/'>'/'>='/「==»），但「阈值必须为正」这道防退化闸门必须仍在,
    且按 op 的比较收敛在 thresholdMet 一个入口里, 便于真执行测试覆盖。
    """
    src = FLINK_JOB.read_text(encoding="utf-8")
    assert "threshold > 0" in src, \
        "threshold=0 时会立刻告警（退化成单事件），需显式要求阈值 > 0"
    assert "thresholdMet" in src, \
        "阈值比较必须收敛在 thresholdMet 单一入口（按规则声明的 op 比较）"


def test_flink_window_picks_worst_action_in_window():
    """同一窗口内多条命中要取最严的声明动作。

    同一 (srcIp, ruleId, 5m) 窗口里的候选来自同一条规则，动作本应一致；
    但规则可能被热更新（learn_loop 支持在线改 action_recommend），
    窗口内新旧动作可能并存。取任意一条会让处置结果依赖到达顺序。
    """
    src = FLINK_JOB.read_text(encoding="utf-8")
    assert "worseAction" in src and "worseSeverity" in src, \
        "窗口内未按最严动作/严重度归并，处置结果会依赖消息到达顺序"


# ══════════════════════════════════════════════════════════════
# 4c. Flink 窗口：进程外**真执行**（本轮新增）
# ══════════════════════════════════════════════════════════════
#
# 上面 4a 是源码字符串断言，4b 是「能编译」。两者都还有同一个洞：
#
#   它们回答不了「阈值比较方向对不对」「window 内取最严动作真的取了吗」
#   「输出 JSON 里的 confidence 是不是真的等于 Python 生产者发的那个数」。
#
# 把比较写成 `<=`、把 worseAction 写成"取最后一条"、把 confidence 硬编码成
# 常量 —— 这些在源码断言下全绿，在生产上却分别是「提前告警」「处置结果随
# 到达顺序漂移」「策略门槛恒不满足」。所以这里真的把进程跑起来。

HARNESS_MAIN = "com.soc.job.SigmaWindowHarness"
HARNESS_SOURCES = [
    # 放在 Flink 包下：InternalProcessWindowContext 的构造器是包私有的，
    # 而 ProcessWindowFunction.Context 的外部实例构造器对 javac 不可见，
    # 从外部无法直接子类化。详见该文件的类注释。
    FLINK_DIR / "src" / "test" / "java" / "org" / "apache" / "flink"
    / "streaming" / "runtime" / "operators" / "windowing" / "functions"
    / "SigmaWindowTestContexts.java",
    FLINK_DIR / "src" / "test" / "java" / "com" / "soc" / "job"
    / "SigmaWindowHarness.java",
]
NO_OUTPUT_SENTINEL = "HARNESS_NO_OUTPUT"


def _jdk_bin(name: str):
    """定位 JDK 可执行文件；Windows 上是 .exe，且 PATH 上的 javac 可能来自
    Oracle 的 javapath 转发器（只保证有 javac，不保证同目录有 javap）。"""
    home = os.environ.get("JAVA_HOME")
    if home:
        for cand in (Path(home) / "bin" / name,
                     Path(home) / "bin" / (name + ".exe")):
            if cand.is_file():
                return str(cand)
    return shutil.which(name)


class _WindowRunner:
    """驱动 harness 进程外执行窗口函数。"""

    def __init__(self, classes: Path, classpath: str):
        self._classes = classes
        self._cp = classpath

    def run(self, payloads):
        stdin = "".join(json.dumps(p) + "\n" for p in payloads)
        proc = subprocess.run(
            [_jdk_bin("java"), "-cp", self._cp, HARNESS_MAIN],
            input=stdin, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=180, cwd=str(FLINK_DIR),
        )
        return {
            "alerts": [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()],
            "stderr": proc.stderr,
            "rc": proc.returncode,
        }


@pytest.fixture(scope="module")
def window_runner():
    """编译 flink-jobs + 导出依赖 classpath + 编译并运行 harness。

    一次性构建（module 作用域）：两次 mvn + 一次 javac 只付一次代价。
    """
    java, javac, mvn = _jdk_bin("java"), _jdk_bin("javac"), MVN
    if not java or not javac:
        pytest.skip("未找到 JDK，跳过窗口层真执行验证")
    if mvn is None:
        pytest.skip("未安装 Maven，跳过窗口层真执行验证")

    for src in HARNESS_SOURCES:
        assert src.is_file(), f"窗口 harness 源码缺失: {src}"

    proj = Path(tempfile.mkdtemp(prefix="flinkwin-"))
    try:
        shutil.copytree(FLINK_DIR / "src", proj / "src",
                        ignore=shutil.ignore_patterns("target"))
        shutil.copy2(FLINK_DIR / "pom.xml", proj / "pom.xml")

        def _mvn(args):
            return subprocess.run([mvn, "-B", "-o", *args], cwd=str(proj),
                                  capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=900)

        proc = _mvn(["-DskipTests", "compile"])
        if proc.returncode != 0 and not _m2_has_flink():
            pytest.skip("Maven 本地仓库没有 Flink 依赖，离线编译无法进行。\n"
                        f"{proc.stdout[-800:]}")
        assert proc.returncode == 0, \
            f"Flink 作业编译失败：\n{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}"

        cp_file = proj / "cp.txt"
        proc = _mvn(["-q",
                     "org.apache.maven.plugins:maven-dependency-plugin"
                     ":3.6.1:build-classpath",
                     f"-Dmdep.outputFile={cp_file}"])
        assert cp_file.is_file(), (
            "依赖 classpath 导出失败，窗口层无法真执行。\n"
            f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")

        cp = (cp_file.read_text(encoding="utf-8").strip()
              + os.pathsep + str(proj / "target" / "classes"))
        out_classes = proj / "target" / "test-classes"
        out_classes.mkdir(parents=True, exist_ok=True)

        proc = subprocess.run(
            [javac, "-J-Dsun.stderr.encoding=UTF-8", "-encoding", "UTF-8",
             "-nowarn", "-cp", cp, "-d", str(out_classes),
             *[str(s) for s in HARNESS_SOURCES]],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=300)
        assert proc.returncode == 0, (
            f"窗口 harness 编译失败：\n{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}")

        yield _WindowRunner(
            out_classes, cp + os.pathsep + str(out_classes))
    finally:
        shutil.rmtree(proj, ignore_errors=True)


def _hit(**kw):
    base = {
        "src_ip": "10.0.0.5", "rule_id": "SIG-001", "threshold": 3,
        "timestamp": 1_700_000_000_000, "action_recommend": "block_ip",
        "severity": "high", "attack_type": "brute_force", "confidence": 0.85,
    }
    base.update(kw)
    return base


def _only_alert(res):
    """断言进程正常结束且恰好产出一条告警，返回它。

    显式区分三种失败：进程挂了 / 一条都没出（多半被静默吞掉）/ 出多了。
    """
    assert res["rc"] == 0, f"harness 进程异常退出：\n{res['stderr'][-2000:]}"
    assert NO_OUTPUT_SENTINEL not in res["stderr"], \
        "本该出告警却走到了「无输出」分支 —— 判定条件可能已失效"
    assert len(res["alerts"]) == 1, \
        f"期望恰好 1 条告警，实际 {len(res['alerts'])} 条：{res['alerts']}"
    return res["alerts"][0]


def _no_alert(res):
    assert res["rc"] == 0, f"harness 进程异常退出：\n{res['stderr'][-2000:]}"
    assert not res["alerts"], f"期望不告警，实际产出：{res['alerts']}"
    assert NO_OUTPUT_SENTINEL in res["stderr"], \
        ("无告警时必须留下哨兵，否则「序列化失败被 catch 吞掉」与"
         "「阈值没到」在输出上无法区分")


# ── 先证明这套量具本身是通的 ────────────────────────────────

def test_harness_executes_and_emits_parsable_json(window_runner):
    """冒烟：harness 真的跑起来了，输出是**可解析**的 JSON。

    这条是给后面所有断言上的地基。没有它，「后面全绿」可能只是因为
    harness 根本没跑（例如 classpath 缺件时静默输出空）。
    """
    alert = _only_alert(window_runner.run([_hit()] * 3))
    assert alert["count"] == 3
    assert alert["window_start"] == 0 and alert["window_end"] == 300_000


# ── 阈值比较方向 ────────────────────────────────────────────

def test_window_fires_exactly_at_threshold(window_runner):
    """count == threshold 就要告警（>=，不是 >）。"""
    _only_alert(window_runner.run([_hit(threshold=3)] * 3))


def test_window_quiet_below_threshold(window_runner):
    """count < threshold 不告警。"""
    _no_alert(window_runner.run([_hit(threshold=3)] * 2))


def test_threshold_comparison_is_not_reversed(window_runner):
    """反向证明：count < threshold 绝不能告警。

    只测「到阈值会告警」的话，把 `>=` 写成 `<=`（或写成 count<=threshold）
    也可能同样通过某条用例。这条专治比较方向写反。
    """
    _no_alert(window_runner.run([_hit(threshold=10)] * 3))


def test_zero_threshold_does_not_degrade_to_single_event(window_runner):
    """threshold=0 时**一条也不能告警**。

    这正是本轮修复的第 4 层：backend 没下发阈值（如旧版本）时，
    `count >= 0` 恒真，会把聚合窗口退化成单事件告警 ——
    恰好是本作业存在的意义所反对的。
    """
    res = window_runner.run([_hit(threshold=0)])
    _no_alert(res)
    # 50 条也不行：不能靠「条数少」蒙混过关
    _no_alert(window_runner.run([_hit(threshold=0)] * 50))


# ── 窗口内取最严 ────────────────────────────────────────────

_ACTION_RANK = {"alert": 1, "drop": 3, "require_confirmation": 2,
                "quarantine": 4, "isolate": 4, "deny": 4, "kill": 3,
                "block": 5, "block_ip": 5}


@pytest.mark.parametrize("actions", [
    ("alert", "block_ip"), ("block_ip", "alert"),
    ("require_confirmation", "quarantine", "alert"),
    ("alert", "alert", "drop"),
])
def test_worst_action_wins_regardless_of_order(window_runner, actions):
    """窗口内取**最严**动作，与消息到达顺序无关。

    顺序必须无关：规则可能被热更新（learn_loop 支持在线改
    action_recommend），窗口内新旧动作可能并存。若按"最后一条"或"第一条"
    归并，处置结果会随机漂移 —— 这类 bug 在源码断言下完全看不出来。
    """
    hits = [_hit(action_recommend=a, timestamp=1_700_000_000_000 + i,
                 threshold=len(actions))
            for i, a in enumerate(actions)]
    alert = _only_alert(window_runner.run(hits))
    expected = max(actions, key=lambda a: _ACTION_RANK.get(a, 0))
    assert alert["action_recommend"] == expected, (
        f"动作 {list(actions)} 未归并为最严 {expected}，"
        f"实得 {alert['action_recommend']}")


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@pytest.mark.parametrize("sevs", [
    ("low", "critical"), ("critical", "low"), ("medium", "high", "low"),
])
def test_worst_severity_wins_regardless_of_order(window_runner, sevs):
    """严重度同样按最严归并，且与顺序无关。

    严重度决定消费端走哪档响应策略；取任意一条会让同一起攻击因
    消息到达顺序不同而被分到不同档位。
    """
    hits = [_hit(severity=s, timestamp=1_700_000_000_000 + i,
                 threshold=len(sevs))
            for i, s in enumerate(sevs)]
    alert = _only_alert(window_runner.run(hits))
    expected = max(sevs, key=lambda s: _SEVERITY_RANK.get(s, 0))
    assert alert["severity"] == expected, (
        f"严重度 {list(sevs)} 未归并为最严 {expected}，"
        f"实得 {alert['severity']}")

def test_output_carries_every_field_the_consumer_reads(window_runner):
    """窗口输出必须带齐消费端真正会读的字段。

    字段名错一个，消费端就静默回落到默认值 —— `alertType` 缺失会退化成
    ANOMALY、`confidence` 缺失会实算 0.0，都是「不报错但不工作」。
    """
    alert = _only_alert(window_runner.run([_hit()] * 3))
    assert alert["source"] == "sigma_aggregation"
    assert alert["type"] == alert["alertType"] == "SIGMA_AGGREGATE"
    assert alert["eventType"] == "brute_force"
    assert alert["rule_id"] == "SIG-001" and alert["src_ip"] == "10.0.0.5"
    assert alert["severity"] == "high"
    assert alert["confidence"] == pytest.approx(0.85)
    assert alert["reasons"] == ["sigma_aggregate:SIG-001", "count=3 threshold=3"]


# ── 跨语言契约：Python 生产者 → Java 消费者 ─────────────────

def test_python_producer_payload_reaches_java_intact(window_runner):
    """**真**生产者产出的载荷，被**真**消费者解析后动作/严重度/置信度不变。

    这是本节最有价值的一条：4a 的源码断言是拿 Python 侧的字符串去比对，
    而这里是把 ``_agg_payload`` 的真实输出喂进真实 Java 解析器。
    只要两端有任何一个键名漂移（``action_recommend`` ↔ ``action``），
    这里就会看到默认值而不是声明值 —— 而两边单测都还是绿的。
    """
    payloads = [PySigmaDetector._agg_payload(
        _meta(), {"src_ip": "10.9.9.9", "timestamp": 1_700_000_000_000},
        {"threshold": 3})] * 3

    alert = _only_alert(window_runner.run(payloads))
    assert alert["action_recommend"] == "block_ip", \
        "Java 侧没解析到 action_recommend（键名漂移或被丢弃）"
    assert alert["severity"] == "high"
    assert alert["eventType"] == "brute_force"
    assert alert["confidence"] == pytest.approx(SIGMA_CONFIDENCE_NUM["high"])


def test_shadow_mode_producer_payload_reaches_java_as_alert(window_runner):
    """灰度规则的生产者载荷必须以 alert 到达 Java 侧。

    ``_agg_payload`` 对 shadow_mode 强制降级为 alert。若这一层失效，
    灰度期就会真的开始处置 —— 而它只在端到端跑一遍时才看得见。
    """
    payloads = [PySigmaDetector._agg_payload(
        _meta(shadow_mode=True), {"src_ip": "10.9.9.9"}, {"threshold": 3})] * 3

    alert = _only_alert(window_runner.run(payloads))
    assert alert["action_recommend"] == "alert"


def test_absent_confidence_falls_back_to_floor_not_ceiling(window_runner):
    """载荷缺 confidence 时必须落到**下限** 0.45，不能是 1.0 或 0。

    这是 ``x or 默认值`` 那类坑在 Java 侧的镜像：把「没有置信度」
    记成「完全可信」会让强制人审/自动封禁的门槛形同虚设。
    """
    payload = _hit()
    del payload["confidence"]
    alert = _only_alert(window_runner.run([payload] * 3))
    assert alert["confidence"] == pytest.approx(0.45)


def test_missing_optional_fields_use_documented_defaults(window_runner):
    """动作/严重度/攻击类型缺失时用文档化的默认值。

    这里同时钉住「默认值到底是什么」—— 之前没有任何测试说明过它们，
    改一个默认值不会有任何测试变红，而生产上处置结果会跟着变。
    """
    payload = _hit()
    for k in ("action_recommend", "severity", "attack_type"):
        del payload[k]
    alert = _only_alert(window_runner.run([payload] * 3))
    assert alert["action_recommend"] == "alert"
    assert alert["severity"] == "medium"
    assert alert["eventType"] == "custom"


# ══════════════════════════════════════════════════════════════
# 7. P0-1: 阈值语义契约（op / timeframe 随候选下发, Flink 按声明比较/建窗）
# ══════════════════════════════════════════════════════════════
#
# 修复前候选只带 threshold: Flink 硬编码 count >= threshold 和 5m 窗口。
# SIG-001 (op '>', threshold 5) 第 5 条就告警(应为第 6 条);
# SIG-007 (op '>', threshold 1) 第 1 条就告警 —— "单事件不得处置"
# 的保护在聚合层退化。下面从载荷(2)→白名单(3)→真执行(4c)逐层钉住。

def test_agg_payload_carries_full_threshold_semantics():
    """载荷必须带 op/func/field/timeframe/timeframe_ms —— 缺一个 Flink 就回退硬编码。"""
    ev = {"src_ip": "10.1.2.3", "dst_ip": "10.0.0.9", "eventId": "evt-42",
          "timestamp": 1_700_000_000_000}
    p = PySigmaDetector._agg_payload(_meta(), ev, {
        "func": "count", "field": "src_ip", "op": ">",
        "threshold": 5, "timeframe": "5m",
    })
    assert p["op"] == ">"
    assert p["func"] == "count" and p["field"] == "src_ip"
    assert p["timeframe"] == "5m"
    assert p["timeframe_ms"] == 300_000
    assert p["event_id"] == "evt-42"
    assert p["dst_ip"] == "10.0.0.9"
    assert p["threshold"] == 5


def test_agg_payload_rule_version_present_and_stable():
    """rule_version 是稳定指纹 —— 同一规则内容两算必须一致。"""
    agg = {"func": "count", "field": "src_ip", "op": ">",
           "threshold": 5, "timeframe": "5m"}
    p1 = PySigmaDetector._agg_payload(_meta(), {"src_ip": "1.1.1.1"}, agg)
    p2 = PySigmaDetector._agg_payload(_meta(), {"src_ip": "2.2.2.2"}, agg)
    assert p1["rule_version"], "rule_version 缺失, 聚合告警无法定版复盘"
    assert p1["rule_version"] == p2["rule_version"], "rule_version 随事件漂移"


@pytest.mark.parametrize("declared,expected_ms", [
    ("5m", 300_000), ("1m", 60_000), ("30s", 30_000), ("1h", 3_600_000),
    (300, 300_000),          # Sigma 规范: 裸数字按秒
    ("bogus", 300_000),      # 解析不了 → 默认 5m（与 Flink 默认一致）
    (None, 300_000), ("", 300_000),
])
def test_agg_payload_timeframe_normalization(declared, expected_ms):
    p = PySigmaDetector._agg_payload(
        _meta(), {"src_ip": "1.1.1.1"},
        {"op": ">", "threshold": 5, "timeframe": declared})
    assert p["timeframe_ms"] == expected_ms


@pytest.mark.asyncio
async def test_publish_sigma_hit_passes_threshold_semantics(monkeypatch):
    """producer 白名单必须放行阈值语义字段。

    白名单漏一个键, op/timeframe 就在 Kafka 边界上被剥掉,
    Flink 悄悄回退 ">= / 5m" 硬编码 —— 与「上游没发」不可区分。
    """
    import json as _json

    from kafka_producer import kafka_producer

    sent = {}

    async def fake_send(topic, key, value, headers=None):
        sent["body"] = _json.loads(value)

    monkeypatch.setattr(kafka_producer, "_started", True, raising=False)
    monkeypatch.setattr(kafka_producer, "_send_bounded", fake_send)

    await kafka_producer.publish_sigma_hit({
        "src_ip": "10.1.2.3", "rule_id": "SIG-001", "threshold": 5,
        "timestamp": 1_700_000_000_000, "action_recommend": "block_ip",
        "severity": "high", "attack_type": "brute_force", "confidence": 0.85,
        "op": ">", "func": "count", "field": "src_ip",
        "timeframe": "5m", "timeframe_ms": 300_000,
        "rule_version": "a1b2c3d4", "event_id": "evt-42", "dst_ip": "10.0.0.9",
        "__internal_debug": "should_not_leak",
    })

    body = sent["body"]
    assert body["op"] == ">"
    assert body["timeframe"] == "5m" and body["timeframe_ms"] == 300_000
    assert body["rule_version"] == "a1b2c3d4"
    assert body["event_id"] == "evt-42" and body["dst_ip"] == "10.0.0.9"
    assert "__internal_debug" not in body, "白名单失效：非约定字段被透传"


@pytest.mark.asyncio
async def test_publish_sigma_hit_semantic_defaults_when_absent(monkeypatch):
    """上游(旧版本)没带语义字段时, 落到与 Flink 回退一致的默认值。"""
    import json as _json

    from kafka_producer import kafka_producer

    sent = {}

    async def fake_send(topic, key, value, headers=None):
        sent["body"] = _json.loads(value)

    monkeypatch.setattr(kafka_producer, "_started", True, raising=False)
    monkeypatch.setattr(kafka_producer, "_send_bounded", fake_send)

    await kafka_producer.publish_sigma_hit(
        {"src_ip": "1.1.1.1", "rule_id": "SIG-001", "threshold": 5})
    body = sent["body"]
    assert body["op"] == ">="
    assert body["func"] == "count" and body["field"] == "src_ip"
    assert body["timeframe_ms"] == 0  # 旧候选不臆造窗口, Flink 回退默认 5m


# ── 阈值语义真执行（SIG-001 / SIG-007 修复验收口径）──────────

def test_sig001_fires_at_six_not_five(window_runner):
    """SIG-001 (op '>', threshold 5): 第 5 条**不**告警, 第 6 条告警。

    这是 P0-1 的直接验收标准 —— 修复前 `count >= 5` 在第 5 条就触发。
    """
    _no_alert(window_runner.run([_hit(op=">", threshold=5)] * 5))
    alert = _only_alert(window_runner.run([_hit(op=">", threshold=5)] * 6))
    assert alert["count"] == 6 and alert["op"] == ">"


def test_sig007_second_event_alerts_not_first(window_runner):
    """SIG-007 (op '>', threshold 1): 第 1 条**不**告警, 第 2 条告警。

    修复前 `count >= 1` 恒真, 聚合窗口退化成单事件告警,
    "单事件不得处置"的保护随之失效。
    """
    _no_alert(window_runner.run([_hit(op=">", threshold=1)] * 1))
    alert = _only_alert(window_runner.run([_hit(op=">", threshold=1)] * 2))
    assert alert["count"] == 2


def test_eq_op_fires_only_at_exact_count(window_runner):
    """op '==' 只在计数**恰好等于**阈值时告警（多一条少一条都不告警）。"""
    _no_alert(window_runner.run([_hit(op="==", threshold=3)] * 2))
    _only_alert(window_runner.run([_hit(op="==", threshold=3)] * 3))
    _no_alert(window_runner.run([_hit(op="==", threshold=3)] * 4))


def test_strict_op_never_fires_below_threshold_plus_one(window_runner):
    """反向钉: op '>' 在 count <= threshold 时**绝不**告警（比较方向写反会挂）。"""
    _no_alert(window_runner.run([_hit(op=">", threshold=3)] * 1))
    _no_alert(window_runner.run([_hit(op=">", threshold=3)] * 3))


def test_unrecognized_op_falls_back_conservative(window_runner):
    """认不出的比较符必须回退 ">=", 且 '<' 语义不得按"少于阈值"触发处置。

    回退方向是安全边界: 落到 ">=" 最坏是语义口径偏紧;
    回落到 '<' 会让 count=1 就触发 —— 单事件处置的口子重新打开。
    """
    _only_alert(window_runner.run([_hit(op="!!", threshold=3)] * 3))
    _no_alert(window_runner.run([_hit(op="<", threshold=3)] * 1))
    _no_alert(window_runner.run([_hit(op="<", threshold=3)] * 2))


def test_missing_op_keeps_legacy_gte_semantics(window_runner):
    """旧版本候选（不带 op）保持 ">= " 语义 —— 部署顺序无关, 前后兼容。"""
    _only_alert(window_runner.run([_hit()] * 3))


def test_java_side_parses_semantic_fields_from_payload(window_runner):
    """Java 侧解析语义字段后**原样带回**告警（跨语言键名不漂移）。

    op/func/field/rule_version 在告警里缺失/改名, 下游与人复盘时
    就答不了「count 是按什么语义算出来的」。
    """
    payload = _hit(op=">", threshold=2)
    payload["func"] = "count"
    payload["field"] = "src_ip"
    payload["rule_version"] = "a1b2c3d4"
    payload["event_id"] = "evt-7"
    payload["dst_ip"] = "10.0.0.9"
    alert = _only_alert(window_runner.run([payload] * 3))
    assert alert["op"] == ">"
    assert alert["func"] == "count" and alert["field"] == "src_ip"
    assert alert["rule_version"] == "a1b2c3d4"
    assert alert["dst_ip"] == "10.0.0.9"

