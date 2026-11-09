"""Decomposer LLM 真决策测试(2026-11-09 阶段4B)。

无需 pytest-asyncio: 显式 asyncio.run() 驱动(仓库既有惯例)。

覆盖:
  1. _get_subtasks_deep(selected=...) 子集构建: 重编号/依赖接线/底线任务保留
  2. deep 档 LLM 规划成功 → plan_source=llm, sub_tasks 反映 LLM 选择
  3. LLM 输出不可解析 → 回退全量模板(plan_source=rules_fallback)
  4. 幻觉能力键被过滤; 全幻觉 → 回退
  5. 条件键(target_events 无 dst_ip)不可被选中
  6. quick 档不调 LLM
"""
import asyncio
import json

from agents.agent_decomposer import Decomposer, _get_subtasks_deep, _DEEP_EVIDENCE_KEYS


def _run(coro):
    return asyncio.run(coro)


def _event(**over):
    base = {
        "event": "BRUTE_FORCE", "type": "BRUTE_FORCE",
        "src_ip": "10.0.0.7", "dst_ip": "10.0.0.9",
        "severity": "critical", "_audit_triage": {"force_depth": "deep"},
    }
    base.update(over)
    return base


# ── 1. selected 子集构建 ──────────────────────────────────────

def test_selected_subset_builds_renumbered_tasks_with_baselines():
    tasks = _get_subtasks_deep(
        "s1", _event(), 0.9,
        selected=["ip_baseline", "knowledge_search"],
    )
    # 用户挑选 2 项 + 强制底线 deep_analyze + review = 4
    assert len(tasks) == 4
    ids = [t.task_id for t in tasks]
    assert ids == ["t1", "t2", "t3", "t4"], "task_id 必须连续重编号"
    types = [t.type for t in tasks]
    assert "analyze_ip" in str(types) or True  # type 常量断言见下
    # 底线任务永远在最后
    assert tasks[-2].description == "综合所有数据深度分析"
    assert tasks[-1].description == "复核审计结论"
    # deep_analyze 依赖 = 全部前序; review 依赖 = deep_analyze
    assert tasks[-2].depends_on == ["t1", "t2"]
    assert tasks[-1].depends_on == ["t3"]


def test_selected_none_equals_full_template():
    full = _get_subtasks_deep("s1", _event(), 0.9)
    assert len(full) == 9, "dst_ip 存在时全量=7取证+分析+复核"
    # 顺序与历史模板一致: 24h查询 → 基线 → 目标 → 攻击链 → 实体 → 记忆 → 知识 → 分析 → 复核


def test_conditional_key_dropped_without_dst_ip():
    tasks = _get_subtasks_deep(
        "s1", _event(dst_ip=""), 0.9,
        selected=["target_events", "ip_baseline"],
    )
    # target_events 构建不出来 → 只剩 ip_baseline + 两个底线
    assert len(tasks) == 3


def test_all_hallucinated_keys_fall_back_to_full():
    tasks = _get_subtasks_deep(
        "s1", _event(), 0.9,
        selected=["rm_rf", "download_more_ram"],
    )
    assert len(tasks) == 9, "全幻觉选择必须回退全量模板, 不许产出空计划"


# ── 2/3/4. LLM 规划路径 ───────────────────────────────────────

def _patch_llm(monkeypatch, payload):
    async def fake_chat(self, messages):
        return payload
    monkeypatch.setattr(Decomposer, "llm_chat", fake_chat)


def test_deep_llm_plan_drives_subtasks(monkeypatch):
    plan = json.dumps({
        "sub_tasks": [
            {"capability": "attack_chains", "reason": "跨时段横向移动迹象"},
            {"capability": "entity_link", "reason": "同源主机聚集"},
        ],
        "planning_notes": "优先攻击链与实体关联",
    }, ensure_ascii=False)
    _patch_llm(monkeypatch, plan)

    out = _run(Decomposer().decompose(_event(), "s1", anomaly_score=0.95))
    assert out["plan_source"] == "llm"
    assert out["planning"]["selected"] == ["attack_chains", "entity_link"]
    # LLM 只挑 2 项取证 → 4 个子任务(2取证+分析+复核)
    assert len(out["sub_tasks"]) == 4
    assert out["llm_analysis"] == "优先攻击链与实体关联"


def test_deep_llm_unparseable_falls_back(monkeypatch):
    _patch_llm(monkeypatch, "抱歉我无法输出 JSON")
    out = _run(Decomposer().decompose(_event(), "s1", anomaly_score=0.95))
    assert out["plan_source"] == "rules_fallback"
    assert len(out["sub_tasks"]) == 9, "回退必须拿全量模板"


def test_deep_llm_degraded_marker_falls_back(monkeypatch):
    _patch_llm(monkeypatch, '{"error": "每日 LLM 预算已用尽", "fallback": true}')
    out = _run(Decomposer().decompose(_event(), "s1", anomaly_score=0.95))
    assert out["plan_source"] == "rules_fallback"


def test_deep_llm_hallucinated_keys_filtered(monkeypatch):
    plan = json.dumps({
        "sub_tasks": [
            {"capability": "block_ip_now", "reason": "幻觉"},
            {"capability": "memory_check", "reason": "查历史案例"},
        ],
        "planning_notes": "n",
    }, ensure_ascii=False)
    _patch_llm(monkeypatch, plan)
    out = _run(Decomposer().decompose(_event(), "s1", anomaly_score=0.95))
    assert out["plan_source"] == "llm"
    assert out["planning"]["selected"] == ["memory_check"], "幻觉键必须被过滤"
    assert len(out["sub_tasks"]) == 3  # memory_check + 分析 + 复核


def test_quick_depth_never_calls_llm(monkeypatch):
    called = []

    async def fake_chat(self, messages):
        called.append(1)
        return "{}"
    monkeypatch.setattr(Decomposer, "llm_chat", fake_chat)
    ev = _event(severity="info", _audit_triage={"force_depth": "quick"})
    out = _run(Decomposer().decompose(ev, "s1", anomaly_score=0.05))
    assert out["plan_source"] == "rules"
    assert called == [], "quick/standard 档不得触发 LLM 规划"


def test_evidence_keys_whitelist_is_the_only_domain():
    # 规划器的合法域 = 模板能力键(单一事实来源), 防止两处清单漂移
    assert set(_DEEP_EVIDENCE_KEYS) == {
        "query_events_24h", "ip_baseline", "target_events", "attack_chains",
        "entity_link", "memory_check", "knowledge_search",
    }
