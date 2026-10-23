"""
P3: 行为检测权重与阈值的评估流程。

与 :mod:`eval_datasets.evaluate_grounding` 同构，评估对象换成
``BehaviorDetector`` 的 action 判定。

关键结构事实（决定了阈值扫描必须怎么扫）：

    ``_score_locked`` 里的门控**不只看加权分**：
        is_anomaly = 加权分 >= warn_threshold  或  任一维度 >= STRONG_DIM_THRESHOLD
        action=deny  = 加权分 >= deny_threshold  或  任一维度 >= deny_threshold
        action=confirm= 加权分 >= confirm_threshold 或 任一维度 >= confirm_threshold

    所以「阈值」与「单维度高分」是两条并行的触发路径，
    只扫加权分阈值会得出偏乐观的结论。扫描必须把 max_dim 一并考虑。

    ⚠️ ``STRONG_DIM_THRESHOLD`` 从**生产模块**导入，不在此处重写一个 0.8。
    历史上这个门限在生产与评估器里各有若干份字面量，改一处忘另一处
    就会让评估器扫的判据与真检测器不是同一套（§9.66）。

⚠️ 与 Grounding 评估器同一条纪律：档位判定若在此处重算而不在真检测器上
验证，扫出来的就是自说自话。这里用 ``_action_for`` 并**强制**它在真阈值上
与真 ``BehaviorDetector`` 逐条比对，不一致直接抛错。
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field

from eval_datasets.behavior_cases import scenarios
from mcp_guard.behavior_detector import STRONG_DIM_THRESHOLD, BehaviorDetector
from mcp_guard.call_record import ToolCallRecord

ACTIONS = ("logged", "confirm", "deny")

#: **出厂默认值**（config.py 里的声明值）。它们是「文档/标定集所依据的基线」，
#: **不是**「生产当前正在用的值」—— 后者见 :func:`current_thresholds`。
DEFAULT_WARN = 0.6
DEFAULT_CONFIRM = 0.8
DEFAULT_DENY = 0.95


def current_thresholds() -> tuple:
    """生产**当前实际在用**的三个阈值，从生产模块读取（单一真源）。

    ## 为什么必须有这个函数

    评估器若把阈值当常量写死，就会与生产**脱钩**：
    运维改了 `tool_signature_confirm_threshold` 之后，
    评估器算出的「当前阈值」「上侧余量」仍然是相对于**旧基线**的。

    实测（§9.67）：把 confirm 配成 0.9、warn 配成 0.5、deny 配成 0.97 后，
    评估器的 `DEFAULT_*` 仍是 0.6/0.8/0.95；
    于是 ``_assert_reimplementation_matches`` 直接抛错
    （「真实现=logged 重实现=confirm」）——
    **评估器扫的不是生产正在跑的那套阈值**。

    ⇒ 所有「当前值」语义一律走这里，不再各自写死。
    """
    det = BehaviorDetector()
    return (det.warn_threshold(), det.confirm_threshold(), det.deny_threshold())


def _record(spec: dict) -> ToolCallRecord:
    return ToolCallRecord.from_kwargs(
        user_role=spec.get("caller_role", ""),
        tool_name=spec["tool_name"],
        arguments=spec.get("arguments"),
        decision=spec.get("decision", ""),
        reason=spec.get("reason", ""),
        caller=spec.get("caller", ""),
        source=spec.get("source", ""),
        tool_match_method=spec.get("tool_match_method", "exact"),
        ts=spec.get("ts"),
    )


@dataclass
class ScenarioResult:
    scenario_id: str
    expect: str
    got: str
    score: float | None
    max_dim: float
    dimensions: dict = field(default_factory=dict)
    reasons: list = field(default_factory=list)
    mode: str = ""
    known_gap: str | None = None

    @property
    def hit(self) -> bool:
        return self.expect == self.got

    @property
    def counted(self) -> bool:
        return self.known_gap is None


@dataclass
class EvalReport:
    results: list[ScenarioResult]

    @property
    def confusion(self) -> dict:
        return {
            want: {
                got: sum(1 for r in self.results if r.expect == want and r.got == got)
                for got in ACTIONS
            }
            for want in ACTIONS
        }

    @property
    def per_class(self) -> dict:
        scored = [r for r in self.results if r.counted]
        out = {}
        for label in ACTIONS:
            tp = sum(1 for r in scored if r.expect == label and r.got == label)
            fp = sum(1 for r in scored if r.expect != label and r.got == label)
            fn = sum(1 for r in scored if r.expect == label and r.got != label)
            prec = tp / (tp + fp) if (tp + fp) else None
            rec = tp / (tp + fn) if (tp + fn) else None
            f1 = (2 * prec * rec / (prec + rec)
                  if prec and rec and (prec + rec) else None)
            # 整改方案 §十三 验收要求「分别报告各类检测器的 Precision、Recall、
            # **误报率与漏报率**」。这里补上后两个率值 —— 此前只有 P/R/F1。
            #
            # 口径与 `evaluate_detection.py` 一致：逐类(one-vs-rest)把当前
            # 处置档位当正类。
            #   TN = 计入准确率的样本总数 − tp − fp − fn
            #        分母用 `counted`（排除 known_gap）。已知检不出的场景既不是
            #        误报也不是漏报 —— 把它算成 TN 会虚高特异度，算成 FN 会虚高
            #        漏报率，这正是 `evaluate_detection.py` 文档里写明的坑。
            #   FPR = FP / (FP + TN)
            #   FNR = FN / (FN + TP) = 1 − recall
            tn = len(scored) - tp - fp - fn
            fpr = fp / (fp + tn) if (fp + tn) else None
            fnr = fn / (fn + tp) if (fn + tp) else None
            out[label] = {
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": prec, "recall": rec, "f1": f1,
                "false_positive_rate": fpr, "false_negative_rate": fnr,
            }
        return out

    @property
    def accuracy(self) -> float | None:
        scored = [r for r in self.results if r.counted]
        if not scored:
            return None
        return sum(1 for r in scored if r.hit) / len(scored)

    @property
    def misses(self) -> list:
        return [r for r in self.results if r.counted and not r.hit]

    @property
    def separation(self) -> dict:
        """logged 与「应处置」两组之间的分数间隔。

        known_gap 与不计分的样本不参与 —— 否则间隔会被已知缺陷永久压成 0，
        指标就失去了回归检测能力。
        """
        scored = [r for r in self.results if r.counted and r.score is not None]
        quiet = [r.score for r in scored if r.expect == "logged"]
        loud = [r.score for r in scored if r.expect in ("confirm", "deny")]
        return {
            "max_logged": max(quiet) if quiet else None,
            "min_should_act": min(loud) if loud else None,
            "margin": (min(loud) - max(quiet)) if quiet and loud else None,
        }

    @property
    def single_dim_trigger_share(self) -> dict:
        """有多少「应处置」样本是靠单维度高分触发的，而不是加权分。

        这决定了阈值与维度权重各自贡献了多少 —— 若绝大多数靠单维度，
        那么加权阈值其实只在少数组合上起作用。
        """
        scored = [r for r in self.results if r.counted and r.expect in ("confirm", "deny")]
        by_score = 0
        by_dim = 0
        both = 0
        cur_warn, cur_confirm, cur_deny = current_thresholds()
        for r in scored:
            gate = cur_deny if r.expect == "deny" else cur_confirm
            s_hit = r.score is not None and r.score >= gate
            d_hit = r.max_dim >= gate
            if s_hit and d_hit:
                both += 1
            elif s_hit:
                by_score += 1
            elif d_hit:
                by_dim += 1
        return {"by_score_only": by_score, "by_dim_only": by_dim, "both": both}


# ═══════════════════════════════════════════
# 档位重实现（仅供阈值扫描）
# ═══════════════════════════════════════════

def _action_for(
    score: float | None,
    max_dim: float,
    is_anomaly: bool,
    mode: str,
    warn_t: float,
    confirm_t: float,
    deny_t: float,
) -> str:
    """复刻 ``_score_locked`` 尾部的档位判定。

    注意这里**不能**省略 is_anomaly —— 它由 warn_threshold 决定，
    而 warn 与 confirm 是两个不同的阈值。
    """
    if not is_anomaly:
        return "logged"
    if mode != "shadow":
        if mode == "deny" and (score >= deny_t or max_dim >= deny_t):
            return "deny"
        if mode in ("confirm", "deny") and (
            score >= confirm_t or max_dim >= confirm_t
        ):
            return "confirm"
    return "logged"


def normalization_sensitivity(report: EvalReport) -> dict:
    """已登记缺口「加权分只按实际存在的维度归一」的敏感性分析。

    ``_score_locked`` 的 ``denom`` 只累加**实际存在**维度的权重，
    另一种口径是按全部维度权重归一（缺失维当作 0 分）。
    两者只在「有维度缺失」时不同 —— 四个维度齐全时数值完全一样。

    ⚠️ ``strong`` 与 ``max_dim`` 读的是**原始维度值**，与维度数量无关，
    因此两条单维度触发路径在两种口径下**不变**。
    这点必须说清楚，否则会误以为改归一等于改单维度路径的灵敏度。

    返回每条样本在两种口径下的分数与档位，以及翻转统计。
    """
    from mcp_guard.behavior_detector import DEFAULT_WEIGHTS

    cur_warn, cur_confirm, cur_deny = current_thresholds()
    full_denom = sum(float(w) for w in DEFAULT_WEIGHTS.values())
    rows = []
    for r in report.results:
        present = {k: float(v) for k, v in (r.dimensions or {}).items()
                   if v is not None}
        numer = sum(float(DEFAULT_WEIGHTS.get(k, 0.0)) * v
                    for k, v in present.items())
        alt = (numer / full_denom) if full_denom > 0 else 0.0
        alt = max(0.0, min(1.0, alt))

        alt_anom = (alt >= cur_warn) or r.max_dim >= STRONG_DIM_THRESHOLD
        alt_got = _action_for(
            alt, r.max_dim, alt_anom, r.mode,
            cur_warn, cur_confirm, cur_deny,
        )
        rows.append({
            "scenario_id": r.scenario_id,
            "expect": r.expect,
            "dims_present": sorted(present),
            "n_dims": len(present),
            "max_dim": r.max_dim,
            "score_now": r.score,
            "score_alt": round(alt, 4),
            "got_now": r.got,
            "got_alt": alt_got,
            "flip": alt_got != r.got,
            "counted": r.counted,
            "known_gap": r.known_gap,
        })

    flips = [x for x in rows if x["flip"]]
    affected = [x for x in rows if x["n_dims"] < len(DEFAULT_WEIGHTS)]
    return {
        "full_denom": full_denom,
        "n": len(rows),
        "n_missing_dims": len(affected),
        "n_flipped": len(flips),
        "flips": flips,
        "rows": rows,
    }


def _assert_reimplementation_matches(report: EvalReport) -> None:
    cur_warn, cur_confirm, cur_deny = current_thresholds()
    for r in report.results:
        is_anom = (r.score is not None and r.score >= cur_warn) or r.max_dim >= STRONG_DIM_THRESHOLD
        got = _action_for(
            r.score, r.max_dim, is_anom, r.mode,
            cur_warn, cur_confirm, cur_deny,
        )
        if got != r.got:
            raise AssertionError(
                f"档位重实现与真检测器不一致：{r.scenario_id} "
                f"score={r.score} max_dim={r.max_dim} mode={r.mode} "
                f"真实现={r.got} 重实现={got}"
            )


def run_scenarios(scns=None) -> EvalReport:
    results = []
    for scn in (scns if scns is not None else scenarios()):
        kwargs = dict(scn.get("detector_kwargs") or {})
        mode = kwargs.get("mode", "confirm")
        det = BehaviorDetector(**kwargs)

        # 先喂基线（decision="allow" 才会被 learn）
        for spec in scn["baseline"]:
            rec = _record(spec)
            rep = det.observe_pre_exec(rec)
            det.observe_post_exec(rec, rep)

        probe = det.observe_pre_exec(_record(scn["probe"]))
        dims = dict(getattr(probe, "dimensions", {}) or {})
        max_dim = max(dims.values()) if dims else 0.0
        results.append(ScenarioResult(
            scenario_id=scn["id"],
            expect=scn["expect"],
            got=probe.action,
            score=probe.anomaly_score,
            max_dim=round(float(max_dim), 4),
            dimensions=dims,
            reasons=list(probe.reasons),
            mode=mode,
            known_gap=scn.get("known_gap"),
        ))
    return EvalReport(results)


# ═══════════════════════════════════════════
# 阈值扫描
# ═══════════════════════════════════════════

def sweep_thresholds(report: EvalReport, step: float = 0.05) -> dict:
    """扫描 (warn, confirm, deny) 三元组，找出标定集完全满足的区间。

    warn 单独扫的意义有限（它只决定 is_anomaly，而 confirm 门槛通常更高），
    但必须一起扫 —— 把 confirm 调低到 warn 之下会改变语义。
    """
    _assert_reimplementation_matches(report)
    scored = [r for r in report.results if r.counted]
    cur_warn, cur_confirm, cur_deny = current_thresholds()

    grid = [round(x * step, 4) for x in range(int(1 / step) + 1)]
    perfect = []
    for warn_t in grid:
        for confirm_t in grid:
            if confirm_t < warn_t:
                continue
            for deny_t in grid:
                if deny_t < confirm_t:
                    continue
                ok = True
                for r in scored:
                    is_anom = (
                        (r.score is not None and r.score >= warn_t)
                        or r.max_dim >= STRONG_DIM_THRESHOLD
                    )
                    got = _action_for(
                        r.score, r.max_dim, is_anom, r.mode,
                        warn_t, confirm_t, deny_t,
                    )
                    if got != r.expect:
                        ok = False
                        break
                if ok:
                    perfect.append((warn_t, confirm_t, deny_t))
    return {
        "step": step,
        "perfect_regions": perfect,
        # ── 搜索域（此前从未对外声明，投影数字因此缺了前提）──────────
        # 扫描用 `continue` 静默跳过了 confirm < warn 与 deny < confirm 的组合。
        # 跳过本身是对的（confirm 低于 warn 语义上讲不通），
        # 但**不声明**就等于让人把投影当成全集 —— 而它只是受限域上的投影。
        "domain": "warn <= confirm <= deny",
        "domain_note": "越过该序关系的组合不参与扫描，也不计入下列投影",
        "n_grid_combos": len(grid) ** 3,
        "n_enumerated": sum(
            1
            for w in grid
            for c in grid
            if c >= w
            for d in grid
            if d >= c
        ),
        "current": current_thresholds(),
        "current_is_perfect": any(
            abs(w - cur_warn) < 1e-9
            and abs(c - cur_confirm) < 1e-9
            and abs(d - cur_deny) < 1e-9
            for w, c, d in perfect
        ),
    }


def _feasible(scored, w: float, c: float, d: float) -> bool:
    """给定三元组，本标定集是否全对（与 sweep 内层同一判据）。"""
    for r in scored:
        is_anom = (r.score is not None and r.score >= w) or r.max_dim >= STRONG_DIM_THRESHOLD
        got = _action_for(r.score, r.max_dim, is_anom, r.mode, w, c, d)
        if got != r.expect:
            return False
    return True


def _within_domain(w: float, c: float, d: float) -> bool:
    """三个阈值是否落在本模块自己声明的搜索域 ``warn <= confirm <= deny`` 内。

    ⚠️ 这个域**不是**装饰。`sweep_thresholds` 用 `continue` 跳过了
    confirm < warn 与 deny < confirm 的组合，并在返回值里声明了
    ``domain = "warn <= confirm <= deny"``。若「精确可行区间」这条路径
    不施加同一个约束，它给出的区间就会包含**该工具自己声明为不可搜索**
    的配置 —— 运维照着调，会得到一个 confirm 低于 warn 的阈值组合。

    实测（§9.66）：修复前 warn 的精确上界报成 1.0000，而 (1.0, 0.8, 0.95)
    恰好越过了 confirm 门槛；confirm 的下界报成 0.0000，(0.6, 0.0, 0.95)
    越过了 warn 门槛。三个阈值各有一条边落在域外。
    """
    return w <= c <= d


def _feasible_in_domain(scored, w: float, c: float, d: float) -> bool:
    """域内**且**标定集全对。"""
    return _within_domain(w, c, d) and _feasible(scored, w, c, d)


def knob_effectiveness(report: EvalReport, current=None, samples: int = 401) -> dict:
    """每个阈值在其**域内可行区间**上，究竟能不能改变任何一条样本的判定。

    ## 为什么需要这个量具

    「可行区间」只回答「改到这个值，标定集是否仍然全对」。
    它**不**回答「改到这个值，行为是否真的变了」——
    而后者才是运维问「我能调这个旋钮吗」时真正要的答案。

    实测（§9.66）：三个阈值在各自报出的区间上，**没有任何一个取值点
    改变过任何一条样本的处置档位**。区间宽度与「旋钮是否有用」是两件事：
    一个区间可以很宽，同时整段都是无效旋钮（因为维度分是离散常量，
    样本的 score / max_dim 落在 0.0 / 0.2 / 0.8 / 0.85 / 0.95 / 1.0
    这些**固定值**上，阈值在相邻两个取值之间移动不改变任何 `>=` 的结果）。

    ⇒ 「余量 +0.4000」这类数字**不能**被读成「有 0.40 的调节空间」。

    ## 口径：只认**处置档位**的变化

    ``is_anomaly`` 的翻转单独计入 ``anomaly_changes``，但**不算**
    「旋钮有效」—— 因为它不改变任何处置后果。实测：warn=0.0 会让三条
    logged 样本的 ``is_anomaly`` 变 True，但它们的 ``action`` 仍是
    ``logged``（档位判定在 is_anomaly 为真之后还要过 confirm/deny 门限，
    而这些样本的 score 与 max_dim 都是 0）。这就是**端点假象**：
    取值点恰好落在 0.0 这个边界上，再往前一步就回退。

    ⇒ ``inert`` 判据用处置档位：区间内处置档位一个都没变 ⇒ 整段无效旋钮。

    Returns:
        每个阈值一个 dict：
          * ``interval``      —— 域内可行区间 (lower, upper)
          * ``action_changes``—— 区间内改变处置档位的取值点个数
          * ``anomaly_changes`` —— 区间内改变 is_anomaly 的取值点个数
          * ``inert``         —— 整段区间是否**完全**不改变任何处置档位
          * ``samples_tested``—— 取样点数
    """
    scored = [r for r in report.results if r.counted]
    cur = tuple(current or current_thresholds())
    bounds = exact_conditional_bounds(report, current=cur)
    names = ("warn", "confirm", "deny")

    def actions_at(w, c, d):
        out = []
        for r in scored:
            is_anom = (
                (r.score is not None and r.score >= w)
                or r.max_dim >= STRONG_DIM_THRESHOLD
            )
            out.append((
                r.scenario_id,
                _action_for(r.score, r.max_dim, is_anom, r.mode, w, c, d),
                is_anom,
            ))
        return out

    base = actions_at(*cur)
    out: dict = {}
    for idx, name in enumerate(names):
        b = bounds[name]
        if not b.get("feasible_at_current"):
            out[name] = {
                "interval": None,
                "action_changes": 0,
                "anomaly_changes": 0,
                "inert": None,
                "samples_tested": 0,
            }
            continue
        lo, hi = b["lower"], b["upper"]
        n = max(1, int(samples))
        step = (hi - lo) / n if n else 0.0
        vals = [round(lo + i * step, 6) for i in range(n + 1)]
        act_pts, anom_pts = set(), set()
        for v in vals:
            t = list(cur)
            t[idx] = v
            for (sid, a0, an0), (sid2, a1, an1) in zip(base, actions_at(*t)):
                if a0 != a1:
                    act_pts.add(v)
                if an0 != an1:
                    anom_pts.add(v)
        out[name] = {
            "interval": (lo, hi),
            "action_changes": len(act_pts),
            "anomaly_changes": len(anom_pts),
            # inert 只看**处置档位**：is_anomaly 翻转不改变任何处置后果，
            # 拿它充数会把「整段无效旋钮」误判成「有效果」（§9.66 实测：
            # warn 区间内唯一那个 is_anomaly 翻转点恰在 0.0 边界上，
            # 处置档位自始至终没变）。
            "inert": not act_pts,
            "samples_tested": len(vals),
        }
    return out


def exact_conditional_bounds(report: EvalReport, current=None) -> dict:
    """每个阈值在**其余两个固定在当前值**时的精确可行区间。

    ## 为什么必须另算，不能用 ``sweep_thresholds`` 的投影顶替

    两者回答的是**不同问题**，不可互相比较、也不可互相替代：

    * 网格投影 = 在整个可行集上对某一维取投影，含义是「**存在**其余两维取值可行」
    * 本函数   = 其余两维**钉死在当前值**，只动这一维

    ## 域约束：``warn <= confirm <= deny`` **必须**在这里也施加

    `sweep_thresholds` 用 `continue` 跳过了 confirm < warn 与 deny < confirm
    的组合，并在返回值里显式声明 ``domain = "warn <= confirm <= deny"``。
    同一个工具里两条路径必须用**同一个域**，否则「精确可行区间」会给出
    该工具自己声明为不可搜索的配置。

    实测（§9.66，修复前）：warn 的精确上界报成 1.0000，
    但 (1.0, 0.8, 0.95) 的 warn > confirm —— **越域**；
    confirm 的精确下界报成 0.0000，但 (0.6, 0.0, 0.95) 的 confirm < warn；
    deny 的精确下界报成 0.0000，但 (0.6, 0.8, 0.0) 的 deny < confirm。
    三个阈值各有一条边落在域外 ⇒ 报出的「余量」有一部分是**调不出来的**。

    修复后（其余两阈值固定在当前值 0.6 / 0.8 / 0.95）：
        warn    域内 [0.0000, 0.8000]   余量 上 +0.2000 / 下 -0.6000
        confirm 域内 [0.6000, 0.8000]   余量 上 +0.0000 / 下 -0.2000
        deny    域内 [0.8000, 0.9500]   余量 上 +0.0000 / 下 -0.1500

    ⚠️ **域约束会改变「余量」的含义**：域内的下界不是「标定集允许的下界」，
    而是「域允许的下界」—— 它由 confirm ≥ warn 这条**语义**约束决定，
    与样本无关。所以下界余量要读作「**不能**调到低于 X，否则语义上讲不通」，
    而不是「标定集只支持到 X」。

    ``unconstrained_lower`` / ``unconstrained_upper`` 保留**施加域约束前**的
    原始值，供追溯用；它们**不是**可运维区间的一部分。

    ## 为什么这个计算是精确的，不是又一次量化近似

    三个阈值只经由 ``score >= t`` 与 ``max_dim >= t`` 起作用，
    因此可行性关于每一维都是**分段常数**的，断点只可能落在数据值上。
    于是只需在「断点本身」与「相邻断点的严格中点」上取值即可覆盖全轴：
    段内恒定，中点取值代表整段。相邻断点的中点严格落在两者之间，
    浮点表示不会越界。这是穷举断点，不是网格近似。
    """
    _assert_reimplementation_matches(report)
    scored = [r for r in report.results if r.counted]
    cur = tuple(current or current_thresholds())
    names = ("warn", "confirm", "deny")

    out: dict = {}
    for idx, name in enumerate(names):
        base = list(cur)

        def ok(v, _idx=idx, _base=base):
            t = list(_base)
            t[_idx] = v
            return _feasible_in_domain(scored, *t)

        def ok_unconstrained(v, _idx=idx, _base=base):
            """不考虑域约束的判据 —— 只用于保留原始值供追溯。"""
            t = list(_base)
            t[_idx] = v
            return _feasible(scored, *t)

        if not ok(cur[idx]):
            # 当前值本身不可行 —— 没有「围绕它的可行段」可言。
            # 静默返回 None 会被渲染层当成 0 宽度区间，正是本轮修的那类谎报。
            out[name] = {
                "current": cur[idx],
                "feasible_at_current": False,
                "lower": None,
                "upper": None,
                "lower_closed": None,
                "upper_closed": None,
                "domain": "warn <= confirm <= deny",
                "unconstrained_lower": None,
                "unconstrained_lower_closed": None,
                "unconstrained_upper": None,
                "unconstrained_upper_closed": None,
            }
            continue

        bps = sorted(
            {0.0, 1.0, cur[idx]}
            # 域约束的边界**必须**进断点集：被移动的这一维的可行段，
            # 端点可能正好停在「另一个阈值的当前值」上（warn <= confirm
            # 这条序关系的分界）。漏掉它，扫描就会跳过边界、退而报出
            # 一个更窄的区间（实测：confirm 的域内下界本应是 0.6，
            # 漏掉后报成 0.8）。
            | set(cur)
            | {r.score for r in scored if r.score is not None}
            | {r.max_dim for r in scored}
        )
        # 候选点 = 断点本身 ∪ 相邻断点的严格中点
        cands: list = []
        for i, b in enumerate(bps):
            cands.append((b, "closed"))
            if i + 1 < len(bps):
                cands.append(((b + bps[i + 1]) / 2.0, "open"))

        k = next(i for i, (v, _) in enumerate(cands) if abs(v - cur[idx]) < 1e-12)
        lo = k
        while lo - 1 >= 0 and ok(cands[lo - 1][0]):
            lo -= 1
        hi = k
        while hi + 1 < len(cands) and ok(cands[hi + 1][0]):
            hi += 1

        # 未施加域约束时的原始边界（仅供追溯，不是可运维区间）
        u_lo = k
        while u_lo - 1 >= 0 and ok_unconstrained(cands[u_lo - 1][0]):
            u_lo -= 1
        u_hi = k
        while u_hi + 1 < len(cands) and ok_unconstrained(cands[u_hi + 1][0]):
            u_hi += 1

        out[name] = {
            "current": cur[idx],
            "feasible_at_current": True,
            # 端点的开闭由「该端点自身是否可行」决定：段内中点可行而端点
            # 不可行 → 该端是开端；端点本身可行 → 该端是闭端。
            "lower": cands[lo][0],
            "lower_closed": cands[lo][1] == "closed",
            "upper": cands[hi][0],
            "upper_closed": cands[hi][1] == "closed",
            "domain": "warn <= confirm <= deny",
            "unconstrained_lower": cands[u_lo][0],
            "unconstrained_lower_closed": cands[u_lo][1] == "closed",
            "unconstrained_upper": cands[u_hi][0],
            "unconstrained_upper_closed": cands[u_hi][1] == "closed",
        }
    return out


def render_report(report: EvalReport, sweep: dict | None = None) -> str:
    L = ["=" * 78, "行为检测标定评估报告", "=" * 78, ""]

    L.append("── 逐条结果 " + "─" * 56)
    L.append(f"{'scenario':34} {'mode':8} {'expect':9} {'got':9} "
             f"{'score':>7} {'maxdim':>7}")
    for r in report.results:
        flag = "OK " if r.hit else ("GAP" if r.known_gap else "MISS")
        sc = "None" if r.score is None else f"{r.score:.4f}"
        L.append(f"{r.scenario_id:34} {r.mode:8} {r.expect:9} {r.got:9} "
                 f"{sc:>7} {r.max_dim:7.4f}  [{flag}]")

    L.append("")
    L.append("── 维度明细 " + "─" * 62)
    for r in report.results:
        if not r.dimensions:
            continue
        dims = " ".join(f"{k}={v:.2f}" for k, v in sorted(r.dimensions.items()))
        L.append(f"  {r.scenario_id:34} {dims}")

    L.append("")
    L.append("── 混淆矩阵（行=标注，列=实现）" + "─" * 46)
    cm = report.confusion
    L.append(f"{'':10}" + "".join(f"{c:>10}" for c in ACTIONS))
    for want in ACTIONS:
        L.append(f"{want:10}" + "".join(f"{cm[want][got]:>10}" for got in ACTIONS))

    L.append("")
    L.append("── 每类指标 " + "─" * 58)
    L.append(f"{'class':10} {'TP':>4} {'FP':>4} {'FN':>4} "
             f"{'precision':>10} {'recall':>8} {'F1':>8}")
    for label, m in report.per_class.items():
        def f(v):
            return "  n/a" if v is None else f"{v:.3f}"
        L.append(f"{label:10} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4} "
                 f"{f(m['precision']):>10} {f(m['recall']):>8} {f(m['f1']):>8}")

    acc = report.accuracy
    L.append("")
    L.append(f"准确率（不含 known_gap）= {'n/a' if acc is None else f'{acc:.4f}'}"
             f"   命中 {sum(1 for r in report.results if r.counted and r.hit)}"
             f"/{sum(1 for r in report.results if r.counted)}")

    gaps = [r for r in report.results if r.known_gap]
    if gaps:
        L.append("")
        L.append("── 已登记的已知缺口（不计入准确率）" + "─" * 38)
        for r in gaps:
            L.append(f"  {r.scenario_id:34} {r.known_gap}")
            L.append(f"  {'':34} 实测 {r.got} / score {r.score} / dims {r.dimensions}")

    L.append("")
    L.append("── 触发路径分解 " + "─" * 58)
    t = report.single_dim_trigger_share
    L.append(f"  应处置样本 = {t['by_score_only'] + t['by_dim_only'] + t['both']}")
    L.append(f"  仅靠加权分触发 = {t['by_score_only']}")
    L.append(f"  仅靠单维度触发 = {t['by_dim_only']}")
    L.append(f"  两者同时       = {t['both']}")
    L.append("  → 单维度高分是一条**并行**触发路径；只看加权阈值会高估其作用。")

    s = report.separation
    def g(v):
        return "n/a" if v is None else f"{v:.4f}"
    L.append("")
    L.append("── 分数分离 " + "─" * 60)
    L.append(f"  logged 组最高分     = {g(s['max_logged'])}")
    L.append(f"  应处置组最低分      = {g(s['min_should_act'])}")
    L.append(f"  → 间隔              = {g(s['margin'])}")

    if sweep is not None:
        L.append("")
        L.append("── 阈值扫描 " + "─" * 62)
        cur = sweep["current"]
        L.append(f"  当前 warn/confirm/deny = {cur}")
        L.append(f"  当前阈值落在完全满足区间内 = {sweep['current_is_perfect']}")
        regions = sweep["perfect_regions"]
        if not regions:
            L.append("  ★ 没有任何阈值组合能让本标定集全对 —— 需先修实现")
        else:
            ws = sorted({r[0] for r in regions})
            cs = sorted({r[1] for r in regions})
            ds = sorted({r[2] for r in regions})
            L.append(f"  搜索域 = {sweep['domain']}（{sweep['domain_note']}）")
            L.append(f"  枚举组合数 = {sweep['n_enumerated']} / 网格全组合 "
                     f"{sweep['n_grid_combos']}")
            L.append(f"  ⚠ 以下三行是**网格(步长 {sweep['step']})上的投影**，"
                     f"含义是「**存在**其余两维取值可行」，"
                     f"既不是精确边界、也不是可行域本身：")
            L.append(f"    warn 投影    = [{ws[0]:.2f}, {ws[-1]:.2f}]")
            L.append(f"    confirm 投影 = [{cs[0]:.2f}, {cs[-1]:.2f}]")
            L.append(f"    deny 投影    = [{ds[0]:.2f}, {ds[-1]:.2f}]")
            L.append(f"    可行组合数 = {len(regions)}")
            _n_box = len(ws) * len(cs) * len(ds)
            L.append(f"  ⚠ 三行交叉可得 {_n_box} 个三元组，但只有其中满足 "
                     f"{sweep['domain']} 的 {len(regions)} 个在搜索域内 —— "
                     f"漏看这条序关系，会把可选范围当成 {_n_box} 份，"
                     f"多算 {_n_box - len(regions)} 份")

            ex = exact_conditional_bounds(report)
            L.append("")
            L.append(f"  ── 精确可行区间（其余两阈值固定在当前值）{'─' * 26}")
            L.append("  （这一组才回答「我能不能单独调这一个、调多少」）")
            L.append("  域约束 = warn <= confirm <= deny（与上方网格扫描同一域）")
            for nm in ("warn", "confirm", "deny"):
                b = ex[nm]
                if not b["feasible_at_current"]:
                    L.append(f"    {nm:8} 当前 {b['current']:.4f} → "
                             f"★★ 当前值本身不可行，无可行区间可言")
                    continue
                lb = "[" if b["lower_closed"] else "("
                rb = "]" if b["upper_closed"] else ")"
                L.append(f"    {nm:8} 当前 {b['current']:.4f} → "
                         f"{lb}{b['lower']:.4f}, {b['upper']:.4f}{rb}"
                         f"   余量 上 {b['upper'] - b['current']:+.4f}"
                         f" / 下 {b['lower'] - b['current']:+.4f}")
                if (b["unconstrained_lower"] != b["lower"]
                        or b["unconstrained_upper"] != b["upper"]):
                    L.append(f"             （未施加域约束时为 "
                             f"[{b['unconstrained_lower']:.4f}, "
                             f"{b['unconstrained_upper']:.4f}] —— "
                             f"其中越域部分**不可运维**）")
            L.append("  注：精确区间与上面的网格投影回答的不是同一个问题，"
                     "因此**不给残差** —— 两者相减没有意义。")
            L.append("  注：下界余量由**域约束**（语义序关系）决定，"
                     "不是由标定集样本决定 —— 读作「不能低于 X」，"
                     "而不是「数据只支持到 X」。")

            eff = knob_effectiveness(report)
            L.append("")
            L.append("── 旋钮有效性（区间内能不能真的改变判定）" + "─" * 34)
            for nm in ("warn", "confirm", "deny"):
                e = eff[nm]
                if e["interval"] is None:
                    L.append(f"  {nm:8} 当前值不可行，跳过")
                    continue
                lo, hi = e["interval"]
                tag = "★ 整段无效旋钮" if e["inert"] else "有效果"
                L.append(f"  {nm:8} 区间 [{lo:.4f}, {hi:.4f}]  "
                         f"改变处置档位的取值点 = {e['action_changes']}  "
                         f"改变 is_anomaly 的取值点 = {e['anomaly_changes']}  "
                         f"→ {tag}")
            L.append("  ⚠ 「可行区间宽」≠「旋钮有用」：区间宽度只保证"
                     "标定集仍然全对，不保证行为改变。")
            L.append("  ⚠ 判据只看**处置档位**：is_anomaly 翻转不改变处置后果，"
                     "拿它充数会把「整段无效旋钮」误判成「有效果」。")

    if report.misses:
        L.append("")
        L.append("── 未命中 " + "─" * 62)
        for r in report.misses:
            L.append(f"  {r.scenario_id}: 标注 {r.expect}，实现 {r.got} "
                     f"(score={r.score}, max_dim={r.max_dim})")

    # 已登记缺口的敏感性分析：只给数据，不给结论
    sens = normalization_sensitivity(report)
    L.append("")
    L.append("── 归一口径敏感性（已登记缺口，未修改实现）" + "─" * 30)
    L.append(f"  全维权重和 = {sens['full_denom']:.2f}；"
             f"存在维度缺失的样本 = {sens['n_missing_dims']}/{sens['n']}")
    L.append("  改按全维归一后判定翻转数 = "
             f"{sens['n_flipped']}")
    if sens['flips']:
        for x in sens['flips']:
            L.append(f"    · {x['scenario_id']}: {x['got_now']} → {x['got_alt']}"
                     f" (score {x['score_now']} → {x['score_alt']}, "
                     f"{x['n_dims']} 维)")
    else:
        L.append("    · 无翻转 —— 当前数据集上两种口径判定完全一致")
    L.append("  注：strong / max_dim 读原始维度值，与维度数量无关，"
             "两条单维度路径不受影响")

    L.append("")
    return "\n".join(L)


def main(argv: list | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    report = run_scenarios()
    sweep = sweep_thresholds(report)
    if "--json" in argv:
        print(json.dumps({
            "results": [r.__dict__ for r in report.results],
            "confusion": report.confusion,
            "per_class": report.per_class,
            "accuracy": report.accuracy,
            "separation": report.separation,
            "trigger_share": report.single_dim_trigger_share,
            "normalization": normalization_sensitivity(report),
            "sweep": {k: v for k, v in sweep.items() if k != "perfect_regions"},
            "perfect_region_count": len(sweep["perfect_regions"]),
        }, ensure_ascii=False, indent=2, default=str))
    else:
        print(render_report(report, sweep))
    return 0 if not report.misses else 1


if __name__ == "__main__":
    raise SystemExit(main())
