"""
检测输入规范化（canonicalization）— 签名匹配前的受限解码与路径归一。

## 为什么要有这一层（2026-10-25 基准证据）

- EVASION 报告（docs/benchmark/EVASION.md）：签名层对抗保持率 **0.438** ——
  url_encode 击穿 6/8 家族、partial_encode 击穿 4/8、double_encode 击穿 2/8；
- REPLAY 报告（docs/benchmark/REPLAY-CSIC-2010.md）：双重编码载荷原样匹配，
  "规范化解码器接入后的可达召回"与原始口径一致 —— 缺口在接入面不在规则；
- 根因：生产接入路径只归一化字段**名**（log_ingestion._normalize_fields），
  不做值规范化。逐条规则加编码变体是死路（B4 口径边界：
  "修复面在 ingest 规范化，而非逐条规则"）。

## 设计（与真实 IDS 的 pre-match normalization 同构）

- **匹配视图**：:func:`canonical_matching_view` 返回浅拷贝视图，只把
  ``url`` / ``message`` 两个字段覆写为规范化值 —— **原始事件永不被改写**，
  存储/取证/展示仍用原始值。接线点在 ``sigma_engine.engine`` 的匹配入口
  （pySigma 路径与 legacy 降级路径都接），生产、EVASION/REPLAY 评测器
  三条路径自动同口径。
- **受限解码**：最多 :data:`MAX_DECODE_ROUNDS` 轮 percent 解码（%XX 与
  旧式 %uXXXX），解码稳定即提前停止 —— 轮数上限防御解码炸弹，
  稳定即停避免对良性 URL 做无谓改写。
- **保守归一**：反斜杠→斜杠（Windows 风格遍历与 ``../`` 同义）、NUL
  字节剥离。**刻意不做**路径点段折叠（RFC 3986 remove_dot_segments）
  —— 折叠会把 ``../`` 子串从规范化视图中消掉，而现有规则库是对
  原始形式写的，这会把路径遍历的基线命中变成漏检（为边际召回引入
  基线回归，不换）；也不做 HTML 实体解码、Unicode NFKC、'+'→空格
  —— 过度解码会引入误报，REPLAY 良性 5000 样本 FP=0 是硬门禁。
- **语义对齐**：:func:`deep_decode` 与
  ``eval_datasets/replay_public_datasets.py`` 的同名函数语义一致
  （评估报告里的"规范化可达召回"因此可直接对比），并扩展轮数上限
  与 %uXXXX 支持。

## 与 Java 侧的镜像

``flink-jobs/.../util/UrlCanonicalizer.java`` 镜像本模块语义
（LogValidationJob 校验通过后把 ``_urlCanonical`` 附加进 rawData，
只增不改）；两侧向量集保持同步，任何一侧改语义必须两侧同改并跑
两侧测试。
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Callable, Dict

__all__ = [
    "MAX_DECODE_ROUNDS",
    "deep_decode",
    "canonical_url",
    "canonical_message",
    "canonical_matching_view",
    "CANON_FIELDS",
]

#: percent 解码轮数上限。double_encode 需 2 轮；3 轮覆盖三重编码，
#: 同时限制解码炸弹（%252525... 链）的最坏代价。
MAX_DECODE_ROUNDS = 3

#: 旧式 IE %uXXXX 编码（如 %u003c → '<'）
_UNICODE_ESCAPE_RE = re.compile(r"%u([0-9a-fA-F]{4})")

#: 参与规范化视图的字段 → 归一函数。扩展字段必须同步补 FP 证据
#: （跑 REPLAY 良性 5000 门禁），并在本 docstring 登记。
CANON_FIELDS: Dict[str, Callable[[str], str]] = {}


def _decode_round(text: str) -> str:
    """一轮解码：先 %uXXXX 再 percent 解码。"""
    if "%u" in text:
        text = _UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return urllib.parse.unquote(text, errors="replace")


def deep_decode(text: str, max_rounds: int = MAX_DECODE_ROUNDS) -> str:
    """受限多轮 percent 解码：稳定即停，最多 max_rounds 轮。

    与 replay_public_datasets.deep_decode 的差异：轮数从固定 2 改为
    "稳定即停 + 上限 3"，并支持 %uXXXX。对 double_encode 向量两者
    结果一致（2 轮后稳定）。
    """
    cur = text
    for _ in range(max_rounds):
        nxt = _decode_round(cur)
        if nxt == cur:
            break
        cur = nxt
    return cur


def canonical_url(value: str) -> str:
    """URL 匹配规范形：受限解码 → NUL 剥离 → 反斜杠归一。

    query 与 path 同等对待（解码不分组件）—— 规则库的 web 规则对
    url 做子串匹配，query 里的编码载荷与 path 里的同等危险；
    反斜杠→斜杠作用于整体 —— ``..\\..\\windows`` 与 ``../../etc``
    是同一种遍历攻击的两种写法。
    """
    if not value or not isinstance(value, str):
        return value
    if "%" not in value and "\\" not in value and "\x00" not in value:
        # 快路径：无编码、无反斜杠，原样返回
        return value
    out = deep_decode(value).replace("\x00", "").replace("\\", "/")
    return out if out != value else value


def canonical_message(value: str) -> str:
    """message 匹配规范形：受限解码 + NUL 剥离。

    message 可能不是 URL（任意告警文本），不做路径归一与反斜杠
    替换 —— Windows 路径在日志文本里是合法数据。
    """
    if not value or not isinstance(value, str):
        return value
    if "%" not in value and "\x00" not in value:
        return value
    out = deep_decode(value).replace("\x00", "")
    return out if out != value else value


CANON_FIELDS.update({"url": canonical_url, "message": canonical_message})


#: url 内嵌 scheme://host:port 的提取（用于补齐缺失的 dst_ip/dst_port）
_URL_AUTHORITY_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/:?#]+):(\d+)(?=[/?#]|$)")


def canonical_matching_view(event: dict) -> dict:
    """构造签名匹配视图：url/message 覆写为规范形（仅当有变化）。

    另做一项**只补缺失**的派生：事件没有 dst_ip 时，从规范形 URL 的
    authority 提取 host:port 填入 dst_ip/dst_port —— SIG-006 这类
    端口型规则（dst_port: 9200）依赖拆分结果，而编码 URL 在拆分前
    必须先解码（EVASION es_unauth 家族编码变体漏检的生产根因）。
    已有 dst_ip 的事件一律不覆盖 —— dst_ip 由数据源/采集器给出时
    它才是权威目标。

    - 无任何变化时**返回原 dict**（零拷贝快路径；调用方不得原地修改）；
    - 有变化时返回浅拷贝，原始字段在原事件里保持不变；
    - 非字符串值与其它字段一律原样保留。

    接线点：``sigma_engine.engine`` 的检测入口。评测器
    （EVASION / REPLAY）直接调 ``detector.detect(ev)``，因此也自动
    走同一视图 —— 改前改后同口径可比。
    """
    if not isinstance(event, dict):
        return event
    view: dict | None = None
    for field, fn in CANON_FIELDS.items():
        v = event.get(field)
        if not isinstance(v, str) or not v:
            continue
        c = fn(v)
        if c != v:
            if view is None:
                view = dict(event)
            view[field] = c
    if view is None:
        # 字段无变化：仅在缺 dst_ip 时尝试从原始 url 补齐
        url = event.get("url")
        if isinstance(url, str) and url and not event.get("dst_ip"):
            m = _URL_AUTHORITY_RE.match(url)
            if m:
                view = dict(event)
                view["dst_ip"] = m.group(1)
                view["dst_port"] = int(m.group(2))
        return view if view is not None else event
    if not view.get("dst_ip"):
        # 字段有变化：从规范形 url 补齐缺失的 dst_ip/dst_port
        m = _URL_AUTHORITY_RE.match(view.get("url") or "")
        if m:
            view["dst_ip"] = m.group(1)
            view["dst_port"] = int(m.group(2))
    return view
