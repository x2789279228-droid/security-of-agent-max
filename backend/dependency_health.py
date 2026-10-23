"""
依赖可达性探针 — 为前端健康仪表提供真实数据（2026-10-03 新增）

为什么需要这个模块
------------------
`GET /api/health` 返回的是**静态** `{"status": "ok"}`（非生产环境才附带几个
配置项字符串），它并不探测任何依赖。而 `observability/health_monitor.py`
监控的是**管道阶段**健康（错误率 / P95 延迟 / 卡死 span），与"PostgreSQL 能否
连通"是两件事，其数据由 `routers/ops.py` 单独暴露。

结果是：前端 Monitor 页的三个健康环（向量检索 / Redis 滑动窗口 / LLM 摘要）
此前【没有任何数据源】——`stores/serviceStore.ts` 的初值被硬编码为 'ok'，
`setService` / `setAll` 在整个前端零调用点。运维在依赖故障时看不到任何提示。

本模块补上缺失的这一层：真实探测 postgres / redis / qdrant，并对 LLM 给出
**配置态**（不发真实请求，见下）。

关于 LLM 为什么不做真实调用
----------------------------
对 LLM 发一次真实请求需要花钱且要等秒级超时，不适合放在一个会被前端轮询的
健康端点里。这里改为报告**配置完备性**（api_key / base_url / model 是否齐备），
并在 `detail` 里明确标注这是"配置态"而非"连通态"，避免再次产生"绿色=可用"
的误导。前端对应显示 CONFIGURED 而非 NOMINAL。
"""
import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# 单个探针的墙钟上限。健康端点会被前端轮询，必须便宜且快速失败。
_PROBE_TIMEOUT_S = 1.5


async def _timed(name: str, coro) -> dict[str, Any]:
    """执行一个探针，附带耗时与超时/异常兜底。绝不向上抛异常。"""
    t0 = time.perf_counter()
    try:
        detail = await asyncio.wait_for(coro, timeout=_PROBE_TIMEOUT_S)
        return {
            "status": "ok",
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "detail": detail or "",
        }
    except asyncio.TimeoutError:
        return {
            "status": "error",
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "detail": f"探测超时（>{_PROBE_TIMEOUT_S}s）",
        }
    except Exception as e:
        return {
            "status": "error",
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "detail": f"{type(e).__name__}: {e}"[:200],
        }


async def _probe_postgres() -> str:
    from sqlalchemy import text
    from models import async_session

    async with async_session() as s:
        await s.execute(text("SELECT 1"))
    return "SELECT 1 ok"


async def _probe_redis() -> str:
    from sliding_window import sliding_window

    r = await sliding_window.get_redis()
    if r is None:
        raise RuntimeError("Redis 客户端未初始化（lifespan 未完成或已断开）")
    await r.ping()
    return "PING → PONG"


async def _probe_qdrant() -> str:
    from qdrant_store import qdrant_store
    from config import settings

    # _client_or_none() 本身已含 get_collections() 连通性探测, 且是 async
    client = await qdrant_store._client_or_none()
    if client is None:
        raise RuntimeError("Qdrant 客户端不可用（未启用或连接失败）")
    if not settings.qdrant_url:
        raise RuntimeError("QDRANT_URL 未配置")
    # qdrant_store 用的是【同步】QdrantClient, collection_exists 不是 coroutine
    exists = client.collection_exists(settings.qdrant_collection)
    if not exists:
        # 集合尚未创建不一定代表不可用（可能是尚未播种），因此只作提示
        return f"连接正常，但集合 {settings.qdrant_collection} 尚未创建"
    return f"集合 {settings.qdrant_collection} 存在"


def _probe_llm_config() -> dict[str, Any]:
    """LLM 只报配置完备性，**不发真实请求**。detail 必须自述这一点。"""
    from config import settings

    missing = [
        name
        for name, val in (
            ("LLM_API_KEY", settings.llm_api_key),
            ("LLM_BASE_URL", settings.llm_base_url),
            ("LLM_MODEL", settings.llm_model),
        )
        if not val
    ]
    if missing:
        return {
            "status": "error",
            "latency_ms": 0.0,
            "detail": f"未配置：{', '.join(missing)}（配置态检查，未发起真实请求）",
        }
    return {
        "status": "ok",
        "latency_ms": 0.0,
        "detail": f"{settings.llm_model}（配置态检查，未发起真实请求）",
    }


async def probe_dependencies() -> dict[str, Any]:
    """并发探测全部依赖。返回可直接 JSON 序列化的结构。

    返回形状::

        {
          "postgres": {"status": "ok|warn|error", "latency_ms": 1.2, "detail": "..."},
          "redis":    {...},
          "qdrant":   {...},
          "llm":      {...},
          "_note":    "...llm 为配置态..."
        }
    """
    results = await asyncio.gather(
        _timed("postgres", _probe_postgres()),
        _timed("redis", _probe_redis()),
        _timed("qdrant", _probe_qdrant()),
    )
    services = {
        "postgres": results[0],
        "redis": results[1],
        "qdrant": results[2],
        "llm": _probe_llm_config(),
    }

    # 汇总：任一 error → degraded；否则 ok。qdrant 的"集合未创建"是 warn 语义，
    # 这里已在 detail 中区分，不误判为不可用。
    overall = "ok"
    if any(v["status"] == "error" for v in services.values()):
        overall = "degraded"

    return {
        "status": overall,
        "services": services,
        "_note": "llm 为配置态检查（未发起真实请求）；其余为真实连通性探测。",
    }
