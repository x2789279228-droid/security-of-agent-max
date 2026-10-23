"""
pytest 全局 conftest

职责:
  1. 注入测试用 env(指向 sqlite 内存库),避免本地装 asyncpg/postgres
  2. 隔离开发者机器上的真实 .env(2026-10-03)
  3. patch sqlalchemy.create_async_engine 去掉 PG 专属 pool 参数,使其能在 sqlite 上跑
  4. 提供 autouse fixture 复位跨测试泄漏的全局状态(2026-10-03)
"""
import asyncio
import os
import sys
from pathlib import Path

# 把 backend 目录加入 sys.path(放在 import models 前)
sys.path.insert(0, str(Path(__file__).parent.parent))

# ══════════════════════════════════════════════════════════════════
# 1. 隔离真实 .env —— 必须早于任何 config / models 的 import
# ══════════════════════════════════════════════════════════════════
# config._load_project_root_env() 在 import 期改写 os.environ,会把开发者机器上
# 的真实 .env 灌进测试进程。实测后果:
#   .env 的 RESPONSE_POLICIES_DIR=/data/response_policies 是 Linux 容器路径,
#   Windows 上不存在 → 全局 policy_engine 指向空目录 → 全量 15 个失败中的 10 个。
# 同一路径还泄漏 FW_SSH_PASSWORD / QDRANT_URL / FIELD_ENCRYPTION_KEY,使
# "无凭据时应当降级"的测试在配了真实凭据的机器上反而去连真实服务。
os.environ["SHARED_MEMORY_SKIP_DOTENV"] = "1"

# backend 根目录（用于定位源码内的策略目录）
_B = Path(__file__).resolve().parent.parent

# 策略/分类树目录显式指向仓库内真实路径（策略引擎按 env 解析这两个变量）。
#
# 【已知问题 · 未修】多个测试（update_response_policy / update_rule / learn_loop 等）
#   会**写**这些 YAML，实测 POL-C2-BEACON.yml 的 mtime 会被测试运行刷新。
#   本次曾尝试改为"复制到会话级临时目录再指过去"，但那会让 learn_loop 的
#   策略状态与全量跑时不一致（新增 test_learn_loop 失败），影响面超出本轮可
#   验证范围，故保留原状并在此记录。正确做法见
#   docs/AUDIT-2026-10-03-非安全类优化点.md §1。
os.environ.setdefault("RESPONSE_POLICIES_DIR", str(_B / "response_engine" / "policies"))
os.environ.setdefault("RESPONSE_TAXONOMY_PATH", str(_B / "response_engine" / "taxonomy.yml"))

# ── 其余测试用 env(必须在 import models 之前) ──
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
# 测试环境标识：让后台 fire-and-forget 的案例聚合在测试里改为同步等待，
# 避免与测试轮询共享 :memory: 单连接产生 commit/rollback 竞争
# （test_case_automation 实测 1/10 复现 UPDATE 0 rows）。
os.environ.setdefault("SHARED_MEMORY_ENV_NAME", "test")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_CONTROL_HMAC_KEY", "test-hmac-key")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")
# live 幂等 fail-closed 闸门: 测试环境默认关闭(生产默认开启)。
# 大量既有测试直接走 live 链(容器注入/遏制适配器), 不关心幂等存储;
# 闸门本身的行为由 test_phase2_reliability.py 显式开启后验证。
os.environ.setdefault("SHARED_MEMORY_REQUIRE_IDEMPOTENCY_FOR_LIVE", "false")
# 开发机上如果导出了字段密钥，失败关闭会把测试里的明文敏感字段拒绝掉。
# 需要密钥的用例自己设置并在结束时恢复。
os.environ.pop("SHARED_MEMORY_FIELD_ENCRYPTION_KEY", None)

# ── patch create_async_engine 去掉 PG 专属 pool 参数(sqlite 不支持) ──
import sqlalchemy.ext.asyncio as _sa_async

_orig_create_async_engine = _sa_async.create_async_engine


def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)


_sa_async.create_async_engine = _patched_create_async_engine

# 让旧测试模块(如 test_case_lifecycle)能 patch 后再 import models
import models  # noqa: F401  触发 create_async_engine 应用 patched 版本

import pytest  # noqa: E402


# ══════════════════════════════════════════════════════════════════
# 4. autouse fixture —— 复位跨测试泄漏的全局状态
# ══════════════════════════════════════════════════════════════════
@pytest.fixture(autouse=True)
def _restore_implicit_event_loop():
    """pytest-asyncio 跑完 async 用例后会 close() 循环并 set_event_loop(None),
    此后隐式 get_event_loop() 永久失效(新 asyncio 策略)。

    实测: test_audit_cache.py(字母序在 test_inc_edr.py 之前)会毒化后者,
    使其报 `RuntimeError: There is no current event loop in thread 'MainThread'`。
    通过与否纯粹取决于**文件名字母序** —— 改个文件名、加个测试文件都可能翻转结果。
    Python 3.12 已弃用该用法, 3.14 将无条件抛错 —— 随版本自动恶化的地雷。
    """
    yield
    asyncio.set_event_loop(asyncio.new_event_loop())


@pytest.fixture(autouse=True)
def _reset_globals():
    """复位模块级单例与 settings。

    本文件此前**没有任何 fixture**。全局单例(policy_engine / security_guard /
    approval_queue / audit_cache._MEM / embedder._stats)跨测试泄漏,且没有任何机制
    在测试失败时兜底 —— 例如 test_audit_endpoints.py:88 的还原写在 try 之外、
    无 finally,一旦断言失败,auto_execute=False 会永久留在全局单例里。
    """
    import audit_cache
    from config import settings

    try:
        from capacity import reset_gates
        reset_gates()
    except Exception:
        pass

    saved_settings = dict(settings.__dict__)

    # 策略引擎: 恢复出厂策略 + 清空运行期冷却
    try:
        from response_engine import policy_engine
        policy_engine.reload()
        policy_engine.clear_cooldowns()
    except Exception:
        pass
    try:
        from response_engine.human_approval import approval_queue
        approval_queue._tickets.clear()
    except Exception:
        pass
    try:
        from security_guard.security_guard import security_guard
        security_guard.reset()
    except Exception:
        pass
    try:
        audit_cache._MEM.clear()
    except Exception:
        pass
    # embedder 计数器是模块级的, 而 test_llm_cache_and_embedding.py 断言绝对值
    try:
        import summary_compression
        summary_compression.embedder._stats = {"hits": 0, "misses": 0, "errors": 0}
    except Exception:
        pass

    yield

    # teardown: 即便测试失败也还原
    settings.__dict__.clear()
    settings.__dict__.update(saved_settings)
