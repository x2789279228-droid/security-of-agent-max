"""
pytest 全局 conftest

职责:
  1. 注入测试用 env(指向 sqlite 内存库),避免本地装 asyncpg/postgres
  2. 隔离开发者机器上的真实 .env(2026-10-03)
  3. patch sqlalchemy.create_async_engine 去掉 PG 专属 pool 参数,使其能在 sqlite 上跑
  4. 提供 autouse fixture 复位跨测试泄漏的全局状态(2026-10-03)
"""
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

# 策略/分类树目录 → 会话级临时副本（2026-10-29 W1-2，拆除 P0-2 残留）。
#
# 历史: 曾直接指向仓库内真实目录 —— update_response_policy / update_rule /
# learn_loop 等测试会**写**这些 YAML，跑一次全量测试就污染 git 工作区
# （POL-C2-BEACON.yml 的 mtime/content 被刷新）。当年尝试 tmp 隔离时用了
# 每测试独立的 tmp 目录导致 learn_loop 状态与全量跑不一致而回滚；本轮改用
# **会话级单一副本**（所有测试共享，与共享仓库目录的语义一致），git 工作区
# 保持零污染。验收: 干净 clone 跑全量后 `git status` 与基线一致。
import shutil as _shutil
import tempfile as _tempfile

_POLICY_TMP = _tempfile.mkdtemp(prefix="soc-test-policies-")
_shutil.copytree(_B / "response_engine" / "policies",
                 Path(_POLICY_TMP) / "policies", dirs_exist_ok=True)
_shutil.copy2(_B / "response_engine" / "taxonomy.yml",
              Path(_POLICY_TMP) / "taxonomy.yml")
os.environ.setdefault("RESPONSE_POLICIES_DIR", str(Path(_POLICY_TMP) / "policies"))
os.environ.setdefault("RESPONSE_TAXONOMY_PATH", str(Path(_POLICY_TMP) / "taxonomy.yml"))

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

# ══════════════════════════════════════════════════════════════════
# 3.5 进程级单一事件循环 (SQLAlchemy 2.1 适配)
# ══════════════════════════════════════════════════════════════════
# 2.1 起异步池的 checkout 锁是 asyncio.Lock, 首次使用时**绑定事件循环**;
# 套件原本"按文件各起 loop"(123 个文件的 _run 助手 + pytest-asyncio 每
# function 一个 loop), 同一 :memory: 引擎跨 loop 复用即
# RuntimeError("bound to a different event loop")。
# 解法: 整个 pytest 进程共享**同一个**循环 ——
#   · pytest.ini: asyncio_default_{test,fixture}_loop_scope=session
#   · 本处 patch asyncio.new_event_loop, 让 123 个 `_run(new_event_loop())`
#     助手与 pytest-asyncio 的 session 循环收敛到同一对象;
#   · close() 对共享循环是 no-op(任何人不得关它, asyncio.run 也关不掉);
#   · 生产代码单循环运行, 不受影响。
import asyncio as _asyncio
import threading as _threading

_orig_new_event_loop = _asyncio.new_event_loop
_SHARED_LOOP = _orig_new_event_loop()
_SHARED_LOOP.close = lambda: None  # type: ignore[method-assign]


async def _noop_shutdown_default_executor() -> None:
    return None


# pytest-asyncio 每个测试的 Runner.close() 会在共享循环上调用
# shutdown_default_executor() —— 默认线程池被关掉后, 生产代码的
# run_in_executor(None, ...)(sigma 检测/bcrypt 等)全部抛
# "Executor shutdown has been called", 级联炸掉后续几十个测试。
# 共享循环的默认执行器必须活着; 线程随进程退出回收。
_SHARED_LOOP.shutdown_default_executor = (  # type: ignore[method-assign]
    _noop_shutdown_default_executor
)


def _patched_new_event_loop():
    if _threading.current_thread() is _threading.main_thread():
        return _SHARED_LOOP
    return _orig_new_event_loop()


_asyncio.new_event_loop = _patched_new_event_loop
# pytest-asyncio 走 asyncio.Runner, CPython 3.11 的 Runner._lazy_init 调用的是
# asyncio.events.new_event_loop() —— 只 patch 包属性会被绕过, 两处都要打。
import asyncio.events as _aio_events

_aio_events.new_event_loop = _patched_new_event_loop
_asyncio.set_event_loop(_SHARED_LOOP)

# 让旧测试模块(如 test_case_lifecycle)能 patch 后再 import models
import models  # noqa: F401  触发 create_async_engine 应用 patched 版本

import pytest  # noqa: E402

# 注: 不需要自写"排干遗留任务"的 fixture —— pytest-asyncio 每个 async 测试的
# Runner.close() 本身就会 cancel-all(实测它会取消共享循环上的一切任务,
# 包括下面这种自写 drain), fire-and-forget 任务随测试终结的原语义保持不变。


# ══════════════════════════════════════════════════════════════════
# 4. autouse fixture —— 复位跨测试泄漏的全局状态
# ══════════════════════════════════════════════════════════════════
# 【已拆除的地雷 · 2026-10-29】此前这里有一个 autouse 的
# `_restore_implicit_event_loop`(每个测试后 set_event_loop(new_event_loop())):
# 根因是生产代码 3 处 + 测试 3 处隐式 get_event_loop() —— pytest-asyncio
# close 循环并 set_event_loop(None) 后, 隐式调用抓到已关闭的循环,
# 通过与否取决于文件名字母序。本轮把全部 6 处改为 get_running_loop()/asyncio.run,
# 隐式依赖消失后该 workaround 移除(若复发, 先查新引入的 get_event_loop)。


@pytest.fixture(autouse=True)
def _reset_globals():
    """复位模块级单例与 settings。

    本文件此前**没有任何 fixture**。全局单例(policy_engine / security_guard /
    approval_queue / audit_cache._MEM / embedder._stats)跨测试泄漏,且没有任何机制
    在测试失败时兜底 —— 例如 test_audit_endpoints.py:88 的还原写在 try 之外、
    无 finally,一旦断言失败,auto_execute=False 会永久留在全局单例里。

    R17(P0-2): 复位失败必须 fail-fast —— 修复前每个复位块各自 except: pass,
    复位是否生效无任何信号, 污染静默延续(正是 scan-swallowed-failures 的靶子形态)。
    现在逐块收集错误, 任一失败 pytest.fail 上报(保留逐块执行, 一次报全)。
    """
    import audit_cache
    from config import settings

    reset_errors: list[str] = []

    def _attempt(name: str, fn) -> None:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — 收集后统一 fail-fast
            reset_errors.append(f"{name}: {type(e).__name__}: {e}")

    _attempt("capacity.reset_gates", lambda: __import__("capacity").reset_gates())

    saved_settings = dict(settings.__dict__)

    # 策略引擎: 恢复出厂策略 + 清空运行期冷却
    def _reset_policy():
        from response_engine import policy_engine
        policy_engine.reload()
        policy_engine.clear_cooldowns()

    def _reset_approval():
        from response_engine.human_approval import approval_queue
        approval_queue._tickets.clear()

    def _reset_guard():
        from security_guard.security_guard import security_guard
        security_guard.reset()

    def _reset_audit_cache():
        audit_cache._MEM.clear()

    def _reset_embedder_stats():
        import summary_compression
        summary_compression.embedder._stats = {"hits": 0, "misses": 0, "errors": 0}

    _attempt("policy_engine.reload", _reset_policy)
    _attempt("approval_queue._tickets.clear", _reset_approval)
    _attempt("security_guard.reset", _reset_guard)
    _attempt("audit_cache._MEM.clear", _reset_audit_cache)
    _attempt("embedder._stats", _reset_embedder_stats)

    if reset_errors:
        pytest.fail(
            "全局状态复位失败(污染将跨测试延续): " + "; ".join(reset_errors),
            pytrace=False,
        )

    yield

    # teardown: 即便测试失败也还原
    settings.__dict__.clear()
    settings.__dict__.update(saved_settings)
