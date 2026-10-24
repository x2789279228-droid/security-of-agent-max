"""认证与健康检查路由 — 登录 / 注册"""
import asyncio
import hmac
import logging
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError

from config import settings
from auth import (
    create_access_token,
    get_current_user,
    revoke_jti,
    revoke_username,
    RequireRole,
    UserInfo,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from models import async_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["auth"])

_LOGIN_FAIL_LIMIT = 5
_LOGIN_LOCKOUT_SECONDS = 900  # 15 分钟


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


# P1: Redis 故障时退回进程内计数 — 修复前 fail-open(logger.debug 后放行),
# Redis 宕机期间登录爆破保护完全消失。
_local_fail_counts: dict[str, tuple[int, float]] = {}
_local_fail_lock = asyncio.Lock()


async def _check_bruteforce(request: Request, username: str) -> None:
    client_ip = request.client.host if request.client else "unknown"
    try:
        from sliding_window import sliding_window
        redis = sliding_window._redis
        if redis:
            fail_key = f"login:fail:{client_ip}:{username}"
            count = await redis.incr(fail_key)
            if count == 1:
                await redis.expire(fail_key, _LOGIN_LOCKOUT_SECONDS)
            if count > _LOGIN_FAIL_LIMIT:
                ttl = await redis.ttl(fail_key)
                logger.warning(f"[Auth] Brute force blocked: {client_ip} / {username} ({count} attempts)")
                raise HTTPException(
                    status_code=429,
                    detail=f"尝试次数过多，请 {ttl} 秒后重试",
                    headers={"Retry-After": str(ttl)},
                )
            return
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[Auth] Redis bruteforce check failed — falling back to in-memory counter: {e}")
    # 内存兜底: 同样的失败阈值, 进程内生效(单实例部署下保护不中断)
    key = f"{client_ip}:{username}"
    now = time.time()
    async with _local_fail_lock:
        count, first_ts = _local_fail_counts.get(key, (0, now))
        if now - first_ts > _LOGIN_LOCKOUT_SECONDS:
            count, first_ts = 0, now
        count += 1
        _local_fail_counts[key] = (count, first_ts)
        if count > _LOGIN_FAIL_LIMIT:
            retry_after = int(max(1, _LOGIN_LOCKOUT_SECONDS - (now - first_ts)))
            logger.warning(
                f"[Auth] Brute force blocked (in-memory fallback): {client_ip} / {username} ({count} attempts)"
            )
            raise HTTPException(
                status_code=429,
                detail=f"尝试次数过多，请 {retry_after} 秒后重试",
                headers={"Retry-After": str(retry_after)},
            )


async def _clear_bruteforce(request: Request, username: str) -> None:
    client_ip = request.client.host if request.client else "unknown"
    try:
        from sliding_window import sliding_window
        redis = sliding_window._redis
        if redis:
            await redis.delete(f"login:fail:{client_ip}:{username}")
    except Exception:
        pass


@router.post("/auth/login")
async def login(req: LoginRequest, request: Request):
    """登录获取 JWT — 先校验内置 admin，再查 app_users"""
    if not settings.admin_password:
        logger.error("[Auth] admin_password not configured — login rejected")
        raise HTTPException(status_code=503, detail="Admin password not configured")

    await _check_bruteforce(request, req.username)

    # 1) 环境变量内置超管 — 常量时间比较, 避免时序侧信道逐字节猜口令
    if (req.username == settings.admin_user
            and hmac.compare_digest(
                (req.password or "").encode("utf-8"),
                (settings.admin_password or "").encode("utf-8"),
            )):
        await _clear_bruteforce(request, req.username)
        token = create_access_token(req.username, role="admin")
        return {"access_token": token, "token_type": "bearer", "role": "admin"}

    # 2) 注册用户
    try:
        from user_store import get_by_username, verify_password
        async with async_session() as session:
            user = await get_by_username(session, req.username)
            if user and user.is_active and verify_password(req.password, user.password_hash):
                user.last_login_at = datetime.now(timezone.utc)
                await session.commit()
                await _clear_bruteforce(request, req.username)
                token = create_access_token(user.username, role=user.role or "viewer")
                return {
                    "access_token": token,
                    "token_type": "bearer",
                    "role": user.role or "viewer",
                }
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[Auth] DB user lookup failed: {e}")

    client_ip = request.client.host if request.client else "unknown"
    logger.warning(f"[Auth] Failed login: {client_ip} / {req.username}")
    raise HTTPException(status_code=401, detail="用户名或密码错误")


@router.post("/auth/register")
async def register(req: RegisterRequest, request: Request):
    """自助注册 — 默认关闭；开启后 role=viewer，不可占用内置 admin 用户名。

    闸门语义：
      * `allow_self_registration=False`（默认）→ 403，不泄露账号是否存在；
      * 开启后仍保留用户名/密码校验、admin 用户名拒绝与 best-effort 限流；
      * 首个管理员账号应由部署脚本/CLI 创建，而不是依赖公开注册。
    """
    if not getattr(settings, "allow_self_registration", False):
        raise HTTPException(status_code=403, detail="自助注册已关闭")

    from user_store import (
        create_user,
        get_by_username,
        validate_password,
        validate_username,
    )

    err = validate_username(req.username)
    if err:
        raise HTTPException(status_code=400, detail=err)
    err = validate_password(req.password)
    if err:
        raise HTTPException(status_code=400, detail=err)

    username = req.username.strip()
    if username.lower() == (settings.admin_user or "admin").lower():
        raise HTTPException(status_code=400, detail="该用户名不可用")

    # 轻量限流：复用登录失败计数键空间的独立前缀
    client_ip = request.client.host if request.client else "unknown"
    try:
        from sliding_window import sliding_window
        redis = sliding_window._redis
        if redis:
            key = f"register:rate:{client_ip}"
            count = await redis.incr(key)
            if count == 1:
                await redis.expire(key, 3600)
            if count > 20:
                raise HTTPException(status_code=429, detail="注册过于频繁，请稍后再试")
    except HTTPException:
        raise
    except Exception:
        pass

    try:
        async with async_session() as session:
            existing = await get_by_username(session, username)
            if existing:
                raise HTTPException(status_code=409, detail="用户名已被注册")
            user = await create_user(session, username, req.password, role="viewer")
            token = create_access_token(user.username, role=user.role)
            return {
                "access_token": token,
                "token_type": "bearer",
                "role": user.role,
                "username": user.username,
            }
    except HTTPException:
        raise
    except IntegrityError:
        raise HTTPException(status_code=409, detail="用户名已被注册")
    except Exception as e:
        logger.error(f"[Auth] Register failed: {e}")
        raise HTTPException(status_code=500, detail="注册失败，请稍后重试")


class RevokeRequest(BaseModel):
    jti: str = ""
    username: str = ""


@router.post("/auth/logout")
async def logout(user: UserInfo = Depends(get_current_user)):
    """吊销当前 JWT 的 jti，立即失效。"""
    await revoke_jti(user.jti, ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    return {"status": "revoked", "jti": user.jti}


@router.post("/auth/revoke")
async def revoke_tokens(
    req: RevokeRequest,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """管理员吊销指定 jti 或该用户名下已记录的全部 token。"""
    if req.jti:
        await revoke_jti(req.jti, ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        return {"status": "revoked", "jti": req.jti, "count": 1}
    if req.username:
        n = await revoke_username(req.username)
        return {"status": "revoked", "username": req.username, "count": n}
    raise HTTPException(status_code=400, detail="jti or username required")


_is_prod = os.environ.get("SHARED_MEMORY_ENV_NAME", settings.env_name) == "prod"


@router.get("/health")
async def health():
    # 进程存活探针。刻意不探测依赖 —— 保持无鉴权/可公开，便于 LB 使用。
    # 依赖可达性见 /health/dependencies（需鉴权）。
    if _is_prod:
        return {"status": "ok"}
    return {"status": "ok", "services": {
        "llm": settings.llm_model,
        "embedding": settings.embedding_model,
        "kafka": "enabled" if settings.kafka_enabled else "disabled",
        "kafka_bootstrap": settings.kafka_bootstrap if settings.kafka_enabled else "",
    }}


@router.get("/health/dependencies")
async def health_dependencies(user: UserInfo = Depends(get_current_user)):
    """依赖可达性探针 —— 前端 Monitor 健康仪表的数据源。

    为什么与 /health 分开：
      - /health 是**静态** {"status": "ok"}，不探测任何依赖，且需保持公开给 LB
      - 本端点真实探测 postgres / redis / qdrant，并对 LLM 给出配置完备性
        （不发真实 LLM 请求 —— 该端点会被前端轮询）

    2026-10-03 修复：此前前端 Monitor 的三个健康环硬编码为 'ok'，而
    setService/setAll 零调用点，即【该数据在全项目中根本不存在】。

    需鉴权：detail 字段含内部地址与错误原文，不宜公开。
    """
    from dependency_health import probe_dependencies
    return await probe_dependencies()
