"""公开注册闸门（2026-10-21 已实现）

> 本文件最初用于登记“`.env.example` 出货了开关但代码零读点”的缺口。
> 2026-10-21 起 `config.allow_self_registration` 与 handler 闸门均已落地，
> 原先的 strict xfail 已转为正向断言；下面的历史说明保留用于追溯。


## 这是什么

`docs/AUDIT-2026-10-03-修复实施计划.md:18` 把这一项列为**待修**：

| 配置项 | 当前代码默认 | 改为 |
|---|---|---|
| `allow_self_registration` | **无（永远开）⚠️** | **`False`** |

同文档 `:139` 写明实施方案是「在 `config.py` 加 `allow_self_registration: bool = False`」。

**但 `config.py` 里至今没有这个字段**，全仓生产代码**零读点**。

而 `.env.example:45` 已经出货了：

```
SHARED_MEMORY_ALLOW_SELF_REGISTRATION=false
```

## 为什么这条比 §7.1.11 那 37 个开关严重

三个原因，缺一不可地叠加：

1. **它在公开端点上。** `app.py:432-438` 的 `_PUBLIC_PATHS` 无条件包含
   `/api/auth/register` —— 任何人都能调，不需要任何凭证。
2. **`false` 出货了，但它是空操作。** 运维照 `.env.example` 配了
   `SHARED_MEMORY_ALLOW_SELF_REGISTRATION=false`，会**真的相信注册已关闭** ——
   这比没出货更糟：不出货只是没信息，出货了是**错误的确认**。
3. **已有测试给它盖章。** `tests/test_security_fixes_2026_10_03.py:362`
   `test_env_example_documents_security_defaults` 断言这三个键在 `.env.example` 里 ——
   **该测试当前是绿的**。它守的是「这个键被写进了 `.env.example`」，
   不是「这个键生效」。于是修复的**文档侧**有测试背书，
   **执行侧**没有任何东西。

> 这是本轮见过的最隐蔽的一种失效：**同一个安全修复，一半有测试、一半没有**，
> 而绿的那一半正好是让人以为整件事做完了的那一半。

## 严重级别要说准 —— 没有提权

**不要**把这条写成「任意用户可注册」就完事，也不要夸大：

* `routers/auth.py:158` `create_user(..., role="viewer")` —— **role 硬编码**，
  注册出来的账号拿不到任何提权；
* `:133-134` 显式拒绝占用内置 admin 用户名；
* `:137-151` 有按 IP 的限流（20 次/小时）。

所以真实影响是**公开端点上的无界账号创建**，不是权限提升。

但有一处值得单独指出：限流是 **best-effort** ——

```python
except Exception:
    pass          # routers/auth.py:150-151
```

Redis 不可用时限流**整个失效**，且**不报错、不告警**。
所以「有限流」不能当作缓解措施写进结论，只能写成「Redis 可用时有限流」。

## 为什么用 strict xfail 而不是直接补

补这个闸门是一个**产品决策**，不该由一次审计代拍：

* 默认值该是 `False`（按审计文档）还是保持现状（按「开箱即用」的产品诉求）？
* 演示/测试环境怎么开？审计文档的方案是 `.env.demo.example` 加 `true` ——
  但仓库里**没有** `.env.demo.example`，这个方案本身也没落地。
* 关掉之后第一个用户（管理员）怎么创建？必须有引导/首次启动流程，否则会把自己锁在门外。

所以用 strict xfail 钉成**可见**缺口，接线即转红。

## 前提守卫（必须常绿）

严重级别依赖下面五条事实，任何一条变化都要重估结论：

* ① `/api/auth/register` 确实无条件在 `_PUBLIC_PATHS` 里
* ② 注册出的 role 确实被硬编码为 `viewer`（无提权）
* ③ admin 用户名确实被显式拒绝
* ④ `.env.example` 确实出货了该键（这是「错误确认」的载体）
* ⑤ 限流确实是 best-effort（Redis 挂了就失效）
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
sys.path.insert(0, str(BACKEND))

APP = BACKEND / "app.py"
AUTH = BACKEND / "routers" / "auth.py"
CONFIG = BACKEND / "config.py"


def _src(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")


def _register_body() -> str:
    src = _src(AUTH)
    assert '@router.post("/auth/register")' in src, "注册端点结构变了，本文件需重新评估"
    return src.split('@router.post("/auth/register")', 1)[1].split("\n@router.", 1)[0]


# ═══════════════════════════════════════════
# 前提守卫：严重级别依赖的五条事实
# ═══════════════════════════════════════════

def test_register_endpoint_is_unconditionally_public():
    """前提①：`/api/auth/register` 无条件在 `_PUBLIC_PATHS` 里。

    没有这一条，「公开端点上的空操作闸门」这个严重级别就不成立。
    """
    src = _src(APP)
    m = re.search(r"_PUBLIC_PATHS\s*=\s*frozenset\(\{(.*?)\}\)", src, re.S)
    assert m, "app.py 不再定义 _PUBLIC_PATHS"
    paths = re.findall(r'"([^"]+)"', m.group(1))
    assert "/api/auth/register" in paths, (
        f"注册端点已从白名单移除（当前 {paths}）—— "
        "若它现在需要鉴权，本条的严重级别要下调，请更新整改报告 §7.1.12"
    )


def test_registered_role_is_hardcoded_viewer_so_there_is_no_privilege_escalation():
    """前提②：注册出的账号 role 被**硬编码**为 `viewer`。

    这条决定了本条的**上限**：没有提权，影响是「无界账号创建」而非权限提升。
    任何夸大严重级别的表述都应在这里被挡住。
    """
    body = _register_body()
    m = re.search(r"create_user\([^)]*\)", body, re.S)
    assert m, "注册路径不再调用 create_user —— 账号创建方式变了，需重新评估"
    assert re.search(r"role\s*=\s*[\"']viewer[\"']", m.group(0)), (
        f"create_user 的 role 不再硬编码为 viewer：{m.group(0)!r} —— "
        "若提权路径出现，本条严重级别需上调"
    )


def test_admin_username_is_still_rejected():
    """前提③：admin 用户名仍被显式拒绝。"""
    body = _register_body()
    assert "settings.admin_user" in body and "不可用" in body, (
        "注册端点不再拒绝占用内置 admin 用户名 —— 请重新评估本条严重级别"
    )


def test_env_example_ships_the_key_that_does_nothing():
    """前提④：`.env.example` **确实**出货了 `SHARED_MEMORY_ALLOW_SELF_REGISTRATION=false`。

    这条是「错误确认」的载体 —— 运维配了它会以为注册已关闭。
    若哪天从 `.env.example` 摘掉了，本条从「危险」降级为「缺失信息」。
    """
    env = (REPO / ".env.example").read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"^\s*SHARED_MEMORY_ALLOW_SELF_REGISTRATION\s*=\s*(\S+)", env, re.M)
    assert m, (
        ".env.example 不再出货 SHARED_MEMORY_ALLOW_SELF_REGISTRATION —— "
        "若是有意摘除，请把 test_security_fixes_2026_10_03.py 里那条断言一并处理"
    )
    assert m.group(1).strip().lower() in ("false", "0"), (
        f"出货值变成了 {m.group(1)!r} —— 但该键仍无实现，请更新整改报告 §7.1.12"
    )


def test_rate_limit_is_best_effort_and_fails_open():
    """前提⑤：限流是 best-effort —— Redis 挂了就**整个失效且不报错**。

    所以「有限流」不能写成缓解措施。若哪天改成 fail-closed，
    本条的严重级别要相应下调。
    """
    body = _register_body()
    assert "register:rate:" in body, "注册限流已移除，请重估严重级别"
    m = re.search(r"except\s+Exception\s*:\s*\n\s*pass", body)
    assert m, (
        "注册限流的异常分支不再吞掉异常 —— "
        "若已改成 fail-closed（限流不可用即拒绝），请更新整改报告 §7.1.12 的严重级别"
    )


# ═══════════════════════════════════════════
# 主断言（strict xfail）：接线即转红
# ═══════════════════════════════════════════

def test_settings_has_allow_self_registration_field():
    """`config.py` 必须有 `allow_self_registration` 字段（默认 `False`）。

    审计文档 `:139` 写明的实施方案就是这一行，至今不存在。
    """
    body = _src(CONFIG).split("class Settings", 1)[1]
    m = re.search(r"^\s{4}allow_self_registration\s*:\s*bool\s*=\s*(\S+)", body, re.M)
    assert m, "config.py 仍没有 allow_self_registration 字段"
    assert m.group(1).rstrip(",") in ("False", "false"), (
        f"默认值是 {m.group(1)!r} —— 审计文档要求默认 False（关闭公开注册）"
    )


def test_register_handler_honors_the_gate():
    """注册端点必须在开关关闭时拒绝请求。

    现在 `routers/auth.py:115-172` 全程没有读任何开关，
    `.env.example` 的 `SHARED_MEMORY_ALLOW_SELF_REGISTRATION=false` 是空操作。

    **接线时要一起解决的**（别只加一个 if）：
      * 默认 `False` 后，第一个管理员账号怎么创建？需要引导/首次启动流程，
        否则会把自己锁在门外 —— 审计文档的「`.env.demo.example` 加 true」
        方案不可用，因为仓库里**没有** `.env.demo.example`；
      * 关闭时该返回 403 还是 404？（404 不泄露「注册功能存在」）
      * 关闭与限流失败的组合语义要写进 docstring。
    """
    body = _register_body()
    reads = [ln for ln in body.splitlines()
             if re.search(r"(getattr\s*\(\s*settings\s*,\s*[\"']allow_self_registration"
                          r"|settings\.allow_self_registration)", ln)
             and not ln.strip().startswith("#")]
    assert reads, (
        "注册端点没有读 allow_self_registration —— 开关仍然失效，"
        ".env.example 出货的 false 依然不阻止任何人注册"
    )


def test_the_gate_is_enforced_in_the_handler_not_only_documented():
    """闸门必须在 handler 内真实生效，而不是只出现在 `.env.example`。

    这里直接检查 `routers/auth.py` 的执行路径：
      * 读取 `settings.allow_self_registration`；
      * 关闭时返回 403（不继续创建账号）。
    """
    body = _register_body()
    assert re.search(
        r"if\s+not\s+getattr\(\s*settings\s*,\s*[\"']allow_self_registration[\"']\s*,\s*False\s*\)",
        body,
    ), "注册 handler 没有在入口处读取 allow_self_registration"
    assert re.search(r"raise\s+HTTPException\(\s*status_code\s*=\s*403", body), (
        "注册 handler 在开关关闭时没有返回 403"
    )
