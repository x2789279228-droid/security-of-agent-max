# -*- coding: utf-8 -*-
"""`.env` 隔离开关必须**真的**隔离（整改报告 §9.48）。

## 背景（一次真实踩坑）

`config.py` 里有**两条**读 `.env` 的通道：

1. `_load_project_root_env()` —— 手工把**项目根** `.env` 灌进 `os.environ`；
   由 `SHARED_MEMORY_SKIP_DOTENV` 开关把守着（2026-10-03 加的）。
2. `class Config: env_file = ".env"` —— **pydantic-settings 自己的 dotenv 源**，
   读的是 **CWD** 下的 `.env`。**此前是无条件的**，开关管不到它。

实测后果（2026-10-20）：

- README 文档的 `pytest backend/tests -q`（**仓库根**执行）在**收集期**直接崩：
  `16 validation errors ... Extra inputs are not permitted`。
  根因：仓库根有 `.env`，里面的键既不是 `SHARED_MEMORY_` 前缀、
  也不是 `Settings` 的声明字段；pydantic-settings 会把 dotenv 里
  **任何未声明的键**当成 extra 塞进数据（`extra="forbid"` ⇒ 直接抛）。
  **conftest 已经设了开关，仍然崩** —— 开关根本没管到这条通道。
- 更糟的一半（今天只是「响亮地崩」）：一旦 `.env` 的键都是合法的，
  **任何以仓库根为 CWD 启动的进程都会把真实密钥读进 Settings**，
  而开关显示「已隔离」—— 那是**假安全感**，不是隔离。

## 本守卫盯什么

1. **开关打开 ⇒ 一个 `.env` 都不读**（含「内容不进 Settings」这一层）；
2. **开关关闭 ⇒ dotenv 通道仍然活着**（反向判据：修复不得顺手把生产
   读 `.env` 的能力关掉 —— 那是**放宽**，不是修复）；
3. 同一份 `.env`（含未声明键）：**开关开 → 不崩；开关关 → 崩**。
   这一对是本守卫的核心：**同一个文件，只差一个开关**。
4. **README 文档的路径**（仓库根执行）必须不再崩。

⚠ 判据用**行为**（子进程真实 import `config` 的结果），不用源码文本。
子进程是必要的：同一进程里 `config` 只能以**一种开关状态**被 import。
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))

#: 探针字段：取一个「不可能是秘密、默认值有辨识度」的字段。
#: 开关打开时进程内**没有任何 .env 注入通道**（os.environ 注入被跳、
#: dotenv 源也被跳过），所以它的值必然是默认值 ——
#: 判定**与开发者机器上真实 `.env` 的内容无关**（这是本守卫能稳定的原因）。
PROBE_FIELD = "llm_price_input_per_1k_tokens"
PROBE_ENV = "SHARED_MEMORY_LLM_PRICE_INPUT_PER_1K_TOKENS"
PROBE_FROM_FILE = "0.123456"

#: 故意放一个**未声明**的键：dotenv 源若生效，它会被当成 extra
#: ⇒ `extra="forbid"` ⇒ ValidationError（这正是仓库根崩溃的机制）。
UNDECLARED_KEY = "ZZZ_NOT_A_SETTING_FIELD"

#: 子进程只继承这些变量 —— **必须**是「干净环境」。
#:
#: 踩过的坑（本守卫第一版就是这么写的，结果**永远不会红**）：
#: 若子进程继承父进程的全部 `os.environ`，而父进程自己已经 import 过
#: `config`（loader 生效时它会把 97 个键灌进 `os.environ`），
#: 那么 loader 在子进程里「不覆盖已存在的键」⇒ 差集**恒为空** ——
#: 守卫测的正是「有没有被注入」，而它测的环境**已经被注入过了**。
#: 判据的前提没被验证，检查就成了摆设。
_MINIMAL_ENV_KEYS = (
    "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATH", "PATHEXT", "COMSPEC",
    "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
)


def _minimal_env(extra: dict | None = None) -> dict:
    env = {k: os.environ[k] for k in _MINIMAL_ENV_KEYS if k in os.environ}
    env["PYTHONPATH"] = str(BACKEND) + (
        os.pathsep + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else "")
    env["PYTHONIOENCODING"] = "utf-8"
    if extra:
        env.update(extra)
    return env


def _run(cwd: Path, switch: str | None, extra_env: dict | None = None):
    extra = dict(extra_env or {})
    # 探针字段不许被外部环境干扰：唯一的可能来源只能是 .env 文件本身
    extra.pop(PROBE_ENV, None)
    if switch is None:
        extra.pop("SHARED_MEMORY_SKIP_DOTENV", None)
    else:
        extra["SHARED_MEMORY_SKIP_DOTENV"] = switch
    env = _minimal_env(extra)
    code = "import config; print(getattr(config.settings, %r))" % PROBE_FIELD
    return subprocess.run(
        [sys.executable, "-c", code], cwd=str(cwd), env=env,
        capture_output=True, text=True, timeout=180,
        encoding="utf-8", errors="replace")


def _dotenv_dir(content: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix="dotenv_isolation_"))
    (d / ".env").write_text(content, encoding="utf-8")
    return d


class TestTheSwitchReallyControlsTheDotenvChannel:
    def test_with_the_switch_on_the_file_content_does_not_reach_settings(self):
        """开关打开 ⇒ `.env` 里的值**进不来**（不是「读进来但被覆盖」）。"""
        d = _dotenv_dir(f"{PROBE_ENV}={PROBE_FROM_FILE}\n")
        r = _run(d, switch="1")
        assert r.returncode == 0, f"import config 失败：\n{r.stdout}\n{r.stderr}"
        assert PROBE_FROM_FILE not in r.stdout, (
            f"开关打开却把 .env 的值读进了 Settings：{r.stdout!r}")
        assert "0.0" in r.stdout, f"探针字段不是默认值：{r.stdout!r}"

    def test_with_the_switch_on_an_undeclared_key_does_not_crash(self):
        """开关打开 ⇒ dotenv 源**根本没被读** ⇒ 未声明的键不会变成 extra。"""
        d = _dotenv_dir(f"{UNDECLARED_KEY}=1\n")
        r = _run(d, switch="1")
        assert r.returncode == 0, (
            f"开关打开仍因 .env 崩溃（这正是仓库根那 16 条 extra 的机制）：\n"
            f"{r.stdout}\n{r.stderr}")

    def test_with_the_switch_off_the_dotenv_channel_is_still_alive(self):
        """**反向判据**：开关关闭 ⇒ dotenv 通道必须仍然生效。

        修复不得顺手把「生产读 `.env`」的能力关掉 —— 那是**放宽**，
        不是修复。判据用「未声明键会让 import 崩」这个**可观测行为**，
        不依赖任何字段值（真实 `.env` 里有没有同名字段都不影响）。
        """
        d = _dotenv_dir(f"{UNDECLARED_KEY}=1\n")
        r = _run(d, switch=None)
        assert r.returncode != 0, "开关关闭时 dotenv 通道竟然没生效 —— 生产读不到 .env 了"
        # pydantic 会把 dotenv 的键**小写化**后再报出来，判定必须大小写无关
        blob = (r.stdout + r.stderr).lower()
        assert UNDECLARED_KEY.lower() in blob, (
            f"崩溃原因不是 dotenv 里的未声明键：\n{r.stdout}\n{r.stderr}")

    def test_with_the_switch_on_the_manual_loader_injects_nothing(self):
        """开关打开 ⇒ 手工 loader（`_load_project_root_env`）也**不许**注入任何东西。

        那是开关**原本**要挡的通道：把项目根 `.env` 灌进 `os.environ`，
        会被直接读 `os.environ` 的模块看到（SSH 密钥 / Qdrant / 加密密钥）。
        判据：`import config` 前后 `os.environ` 的**新增键集合**必须为空。

        （本机仓库根有 `.env` 时这条是**真检查**；没有 `.env` 的机器上平凡通过 ——
        那正是上面「同一个文件只差一个开关」那一对要补上的缺口。）
        """
        code = ("import os, json; before = set(os.environ); import config; "
                "print(json.dumps(sorted(set(os.environ) - before)))")
        env = _minimal_env({"SHARED_MEMORY_SKIP_DOTENV": "1"})
        r = subprocess.run([sys.executable, "-c", code], cwd=str(REPO_ROOT), env=env,
                           capture_output=True, text=True, timeout=180,
                           encoding="utf-8", errors="replace")
        assert r.returncode == 0, f"import config 失败：\n{r.stdout}\n{r.stderr}"
        added = (r.stdout or "").strip().splitlines()[-1] if (r.stdout or "").strip() else "[]"
        assert added == "[]", f"开关打开却往 os.environ 注入了键：{added}"

    def test_the_same_file_crashes_only_when_the_switch_is_off(self):
        """**核心一对**：同一份 `.env`，只差一个开关 —— 关则崩、开则不崩。"""
        d = _dotenv_dir(f"{UNDECLARED_KEY}=1\n")
        on = _run(d, switch="1")
        off = _run(d, switch=None)
        assert on.returncode == 0, f"开关打开不该崩：\n{on.stdout}\n{on.stderr}"
        assert off.returncode != 0, "开关关闭时应当因未声明键而崩"


class TestTheDocumentedPathIsNotBlocked:
    def test_importing_config_from_the_repo_root_works_with_the_switch_on(self):
        """README 文档的 `pytest backend/tests -q` 是**仓库根**执行的。

        仓库根有 `.env`（开发者机器上）⇒ 此前在**收集期**直接崩。
        本例在**没有** `.env` 的机器上（CI）会平凡通过 ——
        真正的重量由上面「同一个文件只差一个开关」那一对承担；
        本例守的是**文档写明的路径**不被仓库根的 `.env` 堵死。
        """
        r = _run(REPO_ROOT, switch="1")
        assert r.returncode == 0, (
            f"从仓库根 import config 失败（README 文档的路径）：\n{r.stdout}\n{r.stderr}")


if __name__ == "__main__":       # pragma: no cover
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
