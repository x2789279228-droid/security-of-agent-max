"""
prompts.loader — Jinja2 LLM 提示词统一加载/渲染器
================================================

把散落在各业务文件里的 LLM 提示词集中到 backend/prompts/**/*.j2 模板,
统一由本模块加载并渲染。好处:
  - 提示词集中管理 / 可 Diff / 可版本化 / 可被存储到 DB 或审计
  - 变量用 Jinja2 语法 {{ var }}, 调用点不再手拼 f-string

用法::

    from prompts import render
    sys = render("audit/executor_synthesize", evidence=..., grounded=...)
    user = prompt                      # 非模板的动态副文本仍留业务侧

设计:
  - FileSystemLoader 指向 backend/prompts/
  - 模板懒加载并缓存; 渲染默认 __missing__ 不抛错(ChainableUndefined),
    便于渐进迁移; 上线稳定后可切 strict(见 strict_render)。
"""
import logging
import os
from typing import TYPE_CHECKING

from jinja2 import ChainableUndefined, Environment, FileSystemLoader, StrictUndefined, TemplateNotFound

logger = logging.getLogger(__name__)

PROMPTS_DIR = os.path.dirname(os.path.abspath(__file__))

_env = Environment(
    loader=FileSystemLoader(PROMPTS_DIR),
    autoescape=False,          # LLM 提示词不需要 HTML 转义
    trim_blocks=True,
    lstrip_blocks=True,        # 去掉控制块行的缩进, 保证模板正文干净
    undefined=ChainableUndefined,
)
if TYPE_CHECKING:  # 仅注解引用, 运行时不需要
    from jinja2 import Template

_cache: dict[str, "Template"] = {}

# 模板相对路径 → 变量说明 的注册表(供文档/审计/校验)
REGISTRY: dict[str, dict] = {}

# P2-E-5: 生产路径的严格变量开关。**默认开启**。
# 理由：实测全部字面量 render() 调用点（57 个）零缺失，
# 宽松模式换来的只是「静默的空提示词」。
# 确需临时退回用 SHARED_MEMORY_PROMPT_PERMISSIVE=1。
_RENDER_STRICT = os.environ.get(
    "SHARED_MEMORY_PROMPT_PERMISSIVE", ""
) not in ("1", "true", "yes")


class MissingTemplateVars(Exception):
    """P2-E-5: 调用点漏传模板变量。

    独立异常类型，使调用方能区分「提示词不完整」与「模板不存在」。
    """

    def __init__(self, name: str, missing: list):
        super().__init__(f"template {name} missing vars: {missing}")
        self.template = name
        self.missing = list(missing)


def set_strict_render(enabled: bool) -> bool:
    """开关严格渲染，返回切换前的状态（便于测试还原）。"""
    global _RENDER_STRICT
    prev = _RENDER_STRICT
    _RENDER_STRICT = bool(enabled)
    return prev


def render_is_strict() -> bool:
    return _RENDER_STRICT


def load(name: str):
    """按相对路径(不含 .j2, 如 'audit/executor_synthesize')加载模板(带缓存)。"""
    tpl = _cache.get(name)
    if tpl is None:
        try:
            tpl = _env.get_template(f"{name}.j2")
        except TemplateNotFound as e:
            raise FileNotFoundError(f"prompt template not found: {name}") from e
        _cache[name] = tpl
    return tpl


def template_variables(name: str) -> set:
    """返回模板源码里引用到的**顶层**变量名集合。

    P2-E-5: 用来建立「模板需要什么」的权威口径。
    修复前的完整性检查靠一张手工维护的 mock 上下文表 ——
    表里写了什么就只校验什么，模板新增变量而表没跟上时
    校验会静默通过（ChainableUndefined 渲染成空串）。

    实现要点：直接用 Jinja2 解析 AST，不做正则猜测。
    只取顶层 `name` / `name.attr` 的根名字；
    for/if 内部引入的循环变量（如 item）不算契约。
    """
    from jinja2 import nodes as jnodes

    try:
        source, _fn, _up = _env.loader.get_source(_env, f"{name}.j2")
    except Exception:
        return set()

    try:
        ast = _env.parse(source)
    except Exception as e:  # noqa: BLE001
        logger.warning("template %s parse failed: %s", name, e)
        return set()

    declared = set()
    for node in ast.find_all(jnodes.Name):
        if node.ctx == "load":
            declared.add(node.name)
    # 宏/导入等引入的名字不算调用方需要提供
    return declared - _template_local_names(ast)


def _template_local_names(ast) -> set:
    """模板内部自己定义的变量（for target / 宏 / set 块）。"""
    from jinja2 import nodes as jnodes

    local: set = set()
    for node in ast.find_all(jnodes.Name):
        if node.ctx in ("store", "param"):
            local.add(node.name)
    for node in ast.find_all(jnodes.Assign):
        for t in node.targets:
            if isinstance(t, jnodes.Name):
                local.add(t.name)
    return local


def render(name: str, **ctx) -> str:
    """渲染模板。缺省变量以空替代(ChainableUndefined), 利于渐进迁移。

    P2-E-5: 新增 ``_RENDER_STRICT`` 开关 —— 生产调用点缺变量时**抛错**。
    缺省变量渲染成空串意味着：模板里 ``{{ evidence }}`` 在调用点漏传时
    变成一个空洞的提示词，模型照常给出「看起来正常」的结论，
    而没有任何日志表明这条提示词是不完整的。
    """
    if _RENDER_STRICT:
        missing = template_variables(name) - set(ctx)
        if missing:
            raise MissingTemplateVars(name, sorted(missing))
    return load(name).render(**ctx)


def strict_render(name: str, **ctx) -> str:
    """严格渲染: 任何未提供变量直接抛错, 用于模板完善后的校验/测试。"""
    tpl = _cache.get(name)
    if tpl is None:
        tpl = _env.get_template(f"{name}.j2")
        _cache[name] = tpl
    # 用 loader.get_source 获取模板源码(兼容 Jinja2 Template 无 .source 属性)
    try:
        source, _filename, _uptodate = _env.loader.get_source(_env, f"{name}.j2")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"prompt template source not readable: {name}") from e
    env2 = Environment(
        loader=FileSystemLoader(PROMPTS_DIR),
        autoescape=False, trim_blocks=True, lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    return env2.from_string(source).render(**ctx)


def register(name: str, note: str = ""):
    """声明/登记一个模板的用途。"""
    REGISTRY[name] = {"path": f"{name}.j2", "note": note}
    return name


def reload():
    """清缓存, 便于开发期热更。"""
    _cache.clear()
