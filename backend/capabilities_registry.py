"""能力登记表加载器。

`capabilities.yaml` 是 Capabilities 页面的唯一事实源：状态（verified /
experimental / disabled）、证据链接、最后验证日期都在这里。运行开关仍由
config.Settings 决定，两者分开记录，避免“配置开了”被误读成“已验证”。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_REGISTRY = Path(__file__).parent / "capabilities.yaml"
_ALLOWED = {"verified", "experimental", "disabled"}


def load_registry(path: Path | None = None) -> dict[str, Any]:
    p = path or _REGISTRY
    if not p.is_file():
        return {"version": "", "updated_at": "", "capabilities": []}
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    caps = []
    for item in data.get("capabilities") or []:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        status = str(item.get("status") or "disabled")
        if status not in _ALLOWED:
            status = "disabled"
        caps.append({**item, "status": status})
    return {
        "version": str(data.get("version") or ""),
        "updated_at": str(data.get("updated_at") or ""),
        "capabilities": caps,
    }


def runtime_enabled(cap: dict, settings_obj: Any) -> bool:
    """配置开关；没有 runtime_setting 的能力视为常开（例如审计链路）。"""
    key = str(cap.get("runtime_setting") or "").strip()
    if not key:
        return True
    return bool(getattr(settings_obj, key, False))
