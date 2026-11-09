"""B1 一致性守卫（REMEDIATION-PLAN-2026-10-30 路线 B1）。

Sigma 规则导入面的两份字段表**不许漂移**：
  - `sigma_engine/mapping.py::PLATFORM_TO_SIGMA` —— 平台归一字段能产出哪些
    Sigma 侧字段（检测引擎实际可命中的面）；
  - `tools/import_sigmahq.py::COMPAT_FIELDS` —— SigmaHQ 规则导入时允许的
    检测字段（字段不在表内 = 平台无源可命中 = 死重，导入器剔除）。

不变式：**mapping 的全部目标字段 ⊆ COMPAT_FIELDS**。只改一边（例如给
mapping 加了 `EventID` 却忘了同步导入器）→ 大批规则被误剔除，且不会有
任何报错 —— 本文件让这种漂移当场转红。

第二批键（2026-10-30）：event_id / process_name / command_line /
parent_process / user_name / image_hash / file_path / registry_key，
来源 = `edr_fusion/sysmon_parser.py::SysmonEvent.to_dict()` 归一键。
"""
from pathlib import Path
import sys

import pytest

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(REPO / "tools"))

from sigma_engine.mapping import PLATFORM_TO_SIGMA, _HASH_TARGETS, apply_mapping  # noqa: E402

from import_sigmahq import COMPAT_FIELDS  # noqa: E402  (tools/import_sigmahq.py)


def _all_mapping_targets() -> set:
    targets: set = set()
    for tgts in PLATFORM_TO_SIGMA.values():
        targets.update(tgts)
    for tgts in _HASH_TARGETS.values():
        targets.update(tgts)
    return targets


def test_mapping_targets_are_all_importable():
    """mapping 能产出的每个 Sigma 字段，都必须在导入白名单内。"""
    leaked = _all_mapping_targets() - COMPAT_FIELDS
    assert not leaked, (
        f"mapping.py 新增了 COMPAT_FIELDS 不认识的字段: {sorted(leaked)} —— "
        "用这些字段的 SigmaHQ 规则会被导入器整体剔除, 请同步 "
        "tools/import_sigmahq.py::COMPAT_FIELDS"
    )


def test_compat_fields_second_batch_present():
    """第二批(Sysmon/linux)字段双表都在 —— 防只删不加的反向漂移。"""
    second_batch = {
        "EventID", "Image", "ImageLoaded", "CommandLine", "ProcessCommandLine",
        "ParentImage", "ParentProcessName", "User", "SubjectUserName",
        "TargetFilename", "TargetObject",
        "process.name", "process.command_line", "user.name", "file.path",
    }
    assert second_batch <= COMPAT_FIELDS, sorted(second_batch - COMPAT_FIELDS)
    assert second_batch <= _all_mapping_targets()


def test_sysmon_parser_keys_covered_by_mapping():
    """sysmon_parser 的归一产出键必须是 mapping 的源键（解析器↔映射对齐）。"""
    from edr_fusion.sysmon_parser import SysmonEvent

    evt = SysmonEvent().to_dict()
    required = {
        "event_id", "process_name", "command_line", "parent_process",
        "user_name", "image_hash", "file_path", "registry_key",
    }
    missing = required - evt.keys()
    assert not missing, f"sysmon_parser 不再产出: {sorted(missing)}"
    unmapped = required - PLATFORM_TO_SIGMA.keys()
    assert not unmapped, (
        f"sysmon_parser 产出但 mapping 无源键: {sorted(unmapped)} —— "
        "解析器改名时必须同步 sigma_engine/mapping.py"
    )


def test_apply_mapping_second_batch_fields():
    """第二批字段的映射行为（含 image_hash 按长度路由 sha256）。"""
    sha = "a" * 64
    out = apply_mapping({
        "event_id": 1,
        "process_name": "C:\\Windows\\Temp\\evil.exe",
        "command_line": "evil.exe -enc AAAA",
        "parent_process": "C:\\Windows\\System32\\cmd.exe",
        "user_name": "CORP\\alice",
        "file_path": "C:\\Users\\b\\bad.dll",
        "registry_key": "HKCU\\Software\\Evil\\Run",
        "image_hash": sha,
    })
    assert out["EventID"] == 1
    assert out["Image"] == "C:\\Windows\\Temp\\evil.exe"
    assert out["ImageLoaded"] == "C:\\Windows\\Temp\\evil.exe"
    assert out["CommandLine"] == "evil.exe -enc AAAA"
    assert out["ParentImage"] == "C:\\Windows\\System32\\cmd.exe"
    assert out["ParentProcessName"] == "C:\\Windows\\System32\\cmd.exe"
    assert out["User"] == "CORP\\alice"
    assert out["TargetFilename"] == "C:\\Users\\b\\bad.dll"
    assert out["TargetObject"] == "HKCU\\Software\\Evil\\Run"
    # image_hash(64 hex) → sha256 专属目标 + 泛化 file_hash, 不污染 md5/sha1
    assert out["sha256"] == sha
    assert out["file_hash"] == sha
    assert "md5" not in out and "sha1" not in out


def test_apply_mapping_image_hash_dirty_value_not_routed():
    """非 hex / 非标长的脏哈希只落泛化名, 不猜算法。"""
    out = apply_mapping({"image_hash": "not-a-hash"})
    assert out["file_hash"] == "not-a-hash"
    assert "sha256" not in out and "md5" not in out
