"""E1 修复钉：sysmon_parser 事件时间提取 + 跨源关联键（capabilities edr 两待修）。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from edr_fusion.sysmon_parser import SysmonParser

_XML = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    "<System><EventID>1</EventID>"
    '<TimeCreated SystemTime="2026-10-30T01:02:03.456789Z"/>'
    "<Computer>WIN-TEST</Computer></System>"
    "<EventData>"
    '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>'
    '<Data Name="CommandLine">cmd /c whoami</Data>'
    '<Data Name="ProcessGuid">{ABC12345-0000-0000-0000-000000000001}</Data>'
    '<Data Name="ParentImage">C:\\x.exe</Data>'
    "</EventData></Event>"
)


def test_timestamp_extracted_from_xml():
    e = SysmonParser().parse(_XML)
    assert e is not None
    assert e.to_dict()["timestamp"] == "2026-10-30T01:02:03.456789Z"


def test_computer_from_system_node():
    """Computer 在 System 节点而非 EventData —— 修复前恒空。"""
    e = SysmonParser().parse(_XML)
    assert e.to_dict()["computer_name"] == "WIN-TEST"


def test_correlation_key_uses_process_guid():
    """修复前 `computer:process:event_id` 把同机同类型事件全部关联。"""
    e = SysmonParser().parse(_XML)
    key = e.to_dict()["correlation_key"]
    assert key == "WIN-TEST:abc12345-0000-0000-0000-000000000001"
    # 同机另一进程(不同 Guid)不得同键 —— 修复前 EventID=1 的它们会同键
    xml_other = _XML.replace("ABC12345", "FFF99999")
    key2 = SysmonParser().parse(xml_other).to_dict()["correlation_key"]
    assert key2 != key


def test_correlation_key_fallback_without_guid():
    """无 Guid 的源降级 computer:pid:process_name, 不回退到 event_id 形态。"""
    e = SysmonParser().parse_dict({
        "EventID": 3,
        "EventData": {"Image": "C:/a.exe", "ProcessId": "488", "SystemTime": "2026-10-30T00:00:00Z"},
        "Computer": "HOST2",
    })
    d = e.to_dict()
    assert d["correlation_key"] == "HOST2:488:C:/a.exe"
    assert d["timestamp"] == "2026-10-30T00:00:00Z"


def test_same_guid_across_event_types_correlates():
    """同一进程的不同事件类型(EID1/EID3)应同键 —— 跨源关联的语义本体。"""
    p = SysmonParser()
    k1 = p.parse(_XML).to_dict()["correlation_key"]
    xml3 = _XML.replace("<EventID>1</EventID>", "<EventID>3</EventID>")
    k3 = p.parse(xml3).to_dict()["correlation_key"]
    assert k1 == k3
