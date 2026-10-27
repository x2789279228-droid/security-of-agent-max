# -*- coding: utf-8 -*-
"""路线 4(2026-10-27)回归: DNS 查询域 / 文件哈希字段的四层贯通。

四层 = ingestion 别名归一 → mapping.py Sigma 别名 → JSON/Avro/Java 契约 →
SigmaHQ 导入器 COMPAT_FIELDS(116→125 实测, +9 条 dns 影子规则)。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_ingestion import LogIngestor  # noqa: E402
from sigma_detector import sigma_detector_legacy  # noqa: E402
from sigma_engine.mapping import apply_mapping  # noqa: E402


def test_mapping_emits_dns_and_hash_aliases():
    out = apply_mapping({
        "dns_query": "xk7fh2.evil-example.net",
        "file_hash": "a" * 64,
        "src_ip": "1.2.3.4",
    })
    # SigmaHQ dns 规则用裸 `query` 字段
    assert out.get("query") == "xk7fh2.evil-example.net"
    # 平台原名保留(双名引用)
    assert out.get("dns_query") == "xk7fh2.evil-example.net"
    assert out.get("sha256") == "a" * 64
    assert out.get("file_hash") == "a" * 64


def test_ingestion_normalizes_aliases():
    svc = LogIngestor()
    out = svc._normalize_fields({
        "event": "DNS_QUERY", "dnsQuery": "evil.example.net",
        "sha256": "b" * 64,
        "rawData": {"rrname": "from-raw.evil.net"},
    })
    assert out["dns_query"] == "evil.example.net"
    assert out["file_hash"] == "b" * 64
    # rawData 兜底: 顶层缺 dns_query 时从 rawData.rrname 提取
    out2 = svc._normalize_fields({"event": "DNS_QUERY",
                                  "rawData": {"rrname": "from-raw.evil.net"}})
    assert out2["dns_query"] == "from-raw.evil.net"


def test_sigma_detector_fieldmap_normalizes():
    out = sigma_detector_legacy._normalize_fields({"dnsQuery": "a.invalid", "sha256": "c" * 64})
    assert out["dns_query"] == "a.invalid"
    assert out["file_hash"] == "c" * 64


def test_cross_runtime_contract_has_new_fields():
    """JSON(两份) + Avro + Java @JsonProperty 四处必须同时携带新字段。"""
    root = Path(__file__).resolve().parent.parent.parent
    for rel in ("backend/schemas/security_event.schema.json",
                "contracts/baseline/security_event.schema.json"):
        d = json.loads((root / rel).read_text(encoding="utf-8"))
        for k in ("dnsQuery", "fileHash"):
            assert k in d["properties"], f"{rel} 缺 {k}"
            assert d["properties"][k]["type"] == ["string", "null"], \
                f"{rel}.{k} 必须可空(与 Avro 对齐)"
    avro = (root / "flink-jobs" / "schemas" / "security-event.avsc").read_text(encoding="utf-8")
    for k in ("dnsQuery", "fileHash"):
        assert f'"name": "{k}"' in avro
    java = (root / "flink-jobs" / "src/main/java/com/soc/model/SecurityEvent.java"
            ).read_text(encoding="utf-8")
    for k in ("dnsQuery", "fileHash"):
        assert f'@JsonProperty("{k}")' in java


def test_sigmahq_manifest_measured_delta():
    """实测口径钉住: 路线 4 后 field_compatible 必须 ≥125(基线 116)。"""
    m = json.loads((Path(__file__).resolve().parent.parent / "sigma_engine" /
                    "SIGMAHQ_MANIFEST.json").read_text(encoding="utf-8"))
    assert m["field_compatible"] >= 125, (
        f"field_compatible={m['field_compatible']} 跌回基线 116 附近 —— "
        "mapping/COMPAT_FIELDS 的 DNS 解锁面丢了"
    )
    assert m["compiled_ok"] >= m["field_compatible"]
    # dns 影子规则确实写入
    active = (Path(__file__).resolve().parent.parent / "sigma_engine" /
              "rules_community_active")
    hq = list(active.glob("hq_*.yml"))
    assert len(hq) >= 125
