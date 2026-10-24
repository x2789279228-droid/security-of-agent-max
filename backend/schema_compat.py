"""
Schema 对齐与兼容性门禁。

权威来源: backend/schemas/*.schema.json（由 catalog.json 索引）
投影: Flink Avro、Java POJO
门禁:
  1. JSON ↔ Avro ↔ Java 字段/类型对齐
  2. 相对 baseline 的 FULL 兼容（新增必填、删必填、改类型、枚举增减）
  3. 共享 fixtures 能被 JSON Schema 校验通过
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

_JSON_PROP = re.compile(
    r'@JsonProperty\(\s*"([^"]+)"\s*\)\s*'
    r'(?:private|protected|public)\s+([\w.<>,\s\[\]]+?)\s+\w+\s*;',
    re.MULTILINE,
)


def find_repo_root(start: Optional[Path] = None) -> Path:
    here = (start or Path(__file__).resolve()).parent
    for p in [here.parent, here, here.parent.parent, here.parent.parent.parent]:
        if (p / "backend" / "schemas").is_dir() and (
            (p / "flink-jobs" / "schemas").is_dir() or (p / "contracts").is_dir()
        ):
            return p
        if (p / "contracts" / "catalog.json").is_file():
            return p
    return here.parent if here.name == "backend" else here


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_catalog(root: Optional[Path] = None) -> tuple[dict, Path]:
    root = root or find_repo_root()
    candidates = [
        root / "contracts" / "catalog.json",
        root / "backend" / "schemas" / "catalog.json",
        Path(__file__).resolve().parent / "schemas" / "catalog.json",
    ]
    for path in candidates:
        if path.is_file():
            return load_json(path), path
    raise FileNotFoundError("找不到 catalog.json")


def canonical_schema(obj: Any) -> str:
    if isinstance(obj, str):
        text = obj.strip()
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return text
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def schemas_equal(a: Any, b: Any) -> bool:
    return canonical_schema(a) == canonical_schema(b)


# ── JSON Schema 兼容 ──────────────────────────────────────────────


def _types(node: dict) -> set[str]:
    if not isinstance(node, dict):
        return {"any"}
    t = node.get("type")
    if t is None:
        if "enum" in node:
            return {"string"}
        return {"any"}
    if isinstance(t, list):
        return {str(x) for x in t}
    return {str(t)}


def _enum(node: dict) -> Optional[set[str]]:
    if not isinstance(node, dict) or "enum" not in node:
        return None
    return {str(x) for x in node["enum"]}


def _props(schema: dict) -> dict:
    return dict(schema.get("properties") or {}) if isinstance(schema, dict) else {}


def _required(schema: dict) -> set[str]:
    return {str(x) for x in (schema.get("required") or [])} if isinstance(schema, dict) else set()


def _type_ok(writer: set[str], reader: set[str]) -> bool:
    w = set(writer) - {"null"}
    r = set(reader) - {"null"}
    if not w or not r or "any" in r:
        return True
    if w <= r:
        return True
    if w == {"integer"} and "number" in r:
        return True
    if w == {"number"} and "integer" in r:
        return False
    return False


def compatibility_issues(current: dict, baseline: dict, mode: str = "FULL") -> list[str]:
    """比较 current 相对 baseline。FULL = 新旧消费者都能读对方写出的数据。"""
    mode = (mode or "FULL").upper()
    issues: list[str] = []
    old_props, new_props = _props(baseline), _props(current)
    old_req, new_req = _required(baseline), _required(current)
    check_back = mode in ("BACKWARD", "FULL", "FULL_TRANSITIVE")
    check_fwd = mode in ("FORWARD", "FULL", "FULL_TRANSITIVE")

    added_req = new_req - old_req
    if check_back:
        for name in sorted(added_req):
            issues.append(f"BACKWARD: 新增必填字段 {name}，旧数据无法通过新消费者")

    removed_req = old_req - new_req
    if check_fwd:
        for name in sorted(removed_req):
            issues.append(f"FORWARD: 必填字段 {name} 被降级或删除，旧消费者会拒收新数据")

    if check_fwd:
        for name in sorted(old_req):
            if name not in new_props:
                issues.append(f"FORWARD: 删除了旧消费者仍依赖的字段 {name}")

    names = set(old_props) | set(new_props)
    for name in sorted(names):
        if name not in old_props or name not in new_props:
            continue
        old, new = old_props[name], new_props[name]
        if not isinstance(old, dict) or not isinstance(new, dict):
            continue
        if check_back and not _type_ok(_types(old), _types(new)):
            issues.append(
                f"BACKWARD: 字段 {name} 类型 {sorted(_types(old))} → {sorted(_types(new))}"
            )
        if check_fwd and not _type_ok(_types(new), _types(old)):
            issues.append(
                f"FORWARD: 字段 {name} 类型 {sorted(_types(new))} 无法被旧消费者 {sorted(_types(old))} 接受"
            )
        old_e, new_e = _enum(old), _enum(new)
        if old_e is not None and new_e is not None:
            if check_back:
                missing = old_e - new_e
                if missing:
                    issues.append(f"BACKWARD: 枚举 {name} 删除了 {sorted(missing)}，旧数据会被拒")
            if check_fwd:
                extra = new_e - old_e
                if extra:
                    issues.append(f"FORWARD: 枚举 {name} 新增 {sorted(extra)}，旧消费者会拒收")

        old_add = old.get("additionalProperties", True)
        new_add = new.get("additionalProperties", True)
        if check_back and old_add is True and new_add is False:
            issues.append(f"BACKWARD: 字段 {name} 关闭 additionalProperties，旧的额外键会被拒")

    if check_back and baseline.get("additionalProperties", True) is True and current.get(
        "additionalProperties", True
    ) is False:
        issues.append("BACKWARD: 顶层关闭 additionalProperties，旧的额外字段会被拒")
    return issues


# ── JSON ↔ Avro ↔ Java 对齐 ────────────────────────────────────────


def _avro_types(field: dict) -> set[str]:
    raw = field.get("type")
    return _avro_type_names(raw)


def _avro_type_names(raw: Any) -> set[str]:
    if isinstance(raw, str):
        mapping = {
            "string": "string",
            "int": "integer",
            "long": "integer",
            "float": "number",
            "double": "number",
            "boolean": "boolean",
            "null": "null",
            "bytes": "string",
        }
        return {mapping.get(raw, raw)}
    if isinstance(raw, list):
        out: set[str] = set()
        for item in raw:
            out |= _avro_type_names(item)
        return out
    if isinstance(raw, dict):
        t = raw.get("type")
        if t == "enum":
            return {"string"}
        if t == "array":
            return {"array"}
        if t in ("map", "record"):
            return {"object"}
        if t:
            return _avro_type_names(t)
    return {"any"}


def parse_avro_fields(avro: dict) -> dict[str, dict]:
    return {f["name"]: f for f in avro.get("fields") or [] if "name" in f}


def parse_java_properties(source: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for match in _JSON_PROP.finditer(source):
        found[match.group(1)] = re.sub(r"\s+", " ", match.group(2)).strip()
    return found


def _java_types(decl: str) -> set[str]:
    d = decl.replace(" ", "")
    out: set[str] = set()
    if "String" in d:
        out.add("string")
    if any(x in d for x in ("int", "Integer", "long", "Long")):
        out.add("integer")
    if any(x in d for x in ("double", "Double", "float", "Float")):
        out.add("number")
    if any(x in d for x in ("boolean", "Boolean")):
        out.add("boolean")
    if "List" in d or "[]" in d:
        out.add("array")
    if "Map" in d:
        out.add("object")
    return out or {"any"}


def alignment_issues(
    json_schema: dict,
    avro: Optional[dict],
    java_source: Optional[str],
    *,
    runtime_extensions: Optional[list[str]] = None,
) -> list[str]:
    extras = set(runtime_extensions or [])
    issues: list[str] = []
    json_props = _props(json_schema)
    json_req = _required(json_schema)

    if avro:
        avro_fields = parse_avro_fields(avro)
        for name in sorted(json_props):
            if name in extras:
                continue
            if name not in avro_fields:
                issues.append(f"ALIGN: JSON 字段 {name} 在 Avro 中缺失")
                continue
            if not _type_ok(_avro_types(avro_fields[name]), _types(json_props[name])) and not _type_ok(
                _types(json_props[name]), _avro_types(avro_fields[name])
            ):
                issues.append(
                    f"ALIGN: 字段 {name} JSON 类型 {sorted(_types(json_props[name]))} "
                    f"与 Avro {sorted(_avro_types(avro_fields[name]))} 不一致"
                )
        for name in sorted(avro_fields):
            if name not in json_props:
                issues.append(f"ALIGN: Avro 字段 {name} 在 JSON Schema 中缺失")
        for name in sorted(json_req):
            if name in extras:
                continue
            if name not in avro_fields:
                issues.append(f"ALIGN: JSON 必填 {name} 在 Avro 中缺失")

    if java_source:
        java_props = parse_java_properties(java_source)
        for name in sorted(json_props):
            if name in extras:
                continue
            if name not in java_props:
                issues.append(f"ALIGN: JSON 字段 {name} 在 Java @JsonProperty 中缺失")
                continue
            jt = _java_types(java_props[name])
            js = _types(json_props[name]) - {"null"}
            if jt != {"any"} and js and not (jt & js) and not (
                "integer" in jt and "number" in js
            ) and not ("number" in jt and "integer" in js):
                issues.append(
                    f"ALIGN: 字段 {name} JSON 类型 {sorted(js)} 与 Java {java_props[name]} 不一致"
                )
        for name in sorted(java_props):
            if name in extras:
                continue
            if name not in json_props:
                issues.append(f"ALIGN: Java 字段 {name} 在 JSON Schema 中缺失")
        for name in sorted(json_req):
            if name in extras:
                continue
            if name not in java_props:
                issues.append(f"ALIGN: JSON 必填 {name} 在 Java 模型中缺失")
    return issues


def check_catalog(root: Optional[Path] = None) -> list[str]:
    root = root or find_repo_root()
    catalog, catalog_path = load_catalog(root)
    issues: list[str] = []
    other = root / "backend" / "schemas" / "catalog.json"
    if catalog_path.resolve() != other.resolve() and other.is_file():
        if canonical_schema(catalog) != canonical_schema(load_json(other)):
            issues.append("ALIGN: contracts/catalog.json 与 backend/schemas/catalog.json 不一致")

    for item in catalog.get("schemas") or []:
        name = item.get("name", "?")
        json_path = root / item["json_schema"]
        if not json_path.is_file():
            issues.append(f"{name}: 找不到 JSON Schema {json_path}")
            continue
        current = load_json(json_path)
        declared = current.get("x-schema-version") or item.get("version")
        if item.get("version") and declared and str(declared) != str(item["version"]):
            issues.append(f"{name}: catalog.version={item['version']} 与 x-schema-version={declared} 不一致")

        avro = None
        avro_path = root / item["avro"] if item.get("avro") else None
        if avro_path is not None:
            if avro_path.is_file():
                avro = load_json(avro_path)
            else:
                issues.append(f"{name}: 找不到 Avro {avro_path}")

        java_source = None
        java_path = root / item["java_model"] if item.get("java_model") else None
        if java_path is not None:
            if java_path.is_file():
                java_source = java_path.read_text(encoding="utf-8")
            else:
                issues.append(f"{name}: 找不到 Java 模型 {java_path}")

        issues.extend(
            f"{name}: {msg}"
            for msg in alignment_issues(
                current,
                avro,
                java_source,
                runtime_extensions=item.get("runtime_extensions") or [],
            )
        )

        baseline_rel = item.get("baseline")
        if baseline_rel:
            baseline_path = root / baseline_rel
            if not baseline_path.is_file():
                issues.append(f"{name}: 找不到 baseline {baseline_path}")
            else:
                mode = item.get("compatibility") or catalog.get("compatibility") or "FULL"
                issues.extend(
                    f"{name}: {msg}"
                    for msg in compatibility_issues(current, load_json(baseline_path), mode)
                )
    return issues


def check_fixtures(root: Optional[Path] = None) -> list[str]:
    root = root or find_repo_root()
    try:
        from jsonschema import Draft7Validator
    except ImportError:
        return ["jsonschema 未安装，跳过 fixture 校验"]
    issues: list[str] = []
    security = load_json(root / "backend" / "schemas" / "security_event.schema.json")
    alert = load_json(root / "backend" / "schemas" / "alert_event.schema.json")
    envelope = load_json(root / "backend" / "schemas" / "envelope.schema.json")
    fixture_dir = root / "contracts" / "fixtures"
    mapping = {
        "security_event.valid.json": security,
        "security_event.legacy.json": security,
        "alert_event.valid.json": alert,
        "security_event.envelope.json": envelope,
    }
    for filename, schema in mapping.items():
        path = fixture_dir / filename
        if not path.is_file():
            issues.append(f"FIXTURE: 缺少 {path}")
            continue
        data = load_json(path)
        validator = Draft7Validator(schema)
        errs = [e.message for e in validator.iter_errors(data)]
        if errs:
            issues.append(f"FIXTURE {filename}: {errs[0]}")
        if filename == "security_event.envelope.json":
            payload_errs = [e.message for e in Draft7Validator(security).iter_errors(data.get("payload") or {})]
            if payload_errs:
                issues.append(f"FIXTURE {filename} payload: {payload_errs[0]}")
    java_dir = root / "flink-jobs" / "src" / "test" / "resources" / "fixtures"
    if java_dir.is_dir():
        for name in (
            "security_event.valid.json",
            "security_event.legacy.json",
            "security_event.envelope.json",
            "alert_event.valid.json",
        ):
            left = fixture_dir / name
            right = java_dir / name
            if left.is_file() and right.is_file():
                if canonical_schema(load_json(left)) != canonical_schema(load_json(right)):
                    issues.append(f"FIXTURE: Python/Flink 副本不一致 {name}")
            elif left.is_file() and not right.is_file():
                issues.append(f"FIXTURE: Flink 测试资源缺少 {name}")
    return issues


def run_gate(root: Optional[Path] = None) -> list[str]:
    root = root or find_repo_root()
    return check_catalog(root) + check_fixtures(root)


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = find_repo_root()
    if "--register" in args:
        # 注册前必须先过对齐/兼容/fixtures 门禁，否则会把不兼容 schema
        # 直接发布到 Registry（此前 --register 完全跳过 run_gate）。
        issues = run_gate(root)
        if issues:
            print(f"Schema 门禁失败，拒绝注册 ({len(issues)}):", file=sys.stderr)
            for item in issues:
                print(f"  - {item}", file=sys.stderr)
            return 1
        from schema_registry import schema_registry
        import asyncio

        async def _reg():
            results = await schema_registry.register_all(strict=True)
            failed = [r for r in results if not r.ok]
            for r in results:
                mark = "OK" if r.ok else "FAIL"
                extra = " idempotent" if r.idempotent else ""
                print(f"[{mark}] {r.subject} HTTP {r.status_code}{extra} {r.reason}")
            return 1 if failed else 0

        return asyncio.run(_reg())

    issues = run_gate(root)
    if issues:
        print(f"Schema 门禁失败 ({len(issues)}):", file=sys.stderr)
        for item in issues:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("Schema 门禁通过: 对齐、兼容性、fixtures 均 OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
