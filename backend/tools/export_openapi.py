"""导出 OpenAPI schema → backend/openapi.json（前端 TS 类型生成的唯一事实源）。

用法（仓库根或 backend/ 均可）:
    python backend/tools/export_openapi.py

产物:
    backend/openapi.json          — 提交入库; CI 校验它与代码同步
    frontend/src/types/api-generated.ts — 由 `npm run gen:api` 从上面文件生成

注意: 导入 app 不启动 lifespan(纯 schema 内省), 全程无 DB/Redis/Kafka 依赖;
env 兜底只为通过 Settings 校验(fail-closed 密钥检查)。
"""
import json
import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent

# 必须早于 import config —— 与 tests/conftest.py 同样的隔离约定
os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "openapi-export")
os.environ.setdefault("SHARED_MEMORY_CONTROL_HMAC_KEY", "openapi-export")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "openapi-export")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "openapi-export")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "openapi-export")

sys.path.insert(0, str(BACKEND_DIR))


def main() -> int:
    from app import app  # noqa: 导入即注册全部路由(无 lifespan 副作用)

    schema = app.openapi()
    out = BACKEND_DIR / "openapi.json"
    out.write_text(
        json.dumps(schema, ensure_ascii=False, indent=1, sort_keys=True),
        encoding="utf-8",
    )
    n_paths = len(schema.get("paths", {}))
    n_schemas = len(schema.get("components", {}).get("schemas", {}))
    print(f"[export_openapi] {out.name}: openapi {schema.get('openapi')}, "
          f"{n_paths} paths, {n_schemas} schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
