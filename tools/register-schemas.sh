#!/bin/bash
# 将权威 JSON Schema 注册到 Confluent Schema Registry。
# 409 只有在已有记录与本次内容完全相同时才算成功。
# 用法: bash tools/register-schemas.sh [registry-url]
# 默认: http://localhost:8085

set -euo pipefail
REGISTRY="${1:-http://localhost:8085}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Schema Registry 注册 (registry=$REGISTRY) ==="

until curl -s "$REGISTRY/subjects" >/dev/null 2>&1; do
  echo "等待 Schema Registry 就绪..."
  sleep 3
done

export SHARED_MEMORY_SCHEMA_REGISTRY_URL="$REGISTRY"
cd "$ROOT"
python tools/check-schema-compat.py --register
status=$?

echo ""
echo "=== 已注册 Subjects ==="
curl -s "$REGISTRY/subjects" | python -m json.tool 2>/dev/null || curl -s "$REGISTRY/subjects"
echo ""
if [ "$status" -ne 0 ]; then
  echo "=== 注册失败：存在不兼容或内容冲突的 subject ==="
  exit "$status"
fi
echo "=== 完成 ==="
