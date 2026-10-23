# Schema 契约

权威来源是 `backend/schemas/*.schema.json`，由 `backend/schemas/catalog.json` 索引。

Flink Avro（`flink-jobs/schemas/*.avsc`）和 Java POJO 是投影：CI 必须证明它们与 JSON Schema 字段、类型、必填项一致。Confluent Schema Registry 是发布面，注册前走兼容性门禁。

## 变更流程

1. 改 JSON Schema（可加可选字段；不要直接加必填、改类型、删旧消费者仍依赖的字段）。
2. 同步 Avro 与 Java 模型。
3. 本地执行 `python tools/check-schema-compat.py`。
4. 门禁通过后再注册 / 发布。HTTP 409 只有在 Registry 里已有**相同内容**时才算幂等成功。

## 信封

新的跨系统消息可以使用 `envelope.schema.json` 外包一层。现有扁平消息继续有效：消费端先解密，再按是否含 `payload` + `schemaVersion` 决定拆信封或按业务 Schema 直校验。
