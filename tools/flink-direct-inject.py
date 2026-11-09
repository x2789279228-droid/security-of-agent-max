"""Wave 3-1: Flink 直灌剖面 —— 直接向 security-logs-raw 注入已知规模合法事件。

事件按 LogValidationJob.validateSchemaEnhanced 的契约构造:
  必填 eventType/severity/message + apiKey 白名单内 + IPv4 + 毫秒时间戳。
产出可对账: eventId 前缀唯一, 落库可按 event_id 前缀精确计数。
"""
import asyncio, json, os, sys, time
from datetime import datetime, timezone

BOOTSTRAP = os.environ.get("KAFKA", "kafka:9092")
TOPIC = "security-logs-raw"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
PREFIX = sys.argv[2] if len(sys.argv) > 2 else "w31"
API_KEY = os.environ.get("INJECT_KEY", "soc-simulator-2024")

SEVS = ["low", "medium", "high"]
TYPES = ["PORT_SCAN", "BRUTE_FORCE", "WEB_ATTACK", "NORMAL_TRAFFIC"]

async def main():
    from aiokafka import AIOKafkaProducer
    p = AIOKafkaProducer(bootstrap_servers=BOOTSTRAP, acks="all",
                         enable_idempotence=True, linger_ms=20)
    await p.start()
    t0 = time.time()
    now_ms = int(time.time() * 1000)
    batch = []
    for i in range(N):
        batch.append({
            "eventId": f"{PREFIX}-{i:06d}",
            "sourceId": "flink-direct-inject",
            "apiKey": API_KEY,
            "eventType": TYPES[i % 4],
            "severity": SEVS[i % 3],
            "confidence": 50 + (i % 40),
            "timestamp": now_ms + i,          # 毫秒(合法范围)
            "srcIp": f"198.51.100.{(i % 250) + 1}",
            "dstIp": "10.30.0.10",
            "dstPort": [22, 80, 443, 3389][i % 4],
            "protocol": "tcp",
            "message": f"W31 direct-inject {TYPES[i%4]} event {i} from 198.51.100.{(i%250)+1}",
        })
    # 分区轮转(3 分区均匀)
    for i, ev in enumerate(batch):
        await p.send_and_wait(TOPIC, json.dumps(ev, ensure_ascii=False).encode(),
                              key=str(i % 3).encode())
    await p.stop()
    dt = time.time() - t0
    print(f"produced {N} -> {TOPIC} in {dt:.1f}s ({N/dt:.0f}/s) prefix={PREFIX}")

asyncio.run(main())
