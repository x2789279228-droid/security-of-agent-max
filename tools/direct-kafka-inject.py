"""A3 实验 C: 绕过 HTTP 网关直灌 security-events-ingest(剥离 leader 网关职责)。"""
import asyncio, json, os, sys, time

BOOTSTRAP = os.environ.get("KAFKA", "kafka:9092")
TOPIC = "security-events-ingest"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
PREFIX = sys.argv[2] if len(sys.argv) > 2 else "a3rc"
SEV = os.environ.get("SEV", "medium")

EVENTS = []
from datetime import datetime, timezone
for i in range(N):
    EVENTS.append({
        "event_id": f"{PREFIX}-{i:05d}",
        "event": "PORT_SCAN", "type": "PORT_SCAN", "threat_type": "PORT_SCAN",
        "severity": SEV, "protocol": "tcp",
        "message": f"端口扫描 src=203.0.113.{100+i%150} 探测 dst=10.30.0.10 (ports=22,80,443)",
        "src_ip": f"203.0.113.{100+i%150}", "dst_ip": "10.30.0.10",
        "_sim": True, "ts": datetime.now(timezone.utc).isoformat(),
    })

async def main():
    from aiokafka import AIOKafkaProducer
    p = AIOKafkaProducer(bootstrap_servers=BOOTSTRAP, acks="all",
                         enable_idempotence=True, linger_ms=50)
    await p.start()
    t0 = time.time()
    for ev in EVENTS:
        await p.send_and_wait(TOPIC, json.dumps(ev, ensure_ascii=False).encode())
    await p.stop()
    print(f"produced {N} in {time.time()-t0:.1f}s -> {TOPIC}")

asyncio.run(main())
