#!/usr/bin/env bash
# A3 根因插桩: 逐分区 offset 推进速率采样 (5s 间隔, TSV)
# 列: GROUP(1) TOPIC(2) PARTITION(3) CURRENT-OFFSET(4) LOG-END(5) LAG(6) CONSUMER-ID(7) HOST(8) CLIENT-ID(9)
DUR=${1:-300}; OUT=${2:-partition-samples.tsv}
echo -e "ts\tpartition\tcurrent_offset\thost" > "$OUT"
END=$((SECONDS+DUR))
while [ $SECONDS -lt $END ]; do
  TS=$(date +%s)
  docker exec soc-kafka kafka-consumer-groups --bootstrap-server localhost:9092 \
    --describe --group soc-backend-ingestpy 2>/dev/null | awk -v ts="$TS" '
    NR>1 && $3 ~ /^[0-9]+$/ {print ts"\t"$3"\t"$4"\t"$8}' >> "$OUT"
  sleep 5
done
echo "samples -> $OUT"
