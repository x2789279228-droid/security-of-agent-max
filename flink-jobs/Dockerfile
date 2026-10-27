# ── 阶段 1: Maven 构建 ──
FROM maven:3.9-eclipse-temurin-11 AS builder

WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -B

# 拉取 Flink 运行时扩展 jar (RocksDB 状态后端 + Prometheus Reporter)
# 放入 /opt/flink/lib 由集群类加载器统一加载 (生产级: 大状态 + 指标可观测)
RUN mvn dependency:copy \
        -Dartifact=org.apache.flink:flink-statebackend-rocksdb:1.20.5 \
        -DoutputDirectory=/build/extra-lib \
        -Dtransitive=false -B
RUN mvn dependency:copy \
        -Dartifact=org.apache.flink:flink-metrics-prometheus:1.20.5 \
        -DoutputDirectory=/build/extra-lib \
        -Dtransitive=false -B

COPY src ./src
RUN mvn package -DskipTests -B

# ── 阶段 2: Flink 运行时 ──
FROM flink:1.20.5-scala_2.12-java11

# 安装守护脚本依赖: curl(JM REST 探测) + jq(JSON 解析)。
# flink 基础镜像为精简 debian, 默认用户 flink 无 sudo; 需切 root 用 apt-get 安装后切回。
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl jq \
    && rm -rf /var/lib/apt/lists/*
USER flink

# 复制构建好的 JAR 到 Flink lib 目录
COPY --from=builder /build/target/flink-jobs-1.0.0.jar /opt/flink/lib/

# 复制 Kafka 连接器及客户端依赖到 Flink lib 目录
# (不打入 fat jar, 由集群统一加载, 避免双类加载器导致的反序列化 ClassCastException)
COPY --from=builder /build/target/kafka-deps/ /opt/flink/lib/

# 复制 RocksDB 状态后端 + Prometheus 指标扩展
COPY --from=builder /build/extra-lib/ /opt/flink/lib/

# 复制作业提交脚本与守护提交脚本
COPY submit-jobs.sh /opt/flink/submit-jobs.sh
COPY auto-submit.sh /opt/flink/auto-submit.sh
# 脚本需可执行(README/守护使用)
USER root
# 2026-10-26: Windows 检出(.sh 被 git 转成 CRLF)会让 shebang 变成 "/bin/bash^M",
# 容器里直接 "bad interpreter: No such file or directory" → exit 126 →
# job-submitter 崩溃循环 → Flink 作业**一个都没提交**, 而容器状态看着是
# "Restarting"。归一为 LF, 不依赖检出端行尾。
RUN sed -i 's/\r$//' /opt/flink/submit-jobs.sh /opt/flink/auto-submit.sh \
    && chmod +x /opt/flink/submit-jobs.sh /opt/flink/auto-submit.sh

# ── checkpointing 配置必须进**镜像的** config.yaml ──
# 作业的 checkpoint 配置来自**客户端**(flink run 构建 StreamGraph 时读 config.yaml),
# 不是 JobManager 的集群配置。官方 entrypoint 会把 FLINK_PROPERTIES 合并进
# config.yaml, 但那只对走官方 entrypoint 的容器(JM/TaskManager)生效 ——
# flink-job-submitter 在 compose 里被覆盖了 entrypoint(直接跑 auto-submit.sh),
# 于是客户端的 config.yaml 里没有 execution.checkpointing.* :
#   → 作业 checkpoint 被禁用(REST 可见 interval=Long.MAX_VALUE、mode=at_least_once)
#   → EXACTLY_ONCE 的 KafkaSink 事务永不提交
#   → 数据对 read_committed 消费者永久不可见(下游 offset 永不推进)
#   → 整条 Flink→Kafka→Python 链路看起来"在跑"却一条都过不去。
# 因此把 checkpointing/state 后端写进镜像, 客户端与集群共用同一份。
# JM 侧 FLINK_PROPERTIES 会用 config-parser-utils 再合并一次(同值, 幂等)。
RUN cat >> /opt/flink/conf/config.yaml <<'YAML'
execution:
  checkpointing:
    interval: 60s
    mode: EXACTLY_ONCE
    min-pause: 30s
    timeout: 10min
    max-concurrent-checkpoints: 1
    externalized-checkpoint-retention: RETAIN_ON_CANCELLATION
    num-retained: 3
    incremental: true
    storage: filesystem
    dir: file:///var/flink-state/checkpoints
    savepoint-dir: file:///var/flink-state/savepoints
state:
  backend:
    type: rocksdb
YAML

# ── checkpoint 存储目录的属主 ──
# 容器以 flink(uid 9999) 运行, 而命名卷 flink_state 首次创建时是 root:root
# → CheckpointCoordinator 建 /var/flink-state/checkpoints/<jobId>/shared 失败
# → "Failed to create checkpoint storage" → 作业直接 FAILED。
# 在镜像里先建好目录并 chown: 新建的命名卷会继承镜像里该目录的属主/内容。
RUN mkdir -p /var/flink-state/checkpoints /var/flink-state/savepoints \
    && chown -R flink:flink /var/flink-state
USER flink
