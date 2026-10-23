package com.soc.job;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.JsonNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.streaming.api.windowing.windows.TimeWindow;
import org.apache.flink.util.Collector;
import org.apache.flink.streaming.runtime.operators.windowing.functions.SigmaWindowTestContexts;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * SigmaWindowHarness — 在**进程外**驱动真实的 {@link SigmaThresholdAggregationJob.ThresholdWindowFunction}。
 *
 * <h2>为什么需要它</h2>
 * 整改方案 §十一 要求监控因果/检测的统计口径，而 §4.3.1 的封禁链路上，
 * 聚合窗口（Flink）是唯一没有被真正执行过的一层。此前只有源码字符串断言，
 * 那是**下限**不是验证 —— 它挡得住「字段被删」，挡不住
 * 「threshold 比较写反」「confidence 没被 put 出去」这类逻辑错误。
 *
 * <p>但这里要跑的**不是整条 Flink 作业**：作业需要 Kafka + 集群 + 窗口分配器。
 * 本 harness 只把三样可独立调用的东西拉出来：
 *
 * <ol>
 *   <li>{@code SigmaHit.fromString} —— 真实的 JSON 解析（验证字段名对不对）</li>
 *   <li>{@code ThresholdWindowFunction.process} —— 真实的窗口聚合逻辑</li>
 *   <li>真实的 {@code ObjectMapper} —— 真实的输出序列化</li>
 * </ol>
 *
 * <p>Context 用的是 Flink 运行时自己的 {@code InternalProcessWindowContext}
 * （见 {@link SigmaWindowTestContexts}），不是仿制品。
 *
 * <h2>它能证明什么，不能证明什么</h2>
 * <p><b>能</b>：载荷字段名与 Java 解析器对得上；阈值比较方向正确；
 * {@code threshold<=0} 不会退化；窗口内取最严动作；输出字段齐全；
 * 从 Python 生产者到 Java 消费者的**跨语言契约**没有漂移。
 *
 * <p><b>不能</b>：5m/1m 滑动窗口的边界分配、同 key 并发、水位线推进、
 * 处理时间 vs 事件时间 —— 那些需要真实 Flink 运行时，已登记在验收报告的
 * 待验证清单里，**不要**因为这个 harness 绿了就认为窗口在集群上是对的。
 *
 * <h2>用法</h2>
 * <pre>
 *   java -cp &lt;deps&gt;:target/classes com.soc.job.SigmaWindowHarness &lt; payloads.ndjson
 * </pre>
 * stdin 每行一个 sigma-hit 候选（与 backend 发布的载荷同构），全部归入同一个窗口。
 * stdout 每行一条窗口输出告警的 JSON；没有告警则 stdout 为空，stderr 打印
 * {@code HARNESS_NO_OUTPUT hits=<n>} —— 这个哨兵用来区分「阈值没到」与
 * 「序列化失败被 process() 内部的 catch 吞掉」，两者 stdout 都是空的。
 */
public final class SigmaWindowHarness {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 收集窗口输出。 */
    private static final class ListCollector implements Collector<String> {
        final List<String> out = new ArrayList<>();

        @Override
        public void collect(String value) {
            out.add(value);
        }

        @Override
        public void close() {
            // nothing to release
        }
    }

    public static void main(String[] args) throws Exception {
        List<SigmaThresholdAggregationJob.SigmaHit> hits = new ArrayList<>();
        try (BufferedReader in = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                SigmaThresholdAggregationJob.SigmaHit h =
                        SigmaThresholdAggregationJob.SigmaHit.fromString(line);
                if (h != null) {
                    hits.add(h);
                }
            }
        }

        // 窗口取 [0, 300_000)，与作业的 5m 处理时间窗口同宽；
        // processing time / watermark 给成窗口中点，真实运行时由 Flink 注入。
        TimeWindow window = new TimeWindow(0L, 300_000L);
        ListCollector collector = new ListCollector();
        SigmaThresholdAggregationJob.ThresholdWindowFunction fn =
                new SigmaThresholdAggregationJob.ThresholdWindowFunction();

        org.apache.flink.streaming.api.functions.windowing.ProcessWindowFunction<
                SigmaThresholdAggregationJob.SigmaHit, String, String, TimeWindow>.Context ctx =
                SigmaWindowTestContexts.create(fn, window, 150_000L, 150_000L);

        // key 口径必须与作业的 keyBy(h -> h.srcIp + "#" + h.ruleId) 一致，
        // 否则日志里的 key 与生产对不上，排障时会先怀疑 harness。
        String key = hits.isEmpty()
                ? "harness#EMPTY"
                : hits.get(0).srcIp + "#" + hits.get(0).ruleId;

        fn.process(key, ctx, hits, collector);

        if (collector.out.isEmpty()) {
            // 区分「阈值没到」与「序列化失败被 process() 内部的 catch 吞掉」。
            // 后者只在 stderr 留一行 WARN、退出码仍是 0 —— 不显式说明的话，
            // pytest 会把「输出序列化了但没成功」当成「阈值没到」而误判为通过。
            System.err.println("HARNESS_NO_OUTPUT hits=" + hits.size());
            return;
        }
        for (String json : collector.out) {
            // 重新解析一遍：确保输出真的是合法 JSON（而不是碰巧看起来像）
            JsonNode parsed = MAPPER.readTree(json);
            System.out.println(parsed.toString());
        }
    }
}
