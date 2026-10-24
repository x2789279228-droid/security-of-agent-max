package com.soc.job;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.flink.streaming.api.windowing.windows.TimeWindow;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * RuleTimeframeHarness — 在**进程外**驱动真实的 {@link SigmaThresholdAggregationJob.RuleTimeframeWindows}。
 *
 * <h2>为什么需要它</h2>
 * {@code SigmaWindowHarness} 只覆盖窗口**函数**(ThresholdWindowFunction.process)，
 * 窗口**分配器**(RuleTimeframeWindows.assignWindows) —— P0-1 最核心的
 * "按规则声明 timeframe 建窗"语义 —— 没有任何执行验证。分配器写错
 * (窗口宽度取错、slide 对齐错、覆盖不住事件时间戳) 的后果是聚合永远不触发
 * 或阈值虚高，且源码断言/编译都看不出来。
 *
 * <p>assignWindows(element, timestamp, ctx) 不使用 ctx(纯函数)，
 * 直接传 null；元素经真实的 {@code SigmaHit.fromString} 解析，
 * 同时验证 timeframe_ms/timeframe 字符串/缺省回退的解析契约。
 *
 * <h2>用法</h2>
 * <pre>
 *   java -cp &lt;deps&gt;:target/classes com.soc.job.RuleTimeframeHarness &lt; payloads.ndjson
 * </pre>
 * stdin 每行一个 sigma-hit 候选；stdout 每行一条分配结果 JSON：
 * {@code {declared_ms, timestamp, window_count, first_start, last_start, size, slide, covers_ts}}
 */
public final class RuleTimeframeHarness {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        SigmaThresholdAggregationJob.RuleTimeframeWindows assigner =
                new SigmaThresholdAggregationJob.RuleTimeframeWindows();
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
                if (h == null) {
                    System.out.println("{\"error\": \"parse_failed\"}");
                    continue;
                }
                Collection<TimeWindow> windows =
                        assigner.assignWindows(h, h.timestamp, null);
                List<Long> starts = new ArrayList<>();
                long minStart = Long.MAX_VALUE, maxEnd = Long.MIN_VALUE, minEnd = Long.MAX_VALUE;
                boolean covers = false;
                for (TimeWindow w : windows) {
                    starts.add(w.getStart());
                    minStart = Math.min(minStart, w.getStart());
                    maxEnd = Math.max(maxEnd, w.getEnd());
                    minEnd = Math.min(minEnd, w.getEnd());
                    if (w.getStart() <= h.timestamp && h.timestamp < w.getEnd()) {
                        covers = true;
                    }
                }
                long size = maxEnd - minStart > 0 ? minEnd - minStart : 0;
                long slide = starts.size() >= 2
                        ? (maxEnd - minStart - size) / Math.max(1, starts.size() - 1)
                        : size;
                // slide 恒等判定: 相邻 start 差值
                long slideDirect = 0;
                if (starts.size() >= 2) {
                    List<Long> sorted = new ArrayList<>(starts);
                    java.util.Collections.sort(sorted);
                    slideDirect = sorted.get(1) - sorted.get(0);
                }
                ObjectNode out = MAPPER.createObjectNode();
                out.put("declared_ms", h.timeframeMs);
                out.put("timestamp", h.timestamp);
                out.put("window_count", windows.size());
                out.put("first_start", starts.isEmpty() ? -1 : minStart);
                out.put("size", size);
                out.put("slide", slideDirect);
                out.put("covers_ts", covers);
                System.out.println(MAPPER.writeValueAsString(out));
            }
        }
    }
}
