package org.apache.flink.streaming.runtime.operators.windowing.functions;

import org.apache.flink.api.common.state.KeyedStateStore;
import org.apache.flink.streaming.api.functions.windowing.ProcessWindowFunction;
import org.apache.flink.streaming.api.windowing.windows.Window;
import org.apache.flink.util.OutputTag;

/**
 * SigmaWindowTestContexts — 在进程外构造一个可用的 {@code ProcessWindowFunction.Context}。
 *
 * <h2>为什么这个类必须放在 Flink 的包里</h2>
 * {@code ProcessWindowFunction.Context} 是 Flink 的**内部类**：字节码里有
 * {@code this$0} 和一个 {@code Context(ProcessWindowFunction)} 外部实例构造器。
 * 但这个构造器对 javac <b>不可见</b> —— {@code javap -p} 能看到它，
 * {@code javac} 解析 ClassSymbol 时只留下隐式无参构造器，于是：
 *
 * <ul>
 *   <li>写 {@code super(host)} → 「需要: 没有参数」</li>
 *   <li>不写 {@code super} → 「需要包含 ProcessWindowFunction.Context 的封闭实例」</li>
 * </ul>
 *
 * 已用最小复现逐一验证过（见整改报告 §四），两种写法都编译不过，
 * 与宿主是否泛型、是否同包、内层/静态嵌套都无关。
 *
 * <p>所以本类放进 {@code org.apache.flink.streaming.runtime.operators.windowing.functions}
 * —— Flink 自己运行时用的具体实现 {@link InternalProcessWindowContext} 就在这个包里，
 * 它的构造器是包私有的。同包即可访问。
 *
 * <h2>为什么用它而不是自己伪造一个 Context</h2>
 * {@code InternalProcessWindowContext} 正是 {@code WindowOperator} 在集群上为每次
 * process 调用创建的那个类。用它意味着 harness 跑的是<b>生产同款</b> Context，
 * 而不是一份仿制品 —— 伪造版一旦漏实现某个方法，反而会把「harness 能跑」
 * 伪装成「窗口在集群上能跑」。
 *
 * <p>它只依赖一个 {@link InternalWindowFunction.InternalWindowContext} 来回答
 * 时钟/状态/旁路输出问题，这里用固定时钟的桩实现。
 */
public final class SigmaWindowTestContexts {

    private SigmaWindowTestContexts() {
    }

    /**
     * 固定时钟的内部上下文。
     *
     * <p>状态访问与旁路输出一律抛异常而不是返回 null：窗口函数哪天真的开始调
     * {@code windowState()} 时，harness 会带着栈炸掉，而不是悄悄拿到 null
     * 继续跑出一份「看起来正常」的输出。
     */
    public static final class FixedClockContext
            implements InternalWindowFunction.InternalWindowContext {

        private static final long serialVersionUID = 1L;

        private final long processingTime;
        private final long watermark;

        public FixedClockContext(long processingTime, long watermark) {
            this.processingTime = processingTime;
            this.watermark = watermark;
        }

        @Override
        public long currentProcessingTime() {
            return processingTime;
        }

        @Override
        public long currentWatermark() {
            return watermark;
        }

        @Override
        public KeyedStateStore windowState() {
            throw new UnsupportedOperationException(
                    "window state is not available outside a real Flink runtime");
        }

        @Override
        public KeyedStateStore globalState() {
            throw new UnsupportedOperationException(
                    "global state is not available outside a real Flink runtime");
        }

        @Override
        public <X> void output(OutputTag<X> outputTag, X record) {
            throw new UnsupportedOperationException(
                    "side output is not available outside a real Flink runtime");
        }
    }

    /**
     * 构造一个 {@link InternalProcessWindowContext}，其窗口与时钟固定为给定值。
     *
     * @param function       被调用的窗口函数实例，即 Context 的封闭实例
     * @param window         当前窗口；生产上由窗口分配器决定
     * @param processingTime 固定的 processing time（毫秒）
     * @param watermark      固定的水位线（毫秒）
     */
    public static <IN, OUT, KEY, W extends Window>
    ProcessWindowFunction<IN, OUT, KEY, W>.Context create(
            ProcessWindowFunction<IN, OUT, KEY, W> function,
            W window,
            long processingTime,
            long watermark) {
        InternalProcessWindowContext<IN, OUT, KEY, W> ctx =
                new InternalProcessWindowContext<>(function);
        ctx.window = window;
        ctx.internalContext = new FixedClockContext(processingTime, watermark);
        return ctx;
    }
}
