/**
 * otel.ts — 浏览器侧 OpenTelemetry 初始化 (前端 → collector → Jaeger/Tempo)
 *
 * 职责:
 *   - 初始化浏览器 TracerProvider, 导出到同源 /otlp/v1/traces
 *     (由 nginx /otlp/ 反代到 otel-collector:4318, 避免 CORS)。
 *   - 注册 FetchInstrumentation: 自动为每个 fetch 创建 span,
 *     并向请求头注入 W3C traceparent → 后端 HttpTraceMiddleware 提取续接,
 *     从而把「浏览器发起 → 后端 HTTP → 审计流水线」串成同一条 trace 树。
 *
 * OTel JS 3.x 迁移 (2.10 → 3.0):
 *   - sdk-trace-web 包已删除, WebTracerProvider/register() 一并移除;
 *     改用合并后的 sdk-trace 包, 手工完成「全局 provider + context manager」注册
 *     (等价于旧 .register() 做的事)。
 *   - 传播器用 api 包默认的 W3C TraceContext + Baggage 组合, 无需显式设置。
 *
 * 说明: 生产环境默认开启; 若想关闭可在构建时注入 VITE_OTEL_DISABLED=1。
 */
import { BatchSpanProcessor, StackContextManager, TracerProvider } from '@opentelemetry/sdk-trace'
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http'
import { FetchInstrumentation } from '@opentelemetry/instrumentation-fetch'
import { registerInstrumentations } from '@opentelemetry/instrumentation'
import { resourceFromAttributes } from '@opentelemetry/resources'
import { ATTR_SERVICE_NAME } from '@opentelemetry/semantic-conventions'
import { context, trace } from '@opentelemetry/api'

let initialized = false

/**
 * 初始化浏览器 trace；重复调用为幂等。
 * 关闭开关(VITE_OTEL_DISABLED)或浏览器不支持时静默跳过。
 */
export function initBrowserTelemetry(): void {
  if (initialized) return
  initialized = true

  if (import.meta.env.VITE_OTEL_DISABLED === '1') return
  if (typeof window === 'undefined') return

  const provider = new TracerProvider({
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: 'soc-frontend',
      'soc.node.role': 'browser',
    }),
    spanProcessors: [
      // 3.x: 构造参数从 (exporter, config) 改为 { exporter, ...config }
      new BatchSpanProcessor({
        exporter: new OTLPTraceExporter({
          url: '/otlp/v1/traces',
        }),
      }),
    ],
  })
  // 3.x: register() 移除 — 手工注册全局 provider 与 context manager
  trace.setGlobalTracerProvider(provider)
  context.setGlobalContextManager(new StackContextManager().enable())

  registerInstrumentations({
    instrumentations: [
      new FetchInstrumentation({
        // 打点 fetch; 自动注入 W3C traceparent 到请求头
        propagateTraceHeaderCorsUrls: /.*/,
        clearTimingResources: true,
      }),
    ],
  })

  // 便于控制台调试 (window.__OTEL_TRACER__)
  ;(window as any).__OTEL_TRACER__ = trace.getTracer('soc-frontend', '1.0.0')
}
