import {
  AGENT_RELAY_STAGES,
  STAGE_LABELS,
  type RelayState,
} from '../../lib/agentPipeline'
import type { StatsResponse } from '../../types/stats'

/**
 * 大屏空闲态剧本卡（/screen 默认视图）。
 *
 * 背景：大屏在没有进行中审查时，思维链主舞台只剩历史 fallback 和空阶段框，
 * 评委走近时像"死屏"。这里把空闲态改成一张有信息量的剧本卡：
 *   最近一次完整处置 + 六站轨迹 + 平台价值指标 + 演示/查看思维链入口。
 *
 * 诚实边界：只展示已完成的审查记录，不注入新事件；没有记录时明确说"待命中"。
 * 响应式：1920 投影展示全量信息；1366 收起六站与说明，保证不溢出。
 */

const fmtNum = (n: number) => n.toLocaleString('zh-CN')

export default function IdleScenarioCard({
  recent,
  stats,
  idleHint,
  onDemo,
  demoBusy = false,
  onOpenChain,
}: {
  recent: RelayState[]
  stats: StatsResponse | null
  idleHint: string
  onDemo?: () => void
  demoBusy?: boolean
  onOpenChain?: (eventId: number) => void
}) {
  const latest = recent.find((r) => r.eventId > 0) ?? null
  const audited = Math.max(0, Number(stats?.audit_llm?.completed ?? 0) || 0)
  const total = Math.max(0, Number(stats?.security_events ?? 0) || 0)
  const memories = Math.max(0, Number(stats?.tree_nodes ?? 0) || 0)
  const pending = Math.max(0, Number(stats?.security_pending ?? 0) || 0)

  const metrics = [
    { k: '累计闭环', v: audited, note: '已完成审计' },
    { k: '已接管', v: total, note: '安全事件入库' },
    { k: '记忆节点', v: memories, note: '关联索引' },
    { k: '待处理', v: pending, note: pending > 0 ? '优先消化' : '队列已清空' },
  ]
  const doneStages = latest
    ? AGENT_RELAY_STAGES.filter((s) => latest.stages[s] === 'success' || latest.done).length
    : 0

  return (
    <div className="flex h-full min-h-0 flex-col px-5 py-4 2xl:px-7 2xl:py-6">
      <div className="flex shrink-0 items-center gap-3">
        <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-[#d9b36a]">值班主舞台</span>
        <span className="border border-[#5da583]/50 bg-[#5da583]/10 px-2 py-0.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#7fd4a8]">
          空闲待命
        </span>
        <span className="ml-auto hidden font-mono text-[10px] tracking-[0.14em] uppercase text-[#5c6b7a] 2xl:inline">
          不注入新事件 · 只看已完成
        </span>
      </div>

      <h2 className="mt-2 shrink-0 font-serif text-[22px] font-semibold leading-tight tracking-[-0.02em] text-[#f1e8d6] 2xl:mt-3 2xl:text-[32px]">
        {latest ? '最近一次完整处置' : '值班待命中'}
      </h2>
      <p className="mt-1.5 max-w-[52rem] shrink-0 font-serif text-[12px] leading-relaxed text-[#a7b4bd] 2xl:mt-2 2xl:text-[14px]">
        {latest
          ? `事件 #${latest.eventId} 已走完六站审查：分解 → 工具 → 执行 → 复核 → CAD → 响应。`
          : '平台在线，等待下一批事件流入；也可以先跑一条演示剧本，看完整链路。'}
      </p>

      {latest && (
        <div className="mt-4 hidden shrink-0 grid-cols-6 gap-2 2xl:grid">
          {AGENT_RELAY_STAGES.map((s, i) => {
            const ok = latest.stages[s] === 'success' || latest.done
            return (
              <div
                key={s}
                className={`border px-3 py-2.5 ${
                  ok ? 'border-[#5da583]/45 bg-[#5da583]/[0.06]' : 'border-[#2a323c] bg-[#161b21]'
                }`}
              >
                <p className="font-mono text-[10px] tracking-[0.16em] text-[#78889a]">
                  {String(i + 1).padStart(2, '0')}
                </p>
                <p className="mt-1 font-serif text-[15px] font-semibold text-[#e9edf2]">
                  {STAGE_LABELS[s] ?? s}
                </p>
                <p className={`mt-1 font-mono text-[10px] ${ok ? 'text-[#7fd4a8]' : 'text-[#6e7a88]'}`}>
                  {ok ? '完成' : '待命'}
                </p>
              </div>
            )
          })}
        </div>
      )}

      {latest && (
        <div className="mt-2 flex shrink-0 flex-wrap items-center gap-2 2xl:mt-3">
          <span className="border border-[#c9a574]/35 px-2 py-0.5 font-mono text-[11px] text-[#d9bc8b]">
            #{latest.eventId}
          </span>
          <span className="border border-[#24384a] px-2 py-0.5 font-mono text-[11px] text-[#a7b4bd]">
            六站 {doneStages}/6 完成
          </span>
          <span className="hidden border border-[#24384a] px-2 py-0.5 font-mono text-[11px] text-[#a7b4bd] 2xl:inline">
            历史记录 · 可回看思维链
          </span>
        </div>
      )}

      <div className="mt-5 hidden shrink-0 grid-cols-2 gap-3 2xl:grid 2xl:grid-cols-4">
        {metrics.map((m) => (
          <div key={m.k} className="border border-[#2a323c] bg-[#161b21] px-4 py-3">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#78889a]">{m.k}</p>
            <p className="mt-1 font-serif text-[24px] font-semibold tabular-nums leading-none text-[#e9edf2] 2xl:text-[30px]">
              {fmtNum(m.v)}
            </p>
            <p className="mt-1 text-[10px] text-[#5c6b7a]">{m.note}</p>
          </div>
        ))}
      </div>

      <div className="mt-auto flex shrink-0 flex-wrap items-center gap-2.5 pt-2 2xl:gap-3 2xl:pt-4">
        {onDemo && (
          <button
            type="button"
            onClick={onDemo}
            disabled={demoBusy}
            className="border border-[#d9b36a]/60 bg-[#d9b36a]/10 px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#d9b36a] transition-colors hover:bg-[#d9b36a]/20 disabled:opacity-40 2xl:px-4 2xl:py-2 2xl:text-[11px] 2xl:tracking-[0.2em]"
          >
            {demoBusy ? '演示启动中…' : '▶ 演示剧本'}
          </button>
        )}
        {latest && onOpenChain && (
          <button
            type="button"
            onClick={() => onOpenChain(latest.eventId)}
            className="border border-[#33475a] px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#a7b4bd] transition-colors hover:border-[#d9b36a]/50 hover:text-[#d9b36a] 2xl:px-4 2xl:py-2 2xl:text-[11px] 2xl:tracking-[0.2em]"
          >
            查看完整思维链 →
          </button>
        )}
        <p className="ml-auto hidden max-w-[34rem] text-right text-[10px] leading-relaxed text-[#5c6b7a] 2xl:block">
          {idleHint}
        </p>
      </div>
    </div>
  )
}

