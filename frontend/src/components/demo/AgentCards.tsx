import {
  AGENT_RELAY_STAGES,
  STAGE_COLORS,
  STAGE_DUTIES,
  STAGE_LABELS,
} from '../../lib/agentPipeline'

/**
 * 舞台页「六个岗位接力」卡片。
 *
 * 之前的 RelayStage 只有六个圆点 + 标签，投屏看不出"谁在干什么"；
 * 这里把每个岗位做成一张卡：编号 / 名称 / 一句话职责 / 当前状态。
 * 数据完全来自导演状态机，不新增假数据；演练信号会明确标注。
 */

type CellStatus = 'idle' | 'running' | 'success' | 'error' | 'timeout'

interface Cell {
  status: CellStatus
  simulated: boolean
}

/** 导演层 StageCell 与本组件所需形状一致，避免跨层依赖 hook 类型 */
export type AgentStageCells = Record<string, Cell>

const STATUS_TEXT: Record<string, string> = {
  idle: '待命',
  running: '进行中',
  success: '完成',
  error: '异常',
  timeout: '超时',
}

const STATUS_CHIP: Record<string, string> = {
  idle: 'border-[#33475a] text-[#6e7a88]',
  running: 'border-[#d9b36a]/60 bg-[#d9b36a]/10 text-[#e5c48d]',
  success: 'border-[#5da583]/50 bg-[#5da583]/10 text-[#7fd4a8]',
  error: 'border-[#e05a4e]/50 bg-[#e05a4e]/10 text-[#e8887c]',
  timeout: 'border-[#d4a054]/50 bg-[#d4a054]/10 text-[#e5b96b]',
}

export function AgentCards({ stages }: { stages: AgentStageCells }) {
  const doneCount = AGENT_RELAY_STAGES.filter((s) => stages[s]?.status === 'success').length
  const running = AGENT_RELAY_STAGES.find((s) => stages[s]?.status === 'running')

  return (
    <div className="mx-auto w-full max-w-[62rem]">
      <div className="mb-4 flex items-center justify-between border-b border-[#2a323c] pb-3">
        <p className="font-mono text-[10px] tracking-[0.24em] uppercase text-[#d9b36a]">
          岗位接力 · {doneCount}/6 完成
        </p>
        <p className="font-mono text-[10px] tabular-nums text-[#6e7a88]">
          {running ? `当前：${STAGE_LABELS[running] ?? running}` : '等待信号'}
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {AGENT_RELAY_STAGES.map((stage, i) => {
          const cell = stages[stage] ?? { status: 'idle' as CellStatus, simulated: false }
          const color = STAGE_COLORS[stage] ?? '#33475a'
          const active = cell.status === 'running'
          return (
            <div
              key={stage}
              className={`relative border bg-[#14222f] px-4 py-4 transition-colors ${
                active ? 'border-[#d9b36a]/60' : 'border-[#2a323c]'
              }`}
            >
              <span
                aria-hidden
                className="absolute left-0 top-0 h-full w-[2px]"
                style={{ background: color, opacity: cell.status === 'idle' ? 0.25 : 0.9 }}
              />
              <div className="flex items-center justify-between gap-3">
                <span className="font-mono text-[10px] tracking-[0.22em] text-[#6e7a88]">
                  {String(i + 1).padStart(2, '0')}
                </span>
                <span
                  className={`border px-1.5 py-px font-mono text-[10px] tracking-[0.14em] uppercase ${
                    STATUS_CHIP[cell.status] ?? STATUS_CHIP.idle
                  }`}
                >
                  {STATUS_TEXT[cell.status] ?? cell.status}
                </span>
              </div>
              <p className="mt-2 font-serif text-[19px] font-semibold text-[#e9edf2]">
                {STAGE_LABELS[stage] ?? stage}
              </p>
              <p className="mt-1 text-[12.5px] leading-snug text-[#8fa0ad]">{STAGE_DUTIES[stage] ?? ''}</p>
              {cell.simulated && (
                <p className="mt-2 font-mono text-[10px] tracking-[0.12em] text-[#c9a574]">演练信号</p>
              )}
            </div>
          )
        })}
      </div>
      <p className="mt-4 text-center font-mono text-[11px] tracking-[0.16em] text-[#6e7a88]">
        分解者 → 工具构建 → 执行者 → 复核者 → CAD 监督 → 响应引擎
      </p>
    </div>
  )
}
