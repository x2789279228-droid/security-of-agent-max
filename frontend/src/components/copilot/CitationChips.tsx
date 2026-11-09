/**
 * CitationChips · 知识库引用条（2026-11 AI Web 改造）
 *
 * 回答下方的 [1][2] 引用块：点击跳知识库页（/rag）。编号与回答正文中的
 * [n] 标注一一对应（copilot_service 产出的 citations 顺序即编号）。
 * hover 显示摘要 tooltip —— 引用可溯源，不装作模型自己知道。
 */
import { useNavigate } from 'react-router-dom'
import type { CopilotCitation } from '../../hooks/useCopilotStream'
import { ROUTES } from '../../lib/constants'

export function CitationChips({ citations }: { citations: CopilotCitation[] }) {
  const navigate = useNavigate()
  if (!citations.length) return null
  return (
    <div className="mt-2.5 flex flex-wrap items-center gap-1.5 border-t border-line-soft pt-2.5">
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-faint">引用</span>
      {citations.map((c) => (
        <button
          key={`${c.index}-${c.doc_id ?? c.title}`}
          type="button"
          title={c.snippet}
          onClick={() => navigate(ROUTES.RAG)}
          className="group inline-flex max-w-[240px] items-center gap-1.5 rounded-[3px] border border-line bg-paper px-2 py-1 text-[11px] text-ink-soft transition-colors hover:border-accent/50 hover:text-ink"
        >
          <span className="font-mono text-[10px] text-accent">[{c.index}]</span>
          <span className="truncate">{c.title}</span>
          {c.source && <span className="hidden truncate font-mono text-[10px] text-ink-faint md:inline">{c.source}</span>}
        </button>
      ))}
    </div>
  )
}
