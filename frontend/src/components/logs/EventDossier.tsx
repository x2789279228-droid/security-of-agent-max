import { useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { api } from '../../lib/api'
import { eventHref } from '../../lib/entityNav'

/**
 * 事件案卷抽屉(P2 案卷链) — Logs 行点击展开,同一事件的全部痕迹一屏归档。
 * 数据源 /api/security/events/{id} 的 raw_data(_sigma/_anomaly/_chain/_audit_llm/_cad_audit),
 * 零后端新增;交互范式复用 CaseDrawer(右侧滑入 + 毛玻璃遮罩)。
 */

interface EventDetail {
  id: number
  event_type: string
  severity: string
  src_ip: string
  dst_ip: string
  message: string
  raw_data: any
  anomaly_score: number | null
  correlation_id: string
  created_at: string
}

const fmtTime = (iso: string) => {
  try {
    return new Date(iso).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return iso
  }
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-b border-line px-6 py-4 last:border-b-0">
      <p className="meta-caps mb-2.5">{title}</p>
      {children}
    </section>
  )
}

export function EventDossier({ eventId, onClose }: { eventId: number | null; onClose: () => void }) {
  const navigate = useNavigate()
  const [detail, setDetail] = useState<EventDetail | null>(null)
  const [status, setStatus] = useState<'loading' | 'ok' | 'missing' | 'error'>('loading')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!eventId) return
    let alive = true
    setStatus('loading')
    setDetail(null)
    setError('')
    api
      .get<EventDetail>(`/security/events/${eventId}`)
      .then((d) => {
        if (!alive) return
        setDetail(d)
        setStatus('ok')
      })
      .catch((e: any) => {
        if (!alive) return
        if (/404|not found/i.test(String(e?.message || ''))) setStatus('missing')
        else {
          setStatus('error')
          setError(e?.message || '加载失败')
        }
      })
    return () => {
      alive = false
    }
  }, [eventId])

  // Esc 合卷
  useEffect(() => {
    if (!eventId) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [eventId, onClose])

  const raw = detail?.raw_data ?? {}
  const sigma = raw._sigma ?? {}
  const anomaly = raw._anomaly ?? {}
  const chain = raw._chain
  const audit = raw._audit_llm ?? {}
  const merged = audit.merged ?? {}
  const cad = raw._cad_audit ?? null
  const thoughtChain: any[] = Array.isArray(audit.thought_chain) ? audit.thought_chain : []
  const grounding = audit.grounding?.score ?? merged.grounding_score ?? null
  const pv = cad?.penetrating_verification ?? null

  return (
    <AnimatePresence>
      {eventId !== null && (
        <motion.div
          key="event-dossier"
          className="fixed inset-0 z-[60]"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
        >
          {/* 毛玻璃遮罩 */}
          <div className="absolute inset-0 bg-ink/30 backdrop-blur-[2px]" onClick={onClose} aria-hidden />

          <motion.aside
            className="absolute right-0 top-0 bottom-0 flex w-full max-w-[560px] flex-col border-l border-line bg-paper shadow-[var(--shadow-3)]"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 320, damping: 34 }}
            role="dialog"
            aria-label="事件案卷"
          >
            {/* 卷头 */}
            <div className="flex items-start justify-between gap-4 border-b border-line px-6 py-4">
              <div>
                <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint">
                  案卷 · EVENT {eventId}
                </p>
                <p className="mt-1 font-serif text-[19px] font-black text-ink">
                  {detail?.event_type || (status === 'loading' ? '调卷中 …' : '—')}
                </p>
              </div>
              <button
                onClick={onClose}
                className="shrink-0 border border-line px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-ink-soft hover:bg-mist transition-colors"
              >
                合卷 Esc
              </button>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto">
              {status === 'loading' && (
                <div className="px-6 py-10">
                  <div className="skeleton mb-3 h-16" />
                  <div className="skeleton h-32" />
                </div>
              )}

              {status === 'missing' && (
                <div className="px-6 py-14 text-center">
                  <p className="font-serif text-[16px] font-bold text-ink">该事件不存在或尚未入库</p>
                  <p className="mt-2 text-[13px] text-ink-faint">事件可能仍在流水线中,稍后重试。</p>
                </div>
              )}

              {status === 'error' && (
                <div className="px-6 py-14 text-center">
                  <p className="text-[13px] text-alert">{error}</p>
                </div>
              )}

              {status === 'ok' && detail && (
                <>
                  <Section title="基本信息">
                    <p className="text-[13px] leading-relaxed text-ink">{detail.message || '—'}</p>
                    <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 text-[12px]">
                      {[
                        ['源', detail.src_ip || '—'],
                        ['目的', detail.dst_ip || '—'],
                        ['严重度', detail.severity || '—'],
                        ['异常分', detail.anomaly_score != null ? detail.anomaly_score.toFixed(2) : '—'],
                        ['关联', detail.correlation_id || '—'],
                        ['时间', fmtTime(detail.created_at)],
                      ].map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-2 border-b border-line/60 py-1">
                          <dt className="font-mono text-[10px] tracking-[0.16em] uppercase text-ink-faint">{k}</dt>
                          <dd className="font-mono tabular-nums text-ink-soft">{v}</dd>
                        </div>
                      ))}
                    </dl>
                  </Section>

                  <Section title="检测信号">
                    {(sigma.detected || (sigma.hits?.length ?? 0) > 0) ? (
                      <ul className="space-y-1">
                        {(sigma.hits || []).slice(0, 4).map((h: any, i: number) => (
                          <li key={i} className="text-[12px] text-ink-soft">
                            <span className="mr-1.5 text-alert">◆</span>
                            {typeof h === 'string' ? h : String(h?.name || h?.rule || JSON.stringify(h))}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-[12px] text-ink-faint">Sigma 无命中</p>
                    )}
                    {anomaly?.score != null && Number(anomaly.score) > 0 && (
                      <p className="mt-2 text-[12px] text-ink-soft">
                        <span className="mr-1.5 text-warn">◆</span>
                        异常检测 <b className="tabular-nums">{Number(anomaly.score).toFixed(2)}</b>
                        {Array.isArray(anomaly.reasons) && anomaly.reasons.length > 0 && (
                          <span className="text-ink-faint"> · {anomaly.reasons.slice(0, 2).join(';')}</span>
                        )}
                      </p>
                    )}
                    {chain && (
                      <p className="mt-2 text-[12px] text-ink-soft">
                        <span className="mr-1.5 text-accent">◆</span>攻击链关联命中
                      </p>
                    )}
                  </Section>

                  <Section title="审计结论">
                    {audit && (merged.verdict || thoughtChain.length > 0 || merged.threat_detected != null) ? (
                      <>
                        <p className="text-[13px] text-ink">
                          {merged.verdict ? String(merged.verdict) : merged.threat_detected ? '威胁成立' : '已完成审计'}
                          {merged.confidence != null && (
                            <span className="ml-2 font-mono text-[11px] tabular-nums text-ink-faint">
                              置信 {Number(merged.confidence).toFixed(2)}
                            </span>
                          )}
                        </p>
                        {merged.summary && (
                          <p className="mt-1.5 line-clamp-3 text-[12px] leading-relaxed text-ink-soft">{String(merged.summary)}</p>
                        )}
                        <p className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] tabular-nums text-ink-faint">
                          <span>思维链 {thoughtChain.length} 节点</span>
                          {grounding != null && <span>grounding {Number(grounding).toFixed(2)}</span>}
                          {merged.response_blocked != null && (
                            <span className={merged.response_blocked ? 'text-alert' : 'text-ok'}>
                              {merged.response_blocked ? '响应已阻断' : '响应未阻断'}
                            </span>
                          )}
                        </p>
                      </>
                    ) : (
                      <p className="text-[12px] text-ink-faint">尚未完成审计 — 流水线处理中或规则收口通道</p>
                    )}
                  </Section>

                  {pv && (
                    <Section title="CAD 穿透验证">
                      <p className="text-[12px] text-ink-soft">
                        核验 <b className="tabular-nums text-ink">{pv.verified_claims ?? pv.verified ?? 0}</b>
                        {' / '}{pv.total_claims ?? pv.total ?? 0} 条关键断言
                        {cad?.circuit_breaker?.tripped && <span className="ml-2 text-alert">熔断已触发</span>}
                      </p>
                    </Section>
                  )}

                  {/* 案卷链跳转 */}
                  <Section title="沿链追踪">
                    <div className="flex flex-wrap gap-2.5">
                      <button
                        onClick={() => navigate(eventHref.monitor(detail.id))}
                        className="border border-ink bg-vault px-4 py-2 font-mono text-[10px] tracking-[0.18em] uppercase text-[#f1e8d6] hover:bg-vault-soft transition-colors"
                      >
                        监控 · 思维链 →
                      </button>
                      <button
                        onClick={() => navigate(eventHref.audit(detail.id))}
                        className="border border-line px-4 py-2 font-mono text-[10px] tracking-[0.18em] uppercase text-ink-soft hover:border-accent hover:text-accent transition-colors"
                      >
                        审计 · 流水线 →
                      </button>
                    </div>
                    <p className="mt-2.5 text-[11px] leading-relaxed text-ink-faint">
                      同一事件的全部入口互通:此处跳转后,目标页自动选中事件 #{detail.id}。
                    </p>
                  </Section>
                </>
              )}
            </div>
          </motion.aside>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
