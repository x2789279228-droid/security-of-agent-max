import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { PageFrame } from '../components/common/PageFrame'
import { EventDossier } from '../components/logs/EventDossier'
import { CountUp } from '../motion/primitives'
import { api } from '../lib/api'
import { useEventParam, eventHref } from '../lib/entityNav'
import {
  useEventStreamLifecycle,
  useEventStreamStore,
  type StreamEvent,
} from '../lib/eventStream'
import type { SecurityLog, Severity } from '../types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const severityMeta: Record<Severity, { label: string; badge: string; dot: string; card: string; num: string }> = {
  critical: { label: '严重', badge: 'border border-alert/40 bg-alert/15 text-alert', dot: 'bg-alert', card: 'border-alert/60 bg-alert/5', num: 'text-alert' },
  high: { label: '高危', badge: 'border border-warn/40 bg-warn/15 text-warn', dot: 'bg-warn', card: 'border-warn/60 bg-warn/5', num: 'text-warn' },
  medium: { label: '中危', badge: 'border border-hui/40 bg-hui/10 text-hui', dot: 'bg-hui', card: 'border-hui/60 bg-hui/5', num: 'text-hui' },
  low: { label: '低危', badge: 'border border-line bg-mist text-ink-faint', dot: 'bg-dan', card: 'border-dan/70 bg-mist/40', num: 'text-ink-soft' },
  info: { label: '提示', badge: 'text-ink-faint', dot: 'bg-line', card: 'border-line bg-mist/20', num: 'text-ink-faint' },
}

/* 新到行动效:入场背景色晕(衰减到透明)+ 左缘severity色条 */
const SEV_TINT: Record<Severity, string> = {
  critical: 'rgba(176, 58, 48, 0.13)',
  high: 'rgba(184, 137, 64, 0.13)',
  medium: 'rgba(74, 122, 136, 0.11)',
  low: 'rgba(28, 40, 56, 0.05)',
  info: 'rgba(28, 40, 56, 0.04)',
}
const SEV_BORDER: Record<Severity, string> = {
  critical: '#b03a30',
  high: '#b88940',
  medium: '#4a7a88',
  low: '#bcc6c0',
  info: '#cfd6d2',
}

const PAGE_SIZE = 100

function formatTime(iso: string) {
  try {
    const d = new Date(iso)
    return `${d.toLocaleDateString('zh-CN')} ${d.toLocaleTimeString('zh-CN', { hour12: false })}`
  } catch {
    return iso
  }
}

function eventIdOf(data: any): number {
  const n = Number(data?.event_id ?? data?.id ?? 0)
  return Number.isFinite(n) && n > 0 ? n : 0
}

function liveLogFromEvent(data: any): SecurityLog | null {
  const id = eventIdOf(data)
  if (!id) return null
  const ts = Number(data._ts)
  return {
    id,
    session_id: String(data.session_id || ''),
    event_type: String(data.event_type || data.event || 'UNKNOWN'),
    severity: (data.severity || 'info') as Severity,
    src_ip: String(data.src_ip || ''),
    dst_ip: String(data.dst_ip || ''),
    message: String(data.message || ''),
    analyzed: false,
    is_anomaly: Boolean(data.is_anomaly),
    anomaly_score: Number(data.anomaly_score) || undefined,
    created_at: Number.isFinite(ts) && ts > 0
      ? new Date(ts * 1000).toISOString()
      : new Date().toISOString(),
  }
}

function applyStreamEvents(prev: SecurityLog[], events: StreamEvent[]): SecurityLog[] {
  if (!events.length) return prev
  let next = prev
  // 缓冲是新→旧；倒序让 security_event 先于同事件的 audit_complete 落地
  for (let i = events.length - 1; i >= 0; i--) {
    const evt = events[i]
    const data = evt.data || {}
    if (evt.type === 'security_event') {
      const live = liveLogFromEvent(data)
      if (!live) continue
      if (next.some((l) => l.id === live.id)) continue
      next = [live, ...next].slice(0, 500)
      continue
    }
    if (evt.type !== 'audit_complete' && evt.type !== 'audit_degraded') continue
    const eid = eventIdOf(data)
    if (!eid) continue
    const quality = String(data.quality || (evt.type === 'audit_degraded' ? 'budget' : 'llm'))
    let hit = false
    const mapped = next.map((l) => {
      if (l.id !== eid) return l
      hit = true
      if (l.analyzed && l.audit_quality === quality) return l
      return { ...l, analyzed: true, audit_quality: quality }
    })
    if (hit) next = mapped
  }
  return next.length > 500 ? next.slice(0, 500) : next
}

export default function Logs() {
  const [logs, setLogs] = useState<SecurityLog[]>([])
  const [loading, setLoading] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [search, setSearch] = useState('')
  const offsetRef = useRef(0)
  const syncingRef = useRef(false)
  // 新到行:SSE 插入的事件 id → 到达时刻(6s 内保持"新到"标记)
  const [recentIds, setRecentIds] = useState<Record<number, number>>({})

  // 案卷链:行点击开事件案卷抽屉;?event= 深链自动开卷并高亮
  const navigate = useNavigate()
  const deepEventId = useEventParam()
  const [dossierId, setDossierId] = useState<number | null>(null)
  useEffect(() => {
    if (deepEventId) setDossierId(deepEventId)
  }, [deepEventId])

  useEventStreamLifecycle()
  const streamStatus = useEventStreamStore((s) => s.status)
  const arrivalTick = useEventStreamStore((s) => s.arrivalTick)
  const connected = streamStatus === 'online' || streamStatus === 'reconnecting'

  const load = useCallback(async (reset = true, offset = 0) => {
    if (reset) setLoading(true); else setLoadingMore(true)
    setError(null)
    try {
      const params: Record<string, string> = {
        limit: String(PAGE_SIZE),
        offset: String(offset),
      }
      if (severity) params.severity = severity
      const data = await api.logsEvents(params)
      setLogs((prev) => {
        const byId = new Map<number, SecurityLog>()
        for (const l of prev) byId.set(l.id, l)
        const incoming = reset ? data : [...prev, ...data]
        const seen = new Set<number>()
        return incoming.filter((l) => {
          if (seen.has(l.id)) return false
          seen.add(l.id)
          return true
        }).map((l) => {
          const local = byId.get(l.id)
          // REST 尚未写完审计时，保留 SSE 已经打上的 analyzed
          if (local?.analyzed && !l.analyzed) {
            return { ...l, analyzed: true, audit_quality: local.audit_quality }
          }
          return l
        })
      })
      offsetRef.current = offset + data.length
    } catch (e: any) {
      setError(e.message || '加载失败')
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [severity])

  useEffect(() => {
    load(true, 0)
  }, [load])

  useEffect(() => {
    const buffer = useEventStreamStore.getState().buffer
    const relevant = buffer.filter((e) => (
      e.kind === 'event'
      && (e.type === 'security_event' || e.type === 'audit_complete' || e.type === 'audit_degraded')
    ))
    if (!relevant.length) return
    // 新到行标记(5s 内视为"刚到",行播放色晕衰减)
    const nowTs = Date.now()
    setRecentIds((prev) => {
      const next = { ...prev }
      for (const evt of relevant) {
        if (evt.type !== 'security_event') continue
        const id = eventIdOf(evt.data)
        if (id && next[id] === undefined) next[id] = nowTs
      }
      for (const k of Object.keys(next)) {
        if (nowTs - next[Number(k)] > 6000) delete next[Number(k)]
      }
      return next
    })
    setLogs((prev) => applyStreamEvents(prev, relevant))
  }, [arrivalTick, loading])

  // 审计完成盖章:捕获 analyzed false→true 翻转(SSE 与 2s 轮询两个来源统一在此)
  const prevAnalyzedRef = useRef<Map<number, boolean>>(new Map())
  const [stampedIds, setStampedIds] = useState<Record<number, number>>({})
  useEffect(() => {
    const now = Date.now()
    const additions: Record<number, number> = {}
    for (const l of logs) {
      if (prevAnalyzedRef.current.get(l.id) === false && l.analyzed) additions[l.id] = now
    }
    prevAnalyzedRef.current = new Map(logs.map((l) => [l.id, l.analyzed]))
    if (Object.keys(additions).length) setStampedIds((s) => ({ ...s, ...additions }))
  }, [logs])

  const filtered = useMemo(() => {
    if (!search.trim()) return logs
    const q = search.trim().toLowerCase()
    return logs.filter(
      (l) =>
        l.event_type.toLowerCase().includes(q) ||
        l.message.toLowerCase().includes(q) ||
        l.src_ip.includes(q) ||
        l.dst_ip.includes(q),
    )
  }, [logs, search])

  const stats = useMemo(() => {
    const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    let reviewed = 0
    let degraded = 0
    for (const l of logs) {
      if (l.severity in bySeverity) bySeverity[l.severity]++
      if (l.analyzed && (l.audit_quality === 'llm' || !l.audit_quality)) reviewed++
      else if (l.analyzed) degraded++
    }
    return { bySeverity, reviewed, degraded, pending: logs.length - reviewed - degraded }
  }, [logs])

  // 近 24 小时接入分布(本地聚合,最右=当前小时)
  const hourly = useMemo(() => {
    const buckets = new Array(24).fill(0)
    const now = Date.now()
    for (const l of logs) {
      const t = Date.parse(l.created_at)
      if (!Number.isFinite(t)) continue
      const ageH = (now - t) / 3_600_000
      if (ageH < 0 || ageH >= 24) continue
      buckets[23 - Math.floor(ageH)]++
    }
    return buckets
  }, [logs])
  const hourlyMax = Math.max(1, ...hourly)

  const syncLiveAudits = useCallback(async () => {
    if (syncingRef.current) return
    syncingRef.current = true
    try {
      const params: Record<string, string> = { limit: String(PAGE_SIZE), offset: '0' }
      if (severity) params.severity = severity
      const data = await api.logsEvents(params)
      if (!Array.isArray(data) || !data.length) return
      setLogs((prev) => {
        const byId = new Map<number, SecurityLog>()
        for (const row of data) {
          if (row?.id) byId.set(Number(row.id), row)
        }
        let changed = false
        let next = prev.map((l) => {
          const row = byId.get(l.id)
          if (!row) return l
          if (row.analyzed && !l.analyzed) {
            changed = true
            return { ...l, analyzed: true, audit_quality: row.audit_quality }
          }
          if (row.analyzed && row.audit_quality && row.audit_quality !== l.audit_quality) {
            changed = true
            return { ...l, analyzed: true, audit_quality: row.audit_quality }
          }
          return l
        })
        const maxId = next.reduce((m, l) => (l.id > m ? l.id : m), 0)
        const newcomers = data.filter((row) => Number(row.id) > maxId)
        if (newcomers.length) {
          changed = true
          next = [...newcomers, ...next]
        }
        if (next.length > 500) {
          changed = true
          next = next.slice(0, 500)
        }
        return changed ? next : prev
      })
    } catch {
      /* 轮询失败时仍靠 SSE */
    } finally {
      syncingRef.current = false
    }
  }, [severity])

  useEffect(() => {
    void syncLiveAudits()
    const timer = window.setInterval(() => { void syncLiveAudits() }, 2000)
    return () => window.clearInterval(timer)
  }, [syncLiveAudits])

  return (
    <PageFrame
      title="日志中心"
      hint="已接入安全事件 · 按时间倒序 · 实时推送。"
      marginalia="——每一条日志都是守望者的一句话。"
      extra={
        <span className="inline-flex items-center gap-2 text-[13px] font-medium tracking-wide">
          <span className="relative flex h-2 w-2">
            {connected && (
              <span className="absolute inset-0 animate-ping rounded-full bg-accent opacity-70" />
            )}
            <span
              className={`relative h-2 w-2 rounded-full ${
                connected
                  ? 'bg-accent shadow-[0_0_8px_rgba(58,101,112,0.35)]'
                  : 'bg-warn'
              }`}
            />
          </span>
          <span className={connected ? 'text-accent' : 'text-warn'}>
            {connected ? '实时连接' : '已断开'}
          </span>
        </span>
      }
    >

        <div className="mb-10 grid grid-cols-2 gap-8 border-b border-line pb-8 md:grid-cols-5">
          {SEVERITIES.map((s) => {
            const active = severity === s
            const meta = severityMeta[s]
            return (
              <button
                key={s}
                onClick={() => setSeverity(active ? '' : s)}
                aria-pressed={active}
                className={`group relative text-left pl-3 pr-2 py-2 transition-colors ${active ? 'bg-vault' : 'opacity-55 hover:opacity-100'}`}
              >
                <span
                  aria-hidden
                  className={`absolute left-0 top-0 bottom-0 w-[2px] transition-colors ${
                    active ? 'bg-dusk-soft' : 'bg-transparent'
                  }`}
                />
                <p className={`font-mono text-[10px] tracking-[0.22em] uppercase transition-colors ${active ? 'text-dusk-soft' : 'text-ink-faint'}`}>
                  {meta.label}
                </p>
                <p className={`mt-2 font-serif text-[32px] font-black tabular-nums leading-none transition-colors ${active ? 'text-[#f1e8d6]' : meta.num}`}>
                  <CountUp value={stats.bySeverity[s]} from="previous" duration={500} />
                </p>
              </button>
            )
          })}
        </div>

        {/* 筛选栏 */}
        <div className="mb-6 flex items-center gap-3 border-y border-line py-3">
          <div className="relative flex-1">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="搜索事件类型 / 消息 / IP"
              className="glass-input w-full py-2 text-[13px] text-ink placeholder:text-ink-faint"
            />
          </div>
          <button
            onClick={() => load(true, 0)}
            className="border border-[#0e1a26] bg-[#0e1a26] px-4 py-2 font-mono text-[11px] tracking-[0.18em] uppercase text-[#f1e8d6] hover:bg-[#182838] transition-colors"
          >
            刷新
          </button>
          <span className="hidden shrink-0 font-mono text-[11px] tracking-[0.16em] uppercase text-ink-faint md:block">
            审计 <span className="tabular-nums text-ok">{stats.reviewed}</span>
            {' · '}降级 <span className="tabular-nums text-warn">{stats.degraded}</span>
            {' · '}待审{' '}
            <span className={`tabular-nums ${stats.pending > 0 ? 'text-alert' : 'text-ink-faint'}`}>
              {stats.pending}
            </span>
          </span>
        </div>

        {/* 近 24 小时接入分布(本地聚合) */}
        <div className="mb-5 border border-line bg-paper px-4 pb-2 pt-3">
          <div className="flex items-center justify-between">
            <p className="meta-caps">近 24 小时接入分布</p>
            <span className="font-mono text-[10px] tabular-nums text-ink-faint">-24h → 现在 · 每柱 1 小时</span>
          </div>
          <div className="mt-2 flex h-10 items-end gap-1">
            {hourly.map((n, i) => (
              <div key={i} className="relative h-full flex-1 bg-mist/50" title={`${n} 条`}>
                <motion.div
                  className="absolute inset-x-0 bottom-0 bg-accent/70"
                  initial={{ height: 0 }}
                  animate={{ height: `${(n / hourlyMax) * 100}%` }}
                  transition={{ duration: 0.45, delay: i * 0.015, ease: [0.22, 1, 0.36, 1] }}
                />
              </div>
            ))}
          </div>
        </div>

        {/* 日志表格 */}
        {loading ? (
          <div className="text-center text-sm text-ink-faint py-20">加载中 …</div>
        ) : error ? (
          <div className="text-center text-sm text-alert py-20">{error}</div>
        ) : filtered.length === 0 ? (
          <div className="border border-line py-20 text-center text-sm text-ink-faint">
            {search || severity ? '没有符合筛选条件的日志' : '暂无日志，等待事件接入 …'}
          </div>
        ) : (
          <div className="overflow-hidden border border-line bg-paper">
            <div className="overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="text-left border-b border-line bg-mist">
                    <th className="px-5 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">级别</th>
                    <th className="px-5 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">事件类型</th>
                    <th className="px-5 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">来源 → 目标</th>
                    <th className="px-5 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal w-2/5">消息</th>
                    <th className="px-5 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">审计</th>
                    <th className="px-5 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">时间</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  <AnimatePresence initial={false}>
                    {filtered.map((log) => {
                      const meta = severityMeta[log.severity] || severityMeta.info
                      const isNew = recentIds[log.id] !== undefined
                      const deepLinked = deepEventId !== null && log.id === deepEventId
                      const justStamped = stampedIds[log.id] !== undefined && Date.now() - stampedIds[log.id] < 1600
                      const auditCls = `text-[11px] font-semibold ${
                        log.audit_quality === 'llm' || !log.audit_quality
                          ? 'text-accent'
                          : log.audit_quality === 'tools' || log.audit_quality === 'rule'
                            ? 'text-hui'
                            : 'text-alert'
                      }`
                      const auditLabel = log.audit_quality === 'llm' || !log.audit_quality
                        ? 'LLM'
                        : log.audit_quality === 'tools' || log.audit_quality === 'rule'
                          ? '规则'
                          : '降级'
                      return (
                        <motion.tr
                          key={log.id}
                          data-event-id={log.id}
                          data-analyzed={log.analyzed ? '1' : '0'}
                          layout
                          onClick={() => setDossierId(log.id)}
                          initial={isNew
                            ? { opacity: 0, y: -10, backgroundColor: SEV_TINT[log.severity] ?? SEV_TINT.info }
                            : { opacity: 0, y: -6 }}
                          animate={isNew
                            ? { opacity: 1, y: 0, backgroundColor: 'rgba(0,0,0,0)' }
                            : { opacity: 1, y: 0 }}
                          exit={{ opacity: 0 }}
                          transition={isNew ? { duration: 1.5 } : { duration: 0.2 }}
                          style={{
                            ...(isNew ? { boxShadow: `inset 3px 0 0 ${SEV_BORDER[log.severity] ?? SEV_BORDER.info}` } : {}),
                            ...(deepLinked ? { backgroundColor: 'rgba(58, 101, 112, 0.07)', boxShadow: 'inset 3px 0 0 #3a6570' } : {}),
                          }}
                          className="group cursor-pointer hover:bg-mist/25 transition-colors align-top"
                        >
                          <td className="px-5 py-3">
                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ${meta.badge}`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
                              {meta.label}
                              {isNew && <span className="ml-0.5 animate-pulse text-[9px] tracking-[0.14em]">NEW</span>}
                            </span>
                          </td>
                          <td className="px-5 py-3 font-medium text-ink whitespace-nowrap">{log.event_type}</td>
                          <td className="px-5 py-3 text-ink-soft whitespace-nowrap font-mono text-xs">
                            {log.src_ip || '—'} <span className="text-ink-faint">→</span> {log.dst_ip || '—'}
                          </td>
                          <td className="px-5 py-3 text-ink-soft leading-relaxed">
                            <span className="line-clamp-2">{log.message}</span>
                            {log.is_anomaly && (
                              <span className="text-alert text-[11px] font-semibold ml-1.5">
                                ⚠ 异常 {log.anomaly_score?.toFixed(2)}
                              </span>
                            )}
                            <button
                              onClick={(e) => {
                                e.stopPropagation()
                                navigate(eventHref.monitor(log.id))
                              }}
                              className="mt-1 block text-[11px] font-medium text-accent opacity-0 transition-opacity group-hover:opacity-100"
                            >
                              思维链 →
                            </button>
                          </td>
                          <td className="px-5 py-3 whitespace-nowrap">
                            {log.analyzed ? (
                              justStamped ? (
                                <motion.span
                                  initial={{ scale: 1.4, opacity: 0.4 }}
                                  animate={{ scale: 1, opacity: 1 }}
                                  transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
                                  className={`inline-block ${auditCls}`}
                                >
                                  {auditLabel}
                                </motion.span>
                              ) : (
                                <span className={auditCls}>{auditLabel}</span>
                              )
                            ) : (
                              <span className="text-ink-faint text-[11px] font-semibold">审核中</span>
                            )}
                          </td>
                          <td className="px-5 py-3 text-ink-faint whitespace-nowrap tabular-nums text-xs">
                            {formatTime(log.created_at)}
                          </td>
                        </motion.tr>
                      )
                    })}
                  </AnimatePresence>
                </tbody>
              </table>
            </div>
            {filtered.length >= PAGE_SIZE && (
              <button
                onClick={() => load(false, offsetRef.current)}
                disabled={loadingMore}
                className="w-full border-t border-line py-3.5 text-sm text-link transition-colors hover:bg-mist/25"
              >
                {loadingMore ? '加载中…' : '加载更多'}
              </button>
            )}
          </div>
        )}

        {/* 事件案卷抽屉(案卷链) */}
        <EventDossier eventId={dossierId} onClose={() => setDossierId(null)} />
    </PageFrame>
  )
}
