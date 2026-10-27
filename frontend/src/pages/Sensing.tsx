import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { LiveBadge } from '../components/ui/LiveBadge'
import RateHistogram from '../components/monitor/RateHistogram'
import { api } from '../lib/api'
import Traffic from './Traffic'
import Encrypted from './Encrypted'
import Intel from './Intel'
import Sandbox from './Sandbox'
import EDR from './EDR'
import CapabilitiesDashboard from './CapabilitiesDashboard'
import { useEventStreamStore, useEventStreamLifecycle } from '../lib/eventStream'

/**
 * 感知中心(阶段 5) — 六个原本独立的"表格+表单"平页合并为单页标签,
 * 顶部实时感知带接入共享 SSE 通道(edr_correlation / tool_anomaly 等事件计数),
 * 各标签共享同一条通道(引用计数),隐藏标签零渲染开销。
 */

const TABS = [
  { key: 'traffic', label: '流量采集', el: <Traffic /> },
  { key: 'encrypted', label: '加密流量', el: <Encrypted /> },
  { key: 'intel', label: '威胁情报', el: <Intel /> },
  { key: 'sandbox', label: '沙箱检测', el: <Sandbox /> },
  { key: 'edr', label: '终端检测', el: <EDR /> },
  { key: 'capabilities', label: '能力总览', el: <CapabilitiesDashboard /> },
] as const

const SENSE_COUNTERS = [
  { type: 'edr_correlation', label: 'EDR 关联' },
  { type: 'tool_anomaly', label: '工具偏离' },
  { type: 'phishing_llm_verdict', label: '钓鱼裁定' },
  { type: 'data_security_llm_verdict', label: '数据安全裁定' },
] as const

/** 演示补给快捷按钮:一键灌入感知类种子数据(demo-seed 标注,可清空) */
function SeedQuick() {
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const seed = async () => {
    setBusy(true)
    setMsg('')
    try {
      const r = await api.demoSeed('sensing')
      const n = Object.values(r.seeded).reduce((a, b) => a + (Number(b) || 0), 0)
      setMsg(n > 0 ? `已灌入 ${n} 条演示数据` : '演示数据已存在')
    } catch (e: any) {
      setMsg(e?.message || '灌入失败')
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="flex items-center gap-2">
      <button
        onClick={() => void seed()}
        disabled={busy}
        title="灌入 demo-seed 标注的感知演示数据(可在 /demo 开场页清空)"
        className="border border-line px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-ink-faint hover:border-accent hover:text-accent transition-colors disabled:opacity-40"
      >
        {busy ? '灌入中 …' : '演示补给'}
      </button>
      {msg && <span className="text-[11px] text-ink-faint">{msg}</span>}
    </div>
  )
}

export default function Sensing() {
  const [params, setParams] = useSearchParams()
  const tab = params.get('t') ?? 'traffic'
  const activeTab = TABS.find((t) => t.key === tab) ?? TABS[0]

  // 共享 SSE 通道:感知类事件计数
  useEventStreamLifecycle()
  const typeCounts = useEventStreamStore((s) => s.typeCounts)
  const status = useEventStreamStore((s) => s.status)

  return (
    <PageTransition>
      {/* 实时感知带 */}
      <div className="page-shell pt-4">
        <div className="flex flex-wrap items-center gap-5 border border-line bg-paper px-5 py-3.5">
          <LiveBadge live={status === 'online'} label={status === 'online' ? '感知 LIVE' : '离线'} />
          <div className="flex flex-wrap items-center gap-5">
            {SENSE_COUNTERS.map(({ type, label }) => (
              <div key={type} className="flex items-baseline gap-2">
                <span className="font-mono text-[10px] tracking-[0.18em] uppercase text-ink-faint">{label}</span>
                <span className="font-serif text-[20px] font-black tabular-nums text-ink">
                  {typeCounts[type] ?? 0}
                </span>
              </div>
            ))}
          </div>
          <SeedQuick />
          <div className="ml-auto hidden h-[54px] w-[220px] lg:block">
            <RateHistogram />
          </div>
        </div>

        {/* 标签条(卷宗耳页式) */}
        <nav className="mt-4 flex items-stretch gap-1 border-b border-line" aria-label="感知能力标签">
          {TABS.map((t) => {
            const active = t.key === activeTab.key
            return (
              <button
                key={t.key}
                onClick={() => setParams(active ? params : { t: t.key })}
                className={`relative -mb-px border border-b-0 px-4 py-2 text-[13px] transition-colors ${
                  active
                    ? 'border-line bg-paper font-medium text-ink'
                    : 'border-transparent text-ink-soft hover:text-ink'
                }`}
              >
                {t.label}
              </button>
            )
          })}
        </nav>
      </div>

      {/* 当前标签内容(各能力页自带 PageFrame 头) */}
      <motion.div
        key={activeTab.key}
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
      >
        {activeTab.el}
      </motion.div>
    </PageTransition>
  )
}
