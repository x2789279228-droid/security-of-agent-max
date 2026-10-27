import { useState, useEffect } from 'react'
import { PageFrame } from '../components/common/PageFrame'
import { api } from '../lib/api'
import { StatBand } from '../components/common/StatBand'

interface FlowRecord {
  id: number
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  app_protocol: string
  bytes_in: number
  bytes_out: number
  direction: string
  flow_start: string
}

export default function Traffic() {
  const [flows, setFlows] = useState<FlowRecord[]>([])
  const [stats, setStats] = useState<any>(null)
  const [filter, setFilter] = useState('')
  const [loadError, setLoadError] = useState('')
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    api.get('/ndr/flows?limit=100').then(setFlows).then(() => setLoadError('')).catch((e: any) => setLoadError(e?.message || '加载失败'))
    api.get('/ndr/capture/stats').then(setStats).catch(() => {})
  }, [refreshKey])

  const filtered = filter
    ? flows.filter(
        (f) =>
          f.src_ip.includes(filter) ||
          f.dst_ip.includes(filter) ||
          f.app_protocol.toLowerCase().includes(filter.toLowerCase()),
      )
    : flows

  return (
    <PageFrame
      title="流量采集"
      hint="网络流 · 协议分布 · 采集状态。横向看流量，眼睛能看出异常。"
      marginalia="——大多数攻击先在流上露出形状。"
      extra={
        stats && (
          <div className="flex gap-3 font-mono text-[10px] tracking-[0.26em] uppercase">
            <span className="border border-line px-3 py-2">
              <span className="text-ink-faint">Packets</span>{' '}
              <span className="ml-1 text-ink tabular-nums">
                {stats.packets_captured?.toLocaleString() ?? 0}
              </span>
            </span>
            <span className="border border-[#0e1a26] bg-[#0e1a26] px-3 py-2 text-[#f1e8d6]">
              <span className="opacity-60">Active</span>{' '}
              <span className="ml-1 tabular-nums">{stats.active_flows ?? 0}</span>
            </span>
          </div>
        )
      }
    >
      <StatBand
        items={[
          { label: '流记录', value: flows.length },
          { label: '出站', value: flows.filter((f) => f.direction === 'outbound').length },
          { label: '横向移动', value: flows.filter((f) => f.direction === 'lateral').length, tone: 'warn' as const },
          { label: '平均下行', value: flows.length ? Math.round(flows.reduce((a, f) => a + (f.bytes_in || 0), 0) / flows.length / 1024) : 0, hint: 'KB / 流' },
        ]}
      />
      <input
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="搜索 IP / 协议 …"
        className="mono-input mb-6 max-w-md text-sm"
      />

      <div className="overflow-x-auto border border-line bg-paper">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-line text-left">
              <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                源
              </th>
              <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                目标
              </th>
              <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                端口
              </th>
              <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                协议
              </th>
              <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                方向
              </th>
              <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal text-right">
                流出
              </th>
              <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                时间
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={f.id} className="border-b border-line last:border-b-0 row-hover">
                <td className="px-4 py-2.5 font-mono text-[13px] text-ink">{f.src_ip}</td>
                <td className="px-4 py-2.5 font-mono text-[13px] text-ink">{f.dst_ip}</td>
                <td className="px-4 py-2.5 font-mono text-[13px] text-ink-soft">{f.dst_port}</td>
                <td className="px-4 py-2.5">
                  <span className="border border-ink px-2 py-0.5 font-mono text-[11px] text-ink">
                    {f.app_protocol || f.protocol}
                  </span>
                </td>
                <td className="px-4 py-2.5 font-mono text-[11px] tracking-[0.18em] uppercase text-ink-faint">
                  {f.direction}
                </td>
                <td className="px-4 py-2.5 text-right font-mono text-[13px] tabular-nums">
                  {(f.bytes_out / 1024).toFixed(1)} KB
                </td>
                <td className="px-4 py-2.5 font-mono text-[11px] tabular-nums text-ink-faint">
                  {f.flow_start ? new Date(f.flow_start).toLocaleTimeString() : '—'}
                </td>
              </tr>
            ))}
            {loadError && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center">
                  <p className="text-[13px] text-warn">加载失败:{loadError}</p>
                  <button
                    onClick={() => setRefreshKey((k) => k + 1)}
                    className="mt-2 border border-line px-3 py-1.5 text-[11px] text-ink transition-colors hover:border-accent hover:text-accent"
                  >
                    重试
                  </button>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-ink-faint">后端不可达已与「暂无数据」区分;可点上方「演示补给」一键灌入演示数据。</p>
                </td>
              </tr>
            )}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-20 text-center text-[13px] text-ink-faint">
                  暂无流量数据
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </PageFrame>
  )
}