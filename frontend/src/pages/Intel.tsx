import { useState, useEffect } from 'react'
import { PageFrame, tabOn, tabOff } from '../components/common/PageFrame'
import { api } from '../lib/api'
import { StatBand } from '../components/common/StatBand'

interface Ioc {
  id: number
  ioc_type: string
  ioc_value: string
  threat_type: string
  severity: string
  confidence: number
  source: string
  is_active: boolean
  created_at: string
}

const typeBadge: Record<string, string> = {
  ip: 'bg-[#0e1a26] text-[#f1e8d6]',
  domain: 'bg-warn text-[#0e1a26]',
  file_hash: 'bg-[#7ba9b5] text-[#0e1a26]',
  url: 'border border-ink text-ink',
}

export default function Intel() {
  const [iocs, setIocs] = useState<Ioc[]>([])
  const [feeds, setFeeds] = useState<any[]>([])
  const [tab, setTab] = useState<'iocs' | 'feeds'>('iocs')
  const [loadError, setLoadError] = useState('')
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    api.get('/intel/iocs?limit=100').then(setIocs).then(() => setLoadError('')).catch((e: any) => setLoadError(e?.message || '加载失败'))
    api.get('/intel/feeds').then(setFeeds).catch(() => {})
  }, [refreshKey])

  return (
    <PageFrame
      title="威胁情报"
      hint="IOC 管理 · 情报源 · 信誉查询。把外部情报变成系统已知。"
    >
      <StatBand
        items={[
          { label: 'IOC 总数', value: iocs.length, hint: `情报源 ${feeds.length} 个` },
          { label: 'IP 指标', value: iocs.filter((x) => x.ioc_type === 'ip').length },
          { label: '域名指标', value: iocs.filter((x) => x.ioc_type === 'domain').length },
          { label: 'critical', value: iocs.filter((x) => x.severity === 'critical').length, tone: 'alert' as const },
        ]}
      />
      <nav className="mb-8 flex gap-6 border-b border-line">
        {(['iocs', 'feeds'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={tab === t ? tabOn : tabOff}
          >
            {t === 'iocs' ? `IOC 指标 · ${iocs.length}` : `情报源 · ${feeds.length}`}
          </button>
        ))}
      </nav>

      {tab === 'iocs' ? (
        <div className="overflow-x-auto border border-line bg-paper">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left">
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.06em] text-ink-faint font-normal">
                  类型
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.06em] text-ink-faint font-normal">
                  指标
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.06em] text-ink-faint font-normal">
                  威胁
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.06em] text-ink-faint font-normal">
                  严重度
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.06em] text-ink-faint font-normal">
                  来源
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.06em] text-ink-faint font-normal">
                  状态
                </th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc) => (
                <tr key={ioc.id} className="border-b border-line last:border-b-0 row-hover">
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 font-mono text-[11px] uppercase tracking-[0.16em] ${typeBadge[ioc.ioc_type] || 'border border-line text-ink-soft'}`}>
                      {ioc.ioc_type}
                    </span>
                  </td>
                  <td className="max-w-[300px] truncate px-4 py-2.5 font-mono text-[13px] text-ink">
                    {ioc.ioc_value}
                  </td>
                  <td className="px-4 py-2.5 text-[13px] text-ink-soft">{ioc.threat_type || '—'}</td>
                  <td className="px-4 py-2.5 font-mono text-[11px] uppercase tracking-[0.06em] text-ink">
                    {ioc.severity}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[11px] text-ink-faint">
                    {ioc.source}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`inline-block h-1.5 w-1.5 ${ioc.is_active ? 'bg-warn' : 'bg-ink-faint/40'}`}
                      aria-hidden
                    />
                  </td>
                </tr>
              ))}
              {loadError && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center">
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
              {iocs.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-20 text-center text-[13px] text-ink-faint">
                    暂无 IOC 数据
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="border border-line bg-paper">
          {feeds.map((f, i) => (
            <div
              key={f.id}
              className={`flex items-center justify-between px-6 py-5 ${i < feeds.length - 1 ? 'border-b border-line' : ''}`}
            >
              <div>
                <p className="text-[18px] font-bold tracking-tight text-ink">
                  {f.name}
                </p>
                <p className="mt-1 font-mono text-[11px] text-ink-faint">
                  {f.feed_type} · {f.url}
                </p>
              </div>
              <div className="text-right">
                <span
                  className={`inline-flex items-center gap-2 border px-2.5 py-1 font-mono text-[10px] tracking-[0.06em] ${
                    f.enabled
                      ? 'border-ok text-ok'
                      : 'border-line text-ink-faint'
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 ${f.enabled ? 'bg-ok' : 'bg-ink-faint/40'}`}
                    aria-hidden
                  />
                  {f.enabled ? 'ENABLED' : 'DISABLED'}
                </span>
                <p className="mt-1.5 font-mono text-[10px] tracking-[0.06em] text-ink-faint">
                  {f.last_poll_status === 'success'
                    ? `上次 · ${f.last_poll_count} 条`
                    : f.last_poll_status}
                </p>
              </div>
            </div>
          ))}
          {feeds.length === 0 && (
            <div className="px-6 py-20 text-center text-[13px] text-ink-faint">
              暂未配置情报源
            </div>
          )}
        </div>
      )}
    </PageFrame>
  )
}