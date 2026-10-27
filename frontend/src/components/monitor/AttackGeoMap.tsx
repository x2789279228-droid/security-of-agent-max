import { useMemo } from 'react'
import { CHINA_PROVINCES } from '../../assets/chinaMap'
import { useEventStreamStore } from '../../lib/eventStream'

/**
 * 攻击态势地图 — 离线 IP 地理 (ip2region) + SSE attack_geo 频道。
 *
 * 数据源: backend/attack_geo_broadcast.py 每 5s 一帧 (bulk 车道合并只留最新):
 *   home    受击方 (默认湖南科技大学, env 可覆盖)
 *   points  [{ip,label,lat,lon,count,max_severity,last_type,country,province}]
 *
 * 投影: cos(35°) 校正等距圆柱 — 中国纬度带内形变最小, 无依赖。
 * 弧线: 受击点→攻击源的二次贝塞尔, SVG animateMotion 质点流动;
 * prefers-reduced-motion 时退化为静态弧线 (演出学: 尊重眩晕设置)。
 */

const COS_MID = Math.cos((35 * Math.PI) / 180)

function project(lon: number, lat: number): [number, number] {
  return [lon * COS_MID, -lat]
}

interface GeoPoint {
  ip: string
  label: string
  lat: number
  lon: number
  count: number
  max_severity: string
  last_type: string
}

interface GeoFrame {
  home: { lat: number; lon: number; label: string }
  points: GeoPoint[]
  window?: number
  distinct_ips?: number
  sampled_events?: number
}

const SEV_COLOR: Record<string, string> = {
  critical: '#e05a4e',
  high: '#d4a054',
  medium: '#5b8db8',
  low: '#3d5a70',
  info: '#3d5a70',
}

export default function AttackGeoMap() {
  const buffer = useEventStreamStore((s) => s.buffer)

  const frame = useMemo<GeoFrame | null>(() => {
    for (let i = buffer.length - 1; i >= 0; i--) {
      const e = buffer[i]
      if (e.kind === 'event' && e.type === 'attack_geo') return e.data as GeoFrame
    }
    return null
  }, [buffer])

  const { paths, viewBox } = useMemo(() => {
    let minX = Infinity; let maxX = -Infinity; let minY = Infinity; let maxY = -Infinity
    const paths: { name: string; d: string }[] = []
    for (const prov of CHINA_PROVINCES) {
      let d = ''
      for (const ring of prov.rings) {
        ring.forEach((p, i) => {
          const [x, y] = project(p[0], p[1])
          if (x < minX) minX = x
          if (x > maxX) maxX = x
          if (y < minY) minY = y
          if (y > maxY) maxY = y
          d += (i === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1)
        })
        d += 'Z'
      }
      if (d) paths.push({ name: prov.name, d })
    }
    const pad = 6
    return {
      paths,
      viewBox: `${(minX - pad).toFixed(1)} ${(minY - pad).toFixed(1)} ${(maxX - minX + pad * 2).toFixed(1)} ${(maxY - minY + pad * 2).toFixed(1)}`,
    }
  }, [])

  const home = frame?.home
  const homeXY = home ? project(home.lon, home.lat) : null
  const points = (frame?.points ?? []).slice(0, 24)

  return (
    <div className="relative flex h-full flex-col">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[10px] tracking-[0.22em] uppercase text-ink-faint">攻击态势 · 来源地理</span>
        {frame && (
          <span className="font-mono text-[10px] text-ink-faint tabular-nums">
            {points.length} 源 / 近 {frame.sampled_events ?? '—'} 事件
          </span>
        )}
      </div>

      <svg
        viewBox={viewBox}
        className="mt-1 min-h-0 w-full flex-1"
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="攻击来源地理分布"
      >
        {paths.map((p) => (
          <path key={p.name} d={p.d} fill="#132433" fillOpacity={0.85} stroke="#2c4356" strokeWidth={0.12} />
        ))}

        {/* 受击方: 同心呼吸环 (等一下: reduced-motion 由 CSS 层处理, SVG 环静态常显) */}
        {homeXY && (
          <g>
            <circle cx={homeXY[0]} cy={homeXY[1]} r={1.6} fill="none" stroke="#5da583" strokeWidth={0.35} className="attack-map-home-ring" />
            <circle cx={homeXY[0]} cy={homeXY[1]} r={0.7} fill="#5da583" />
          </g>
        )}

        {/* 攻击源 → 受击方 弧线 + 流动质点 */}
        {homeXY && points.map((pt, i) => {
          const xy = project(pt.lon, pt.lat)
          const color = SEV_COLOR[pt.max_severity] ?? SEV_COLOR.info
          // 控制点: 中点向上抬弧 (抬幅 = 距离的 0.22, 上限 9°)
          const mx = (homeXY[0] + xy[0]) / 2
          const my = (homeXY[1] + xy[1]) / 2
          const dist = Math.hypot(xy[0] - homeXY[0], xy[1] - homeXY[1])
          const lift = Math.min(9, dist * 0.22)
          const cx = mx
          const cy = my - lift
          const d = `M${homeXY[0].toFixed(1)} ${homeXY[1].toFixed(1)} Q${cx.toFixed(1)} ${cy.toFixed(1)} ${xy[0].toFixed(1)} ${xy[1].toFixed(1)}`
          const r = 0.28 + Math.min(0.6, Math.log2(1 + pt.count) * 0.14)
          return (
            <g key={pt.ip}>
              <path d={d} fill="none" stroke={color} strokeOpacity={0.28} strokeWidth={0.14} fillOpacity={1} />
              <circle cx={xy[0]} cy={xy[1]} r={r} fill={color}>
                <title>{`${pt.label} · ${pt.ip} · ${pt.count} 条 (${pt.max_severity})`}</title>
              </circle>
              <circle r={0.34} fill={color} opacity={0.95}>
                <animateMotion dur={`${(1.4 + (i % 5) * 0.35).toFixed(2)}s`} begin={`${(-(i * 0.42) % 3).toFixed(2)}s`} repeatCount="indefinite" path={d} />
              </circle>
            </g>
          )
        })}
      </svg>

      {!frame && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <span className="font-mono text-[11px] text-ink-faint">等待态势帧…</span>
        </div>
      )}

      {/* 图例: 严重度四色 */}
      <div className="mt-0.5 flex gap-3 text-[9px] text-ink-faint">
        <LegendDot color={SEV_COLOR.critical} label="严重" />
        <LegendDot color={SEV_COLOR.high} label="高" />
        <LegendDot color={SEV_COLOR.medium} label="中" />
        <LegendDot color={SEV_COLOR.info} label="低/信息" />
      </div>
    </div>
  )
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1">
      <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: color }} aria-hidden />
      {label}
    </span>
  )
}
