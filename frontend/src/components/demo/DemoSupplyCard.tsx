import { useCallback, useEffect, useState } from 'react'
import { api } from '../../lib/api'

/**
 * 演示补给卡(P3) — 一键灌入/清空 demo-seed 标注数据。
 * 放在 /demo 开场页:答辩开场先补给,再开演,保证感知/运营各页不露怯。
 */
export function DemoSupplyCard() {
  const [busy, setBusy] = useState<'seed' | 'clear' | null>(null)
  const [status, setStatus] = useState<Record<string, number> | null>(null)
  const [message, setMessage] = useState('')

  const refresh = useCallback(async () => {
    try {
      const s = await api.demoSeedStatus()
      setStatus(s)
    } catch {
      setStatus(null)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const seed = async (scene: 'all' | 'sensing') => {
    setBusy('seed')
    setMessage('')
    try {
      const r = await api.demoSeed(scene)
      setMessage(`已灌入:${Object.entries(r.seeded).filter(([, v]) => v > 0).map(([k, v]) => `${k} ${v}`).join(' · ') || '无新增(已存在)'}`)
      await refresh()
    } catch (e: any) {
      setMessage(e?.message || '灌入失败')
    } finally {
      setBusy(null)
    }
  }

  const clear = async () => {
    setBusy('clear')
    setMessage('')
    try {
      const r = await api.demoSeedClear()
      setMessage(`已清空:${Object.entries(r.deleted).filter(([, v]) => v > 0).map(([k, v]) => `${k} ${v}`).join(' · ') || '无标记行'}`)
      await refresh()
    } catch (e: any) {
      setMessage(e?.message || '清空失败')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="w-full max-w-[34rem] border border-[#24384a] bg-[#14222f] px-5 py-4 text-left">
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-[#c9a574]">演示补给 · Demo Seed</p>
        <span className="font-mono text-[10px] text-[#78889a]">标注 demo-seed · 可一键清空</span>
      </div>
      {status && (
        <p className="mt-2 font-mono text-[10px] tabular-nums text-[#78889a]">
          {Object.entries(status)
            .filter(([k]) => k !== 'marker')
            .map(([k, v]) => `${k}:${v}`)
            .join(' · ')}
        </p>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2.5">
        <button
          onClick={() => void seed('all')}
          disabled={busy !== null}
          className="border border-[#c9a574]/50 px-4 py-2 font-mono text-[10px] tracking-[0.2em] uppercase text-[#c9a574] hover:bg-[#182838] transition-colors disabled:opacity-40"
        >
          {busy === 'seed' ? '灌入中 …' : '一键灌入(全场景)'}
        </button>
        <button
          onClick={() => void seed('sensing')}
          disabled={busy !== null}
          className="border border-[#33475a] px-4 py-2 font-mono text-[10px] tracking-[0.2em] uppercase text-[#a7b4bd] hover:border-[#c9a574]/50 hover:text-[#c9a574] transition-colors disabled:opacity-40"
        >
          仅感知数据
        </button>
        <button
          onClick={() => void clear()}
          disabled={busy !== null}
          className="border border-[#33475a] px-4 py-2 font-mono text-[10px] tracking-[0.2em] uppercase text-[#a7b4bd] hover:border-[#e05a4e]/50 hover:text-[#e8887c] transition-colors disabled:opacity-40"
        >
          {busy === 'clear' ? '清空中 …' : '清空标记数据'}
        </button>
      </div>
      {message && <p className="mt-2.5 text-[11px] leading-relaxed text-[#a7b4bd]">{message}</p>}
    </div>
  )
}
