#!/usr/bin/env node
/**
 * 中国省界 GeoJSON → 前端 TS 地图资产 (A2 攻击态势地图)
 *
 * 输入: 阿里 DataV GeoAtlas 100000_full.json (省级 GeoJSON)
 * 输出: frontend/src/assets/chinaMap.ts
 *   export const CHINA_PROVINCES: { name, rings: [lon,lat][][], centroid: [lon,lat] }[]
 *
 * 简化策略: 每条环做最小间距抽稀 (MIN_DEG 度), 坐标量化到 2 位小数 —
 * 墙面显示足够, 体积从 ~580KB 压到百 KB 级。周边小岛(< MIN_POINTS 点)丢弃。
 *
 * 用法: node tools/build-china-map.mjs <geojson> [out-ts]
 */
import { readFileSync, writeFileSync } from 'node:fs'

const [, , input = '/tmp/china-100000.json', output = 'frontend/src/assets/chinaMap.ts'] = process.argv

const MIN_DEG = 0.08          // 抽稀最小间距(度)
const MIN_RING_POINTS = 6     // 少于该点数的环丢弃(小岛)

function decimate(ring) {
  const out = []
  let last = null
  for (const p of ring) {
    if (!last || Math.abs(p[0] - last[0]) + Math.abs(p[1] - last[1]) >= MIN_DEG) {
      out.push([Math.round(p[0] * 100) / 100, Math.round(p[1] * 100) / 100])
      last = p
    }
  }
  return out.length >= 2 ? out : null
}

const geo = JSON.parse(readFileSync(input, 'utf8'))
const provinces = []
for (const f of geo.features ?? []) {
  const name = f.properties?.name ?? ''
  if (!name) continue
  const geom = f.geometry
  if (!geom) continue
  const polys = geom.type === 'MultiPolygon' ? geom.coordinates
    : geom.type === 'Polygon' ? [geom.coordinates] : []
  const rings = []
  for (const poly of polys) {
    for (const ring of poly) {
      const simplified = decimate(ring)
      if (simplified && simplified.length >= MIN_RING_POINTS) rings.push(simplified)
    }
  }
  if (!rings.length) continue
  const centroid = f.properties?.centroid ?? f.properties?.center ?? null
  provinces.push({
    name,
    centroid: centroid ? [Math.round(centroid[0] * 100) / 100, Math.round(centroid[1] * 100) / 100] : null,
    rings,
  })
}

const ts = `/**
 * 中国省界地图资产 (自动生成, 勿手改) — node tools/build-china-map.mjs
 * 源: 阿里 DataV GeoAtlas 100000_full.json (公开地理栅格, 仅用于态势可视化)
 * 坐标为 [lon, lat] 原始经纬度, 投影在前端完成 (cos(35°) 校正等距圆柱)。
 */
export interface ChinaProvince {
  name: string
  centroid: [number, number] | null
  rings: number[][][]
}

export const CHINA_PROVINCES: ChinaProvince[] = ${JSON.stringify(provinces)}
`
writeFileSync(output, ts, 'utf8')
const kb = Math.round(ts.length / 1024)
console.log(`wrote ${output}: ${provinces.length} provinces, ${kb}KB`)
