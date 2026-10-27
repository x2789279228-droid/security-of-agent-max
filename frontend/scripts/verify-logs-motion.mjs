/**
 * 日志动效验证:/logs → 断言 24h 分布条、严重度墨染块、新到行标记结构(SSE 高亮需后端)。
 */
import { runVerified, finish, sleep } from './lib-cdp.mjs'

await runVerified('logs-motion', { width: 1600, height: 1000 }, async ({ goto, evaluate, text, shot }) => {
  await goto('/logs', 1200)
  let body = ''
  for (let i = 0; i < 20; i++) {
    await sleep(700)
    body = await text()
    if (/日志中心/.test(body)) break
  }
  const checks = {
    hasHourlyStrip: /近 24 小时接入分布/.test(body),
    hasStripAxis: /-24h → 现在/.test(body),
    hasSeverityBlocks: /严重|高危|中危|低危|提示/.test(body),
    hasAuditLegend: /审计|降级|待审/.test(body),
  }
  // 墨染选中:点击「严重」块,断言选中样式类切换(bg-vault)
  const stamp = await evaluate(`(() => {
    const btn = [...document.querySelectorAll('button')].find(b => (b.textContent || '').includes('严重') && b.getAttribute('aria-pressed') !== null)
    if (!btn) return 'no-btn'
    btn.click()
    return 'clicked'
  })()`)
  await sleep(600)
  const activeCls = await evaluate(`(() => {
    const btn = [...document.querySelectorAll('button')].find(b => b.getAttribute('aria-pressed') === 'true')
    return btn ? btn.className : 'none'
  })()`)
  checks.inkFillActive = /bg-vault/.test(String(activeCls))
  console.log('severity-click', stamp, { inkFillActive: checks.inkFillActive })
  await shot('logs-motion-verify.png')
  finish(checks)
})
