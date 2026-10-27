/**
 * 攻击剧本验证:login → /demo → 演练模式(纯前端,不依赖后端) →
 * 断言六幕推进与结案印章落定。全程 ≤ 60s。
 */
import { runVerified, finish, sleep } from './lib-cdp.mjs'

await runVerified('demo', { width: 1600, height: 1000 }, async ({ goto, evaluate, text, shot }) => {
  await goto('/demo', 1500)

  // 轮询等待开场页(懒加载 chunk 在 headless 冷启动下可能 >3s)
  let start = ''
  let startChecks = { hasStartScreen: false, hasSixActs: false }
  for (let i = 0; i < 20; i++) {
    await sleep(800)
    start = await text()
    startChecks.hasStartScreen = /攻击剧本|实时开演|演练模式/.test(start)
    if (startChecks.hasStartScreen) break
  }
  startChecks.hasSixActs = /六幕|第一幕|入侵/.test(start)
  console.log('start', JSON.stringify(startChecks))

  // 点「演练模式(离线)」
  let clicked = 'no-btn'
  for (let i = 0; i < 10 && clicked === 'no-btn'; i++) {
    clicked = await evaluate(`(() => {
      const btn = [...document.querySelectorAll('button')].find(b => /演练模式/.test(b.textContent || ''))
      if (!btn) return 'no-btn'
      btn.click()
      return 'clicked'
    })()`)
    if (clicked !== 'clicked') await sleep(800)
  }
  console.log('rehearsal-click', clicked)

  // 轮询幕次推进(最长 50s)
  let reachedReason = false
  let sealText = ''
  for (let i = 0; i < 50; i++) {
    await sleep(1000)
    const body = await text()
    if (/第四幕|思维链/.test(body)) reachedReason = true
    const seal = body.match(/已阻断|已处置|待审批/)
    if (seal && /结案/.test(body)) {
      sealText = seal[0]
      break
    }
  }
  const end = await text()
  const runChecks = {
    rehearsalBadge: /演练/.test(end),
    reachedReason,
    sealLanded: /已阻断|已处置|待审批/.test(end),
    typewriterOrSteps: /思维链|步/.test(end),
  }
  console.log('run', JSON.stringify({ ...runChecks, sealText }))
  await shot('demo-verify-seal.png')
  finish({ ...startChecks, ...runChecks })
})
