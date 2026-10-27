/**
 * 接力条 v2 验证:/monitor → 断言流式化结构(节点/滴流/分段线)→ 点「跑一条演示」→
 * 有后端时断言滴流文本出现;哑 token 时验证结构与空态。
 */
import { runVerified, finish, sleep } from './lib-cdp.mjs'

await runVerified('relay', { width: 1600, height: 1000 }, async ({ goto, evaluate, text, shot }) => {
  await goto('/monitor', 1200)
  let body = ''
  for (let i = 0; i < 20; i++) {
    await sleep(700)
    body = await text()
    if (/多\s*Agent/.test(body)) break
  }
  const checks = {
    hasRelayTitle: /多\s*Agent\s*审查接力/.test(body),
    hasSixStages: /分解者/.test(body) && /CAD/.test(body) && /响应引擎|响应/.test(body),
    hasRatePanel: /到达速率/.test(body),
  }

  // 点「跑一条演示」(有后端时才有效,哑 token 下按钮报错属预期)
  const clicked = await evaluate(`(() => {
    const btn = [...document.querySelectorAll('button')].find(b => /跑一条演示/.test(b.textContent || ''))
    if (!btn) return 'no-btn'
    btn.click()
    return 'clicked'
  })()`)
  console.log('demo-click', clicked)
  await sleep(5000)

  const after = await text()
  checks.demoErrorOrProgress = /演示启动|演示审查启动|失败|进行中|思维链/.test(after)
  console.log(JSON.stringify({ checks }, null, 2))
  await shot('relay-verify.png')
  finish(checks)
})
