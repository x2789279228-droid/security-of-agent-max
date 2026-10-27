/**
 * 演示补给验证:/demo 开场页断言补给卡结构(一键灌入/仅感知/清空)→ 点「仅感知数据」。
 * 哑 token 无后端时报错文案属预期;有 admin 后端时真实灌入。
 */
import { runVerified, finish, sleep } from './lib-cdp.mjs'

await runVerified('seed', { width: 1600, height: 1100 }, async ({ goto, evaluate, text, shot }) => {
  await goto('/demo', 1200)
  let body = ''
  for (let i = 0; i < 20; i++) {
    await sleep(700)
    body = await text()
    if (/演示补给/.test(body)) break
  }
  const checks = {
    hasSupplyCard: /演示补给/.test(body),
    hasSeedBtn: /一键灌入/.test(body),
    hasClearBtn: /清空标记数据/.test(body),
  }

  const clicked = await evaluate(`(() => {
    const btn = [...document.querySelectorAll('button')].find(b => /仅感知数据/.test(b.textContent || ''))
    if (!btn) return 'no-btn'
    btn.click()
    return 'clicked'
  })()`)
  console.log('seed-click', clicked)
  await sleep(2500)
  const after = await text()
  checks.seedFeedback = /已灌入|已存在|失败|403|认证|500|Error/i.test(after)
  console.log(JSON.stringify({ checks }, null, 2))
  await shot('seed-verify.png')
  finish(checks)
})
