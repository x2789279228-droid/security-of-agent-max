/**
 * 审计大屏验证:login → /monitor → 进入大屏模式 → 断言三列网格与层叠面板 → Esc 退出。
 * 哑 token 时后端数据为空,验证的是结构与暗色战场骨架。
 */
import { runVerified, finish, sleep } from './lib-cdp.mjs'

await runVerified('battle', { width: 1920, height: 1080 }, async ({ goto, evaluate, text, shot }) => {
  await goto('/monitor', 1200)
  // 轮询等待 Monitor 页(懒加载)
  let clicked = 'no-btn'
  for (let i = 0; i < 20 && clicked !== 'clicked'; i++) {
    await sleep(800)
    clicked = await evaluate(`(() => {
      const btn = [...document.querySelectorAll('button')].find(b => /大屏模式/.test(b.textContent || ''))
      if (!btn) return 'no-btn'
      btn.click()
      return 'clicked'
    })()`)
  }
  console.log('battle-click', clicked)
  await sleep(1200)

  // 轮询等待大屏网格
  let body = ''
  for (let i = 0; i < 12; i++) {
    body = await text()
    if (/审计作战/.test(body)) break
    await sleep(700)
  }
  const checks = {
    enteredBattle: /审计作战/.test(body),
    hasLeftColumn: /依赖健康|作战指标/.test(body),
    hasMainStage: /思维链|主舞台|审查接力/.test(body),
    hasRightColumn: /实时事件流|事件类型计数/.test(body),
    hasFooterTape: /管线在跳|值守/.test(body),
    darkModeOn: await evaluate(`document.documentElement.dataset.mode === 'battle'`),
  }
  console.log(JSON.stringify({ checks, preview: body.replace(/\s+/g, ' ').slice(0, 400) }, null, 2))
  await shot('battle-verify.png')

  // Esc 退出
  await evaluate(`document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))`)
  await sleep(1200)
  const after = await text()
  checks.exitRestores = !/审计作战/.test(after) && /系统监控|实时事件|接力/.test(after)
  console.log('exit', { exitRestores: checks.exitRestores })
  finish(checks)
})
