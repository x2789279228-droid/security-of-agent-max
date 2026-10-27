/**
 * 评测战绩页验证:login → /benchmark → 断言卷宗结构与关键数字口径
 * 有后端 + ADMIN_PASS 时验证真实数据;哑 token 时验证结构与空态文案。
 */
import { runVerified, finish, sleep } from './lib-cdp.mjs'

await runVerified('benchmark', { width: 1440, height: 1100 }, async ({ goto, text, shot }) => {
  await goto('/benchmark', 1200)
  // 轮询等待懒加载完成
  let body = ''
  for (let i = 0; i < 20; i++) {
    await sleep(800)
    body = await text()
    if (/评测战绩/.test(body)) break
  }
  const checks = {
    hasTitle: /评测战绩/.test(body),
    hasDossierTabs: /卷宗|BENCHMARK/.test(body),
    // 有后端:关键数字;无后端:诚实空态
    hasDataOrHonestEmpty: /CSIC|25,065|误报|卷宗尚未归档|未找到评测结果/.test(body),
    hasScopeDiscipline: /口径|docs\/benchmark/.test(body),
  }
  console.log(JSON.stringify({ checks, preview: body.replace(/\s+/g, ' ').slice(0, 500) }, null, 2))
  await shot('benchmark-verify.png')
  finish(checks)
})
