import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

/**
 * 2026-10-03 修复的回归护栏（前端结构性断言）
 *
 * 这三项修复的共同点：修复前的代码"看起来是好的"，只有把不变量写死才能防复发。
 *   1. Monitor 健康仪表曾硬编码为绿色，且数据源在全项目中根本不存在
 *   2. App.tsx 全部 15 条路由显式绕过 Guard
 *   3. 破坏性动作（威胁模拟 / 手动响应 / 回滚）单击直达生产
 *
 * 不依赖 node_modules / tsc —— 纯结构断言，CI 装不上依赖时也能跑。
 *   运行: node --experimental-strip-types --test scripts/securityUxFixes.test.ts
 */
const HERE = dirname(fileURLToPath(import.meta.url))
const SRC = join(HERE, '..', 'src')
const read = (p: string) => readFileSync(join(SRC, p), 'utf-8')

describe('修复 1：依赖健康仪表不得再伪装正常', () => {
  it('serviceStore 初值必须是 unknown，不能是 ok', () => {
    const src = read('stores/serviceStore.ts')
    // 初值里出现 'ok' 即为回归
    assert.doesNotMatch(
      src,
      /services:\s*\{[^}]*'ok'/,
      'serviceStore 初值不得包含 ok —— 探测完成前必须显示 UNKNOWN',
    )
    assert.match(src, /'unknown'/, "必须存在 'unknown' 态")
  })

  it('setUnprobed 存在：探测请求失败时能回落 UNKNOWN', () => {
    assert.match(read('stores/serviceStore.ts'), /setUnprobed/)
  })

  it('Monitor 真实轮询 /health/dependencies', () => {
    const src = read('pages/Monitor.tsx')
    assert.match(src, /api\.dependencyHealth\(\)/, 'Monitor 未调用依赖探针')
    assert.match(src, /setInterval\(tick,/, 'Monitor 未设置轮询')
  })

  it('SERVICE_TONE 的 unknown 态不得借用绿色', () => {
    const src = read('pages/Monitor.tsx')
    const m = src.match(/unknown:\s*\{[\s\S]*?\},/)
    assert.ok(m, 'SERVICE_TONE 缺少 unknown 映射')
    assert.doesNotMatch(
      m[0],
      /bg-ok|text-ok/,
      "unknown 态复用了 ok 的绿色 —— 会把'没探测到'显示成'正常'",
    )
  })

  it('服务 key 与后端探针项对齐', () => {
    for (const key of ['postgres', 'redis', 'qdrant', 'llm']) {
      assert.match(read('pages/Monitor.tsx'), new RegExp(`${key}:`), `缺少 ${key} 展示项`)
    }
  })
})

describe('修复 2：业务路由不得绕过 Guard', () => {
  it('App.tsx 中不存在 page(<X />, false) 形式的绕过', () => {
    const src = read('App.tsx')
    // 注: `[^>]+\/` 的斜杠需转义 —— node --experimental-strip-types 的解析器
    //     不接受字符类/量词之后紧跟未转义的 "/"。
    const bypasses = src.match(/page\(<[^>]+\/>\s*,\s*false\s*\)/g) ?? []
    assert.deepEqual(
      bypasses,
      [],
      `仍有 ${bypasses.length} 条路由绕过鉴权：${bypasses.join(', ')}`,
    )
  })

  it('page() 不再提供 auth 跳过开关', () => {
    const src = read('App.tsx')
    assert.doesNotMatch(src, /function page\(el: ReactNode, auth/, 'page() 仍带 auth 参数')
  })

  it('Guard 确实被使用', () => {
    assert.match(read('App.tsx'), /<Guard>/)
  })
})

describe('修复 3：破坏性动作必须二次确认', () => {
  it('ConfirmDialog 组件存在且具备焦点陷阱与 Esc 关闭', () => {
    const src = read('components/ui/ConfirmDialog.tsx')
    assert.match(src, /role="alertdialog"/, '缺少 alertdialog 语义')
    assert.match(src, /aria-modal="true"/, '缺少 aria-modal')
    assert.match(src, /e\.key === 'Escape'/, '缺少 Esc 关闭')
    assert.match(src, /cancelRef\.current\?\.focus\(\)/, '打开时应把焦点落在取消上')
  })

  it('Response 页的模拟/执行/回滚都经由确认', () => {
    const src = read('pages/Response.tsx')
    // 去掉注释行：修复说明里会引用旧的 onClick 形态，不应被当成残留
    const code = src
      .split('\n')
      .filter((l) => !l.trimStart().startsWith('//') && !l.trimStart().startsWith('*'))
      .join('\n')

    // 按钮不得再直接绑定底层动作
    assert.doesNotMatch(
      code,
      /onClick=\{\(\) => simulateThreat\(/,
      '仍有按钮直接调用 simulateThreat，绕过确认',
    )
    assert.doesNotMatch(code, /onClick=\{handleExecResponse\}/, '手动执行未接确认')
    assert.doesNotMatch(code, /onClick=\{handleRollback\}/, '回滚未接确认')
    assert.match(code, /onClick=\{\(\) => requestSimulate\(/, '预设按钮未走 requestSimulate')
    assert.match(code, /requestExecResponse/, '手动执行未接确认')
    assert.match(code, /requestRollback/, '回滚未接确认')
    assert.match(code, /<ConfirmDialog/, '未挂载 ConfirmDialog')
  })

  it('确认文案复述了影响面（提到 auto_execute / 真实动作）', () => {
    const src = read('pages/Response.tsx')
    assert.match(src, /auto_execute/, '确认弹窗未说明 auto_execute 的后果')
    assert.match(src, /真实响应动作|立即恢复网络访问/, '确认弹窗未复述真实影响')
  })
})

describe('修复 4：因果判定不得在前端被压成一个词', () => {
  // 整改方案 §三.1 末段：前端必须能区分 causal_support / not_identifiable /
  // insufficient_data / unknown，「不能把这些结果统一映射成一个真假值」。
  //
  // 修复前 SecurityAudit.tsx 是一个三支三元表达式：
  //   causal_support ? '因果支持' : (spurious ? '伪相关' : '未知')
  // 其中 'spurious' 根本不在后端 VERDICTS 里（死分支），
  // 其余四种判定全部落进 '未知'，界面上完全同形。
  const verdictMap = () => {
    const src = read('pages/SecurityAudit.tsx')
    const m = src.match(/CAUSAL_VERDICT_LABEL[^=]*=\s*\{([\s\S]*?)\}/)
    assert.ok(m, '找不到 CAUSAL_VERDICT_LABEL 映射表 —— 五种判定很可能又被压回去了')
    return m
  }

  it('五种判定各自都有标签', () => {
    const body = verdictMap()[1]
    for (const v of [
      'causal_support',
      'insufficient_causal_evidence',
      'not_identifiable',
      'insufficient_data',
      'unknown',
    ]) {
      assert.match(body, new RegExp(`\\b${v}:`), `缺少 ${v} 的标签`)
    }
  })

  it('标签表不得含后端从不产出的取值', () => {
    // 多出来的键就是永远不成立的死分支，会让人以为存在一种其实没有的结论
    const keys = [...verdictMap()[1].matchAll(/([a-z_]+)\s*:/g)].map((m) => m[1])
    assert.equal(keys.length, 5, `标签表有 ${keys.length} 项，应为 5：${keys.join(', ')}`)
  })

  it('五个标签必须互不相同', () => {
    const labels = [...verdictMap()[1].matchAll(/:\s*'([^']+)'/g)].map((m) => m[1])
    assert.equal(labels.length, 5)
    assert.equal(new Set(labels).size, labels.length, `标签有重复：${labels.join(', ')}`)
  })

  it('渲染处不得再有 ternary 链，也不得再出现 spurious', () => {
    const src = read('pages/SecurityAudit.tsx')
    assert.doesNotMatch(
      src,
      /causal_verdict\s*===/,
      '又写回了 causal_verdict === ... 的三元链 —— 五种判定会被压回同一个词',
    )
    const code = src
      .split('\n')
      .filter((l) => !l.trimStart().startsWith('*') && !l.trimStart().startsWith('//'))
      .join('\n')
    assert.doesNotMatch(code, /'spurious'/, "代码里仍有 'spurious' —— 后端从不产出这个判定")
  })

  it('表外的取值直接显示原值，不得谎报成「未知」', () => {
    const src = read('pages/SecurityAudit.tsx')
    assert.match(
      src,
      /CAUSAL_VERDICT_LABEL\[c\.causal_verdict\] \?\? c\.causal_verdict/,
      '缺少 ?? c.causal_verdict 兜底 —— 后端将来新增判定时会显示成别的结论',
    )
  })
})