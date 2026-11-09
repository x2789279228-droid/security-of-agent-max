/**
 * copilot 流状态归约测试 — applyFrame / applyAction（2026-11 传智杯 AI Web 改造）
 *
 * 覆盖：stage upsert（乱序到达按流水线序插入）/ token·reasoning 增量累积 /
 * citations / vision_note / error（active 阶段转 skipped）/ done（content 权威重置、
 * 阶段结转）/ fail（网络失败）/ 跨轮互不串扰。
 * 运行：npm run test:copilot
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  applyFrame,
  applyAction,
  nextTurnId,
  type CopilotTurn,
} from '../src/hooks/useCopilotStream.ts'

function blankTurn(): CopilotTurn {
  return {
    id: nextTurnId(),
    question: '测试问题',
    stages: [],
    reasoning: '',
    answer: '',
    citations: [],
    done: false,
  }
}

test('stage 帧乱序到达仍按流水线顺序插入，重复帧刷新 detail', () => {
  let t = blankTurn()
  t = applyFrame(t, 'stage', { stage: 'answer', detail: '生成回答' })
  t = applyFrame(t, 'stage', { stage: 'context', detail: '拉取事件 #1' })
  assert.deepEqual(t.stages.map((s) => s.stage), ['context', 'answer'])
  t = applyFrame(t, 'stage', { stage: 'context', detail: '上下文就绪' })
  assert.equal(t.stages[0].detail, '上下文就绪')
  assert.equal(t.stages[0].status, 'active')
})

test('token / reasoning 增量累积', () => {
  let t = blankTurn()
  t = applyFrame(t, 'reasoning', { text: '先看' })
  t = applyFrame(t, 'reasoning', { text: '证据' })
  t = applyFrame(t, 'token', { text: '结论：' })
  t = applyFrame(t, 'token', { text: '是攻击' })
  assert.equal(t.reasoning, '先看证据')
  assert.equal(t.answer, '结论：是攻击')
  assert.equal(t.done, false)
})

test('citations 与 vision_note 各就各位', () => {
  let t = blankTurn()
  const cits = [{ index: 1, title: 'C2 检测要点', source: 'MITRE', snippet: '…' }]
  t = applyFrame(t, 'citations', { citations: cits })
  t = applyFrame(t, 'vision_note', { text: '视觉模型未配置' })
  assert.equal(t.citations.length, 1)
  assert.equal(t.visionNote, '视觉模型未配置')
})

test('error 帧：记录错误并把 active 阶段转 skipped', () => {
  let t = blankTurn()
  t = applyFrame(t, 'stage', { stage: 'rag', detail: '检索中' })
  t = applyFrame(t, 'error', { text: 'LLM 未配置', fallback: true })
  assert.equal(t.error, 'LLM 未配置')
  assert.equal(t.stages[0].status, 'skipped')
})

test('done 帧：content 为权威重置、usage/latency 落位、阶段结转 done', () => {
  let t = blankTurn()
  t = applyFrame(t, 'stage', { stage: 'context', detail: '拉取事件' })
  t = applyFrame(t, 'stage', { stage: 'rag', detail: '检索' })
  t = applyFrame(t, 'token', { text: '流式答案' })
  t = applyFrame(t, 'done', {
    content: '最终答案（完整）',
    citations: [{ index: 1, title: 'x', source: '', snippet: '' }],
    usage: { total_tokens: 42 },
    latency_ms: 1234,
  })
  assert.equal(t.answer, '最终答案（完整）')
  assert.equal(t.done, true)
  assert.equal(t.usage?.total_tokens, 42)
  assert.equal(t.latencyMs, 1234)
  assert.equal(t.citations.length, 1)
  assert.ok(t.stages.every((s) => s.status === 'done'))
})

test('done 时 RAG 无命中 → rag 阶段如实转 skipped', () => {
  let t = blankTurn()
  t = applyFrame(t, 'stage', { stage: 'rag', detail: '检索' })
  t = applyFrame(t, 'citations', { citations: [] })
  t = applyFrame(t, 'done', { content: '答案', citations: [], usage: {} })
  assert.equal(t.stages.find((s) => s.stage === 'rag')?.status, 'skipped')
})

test('applyAction fail：网络失败标 error + done', () => {
  let state = [blankTurn()]
  const id = state[0].id
  state = applyAction(state, { kind: 'fail', turnId: id, message: 'API 502: bad gateway' })
  assert.equal(state[0].error, 'API 502: bad gateway')
  assert.equal(state[0].done, true)
})

test('多轮互不串扰：帧只落到目标轮', () => {
  const t1 = blankTurn()
  const t2 = blankTurn()
  let state = [t1, t2]
  state = applyAction(state, { kind: 'frame', turnId: t2.id, event: 'token', data: { text: 'B' } })
  assert.equal(state[0].answer, '')
  assert.equal(state[1].answer, 'B')
})
