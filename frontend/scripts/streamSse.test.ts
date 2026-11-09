/**
 * streamSse 单元测试 — SseParser 纯解析器（2026-11 AI Web 改造）
 *
 * 覆盖：完整帧 / 跨 chunk 切割（逐字节喂）/ CRLF / 多 data 行 / 注释行 /
 * event 字段缺省 / 无终止空行的最后一帧（end() 宽容冲洗）。
 * 运行：npm run test:stream （node --experimental-strip-types --test）
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { SseParser } from '../src/lib/streamSse.ts'

function collect() {
  const frames: { event: string; data: string }[] = []
  return {
    frames,
    parser: new SseParser((f) => frames.push({ ...f })),
  }
}

test('完整帧：event + data + 空行边界', () => {
  const { frames, parser } = collect()
  parser.feed('event: token\ndata: {"text":"你好"}\n\n')
  parser.end()
  assert.equal(frames.length, 1)
  assert.equal(frames[0].event, 'token')
  assert.equal(frames[0].data, '{"text":"你好"}')
})

test('跨 chunk 逐字节切割不丢帧', () => {
  const { frames, parser } = collect()
  const payload = 'event: reasoning\ndata: {"text":"思考"}\n\nevent: token\ndata: {"text":"答"}\n\n'
  for (const ch of payload) parser.feed(ch)
  parser.end()
  assert.equal(frames.length, 2)
  assert.equal(frames[0].event, 'reasoning')
  assert.equal(frames[1].event, 'token')
})

test('CRLF 行结束符兼容', () => {
  const { frames, parser } = collect()
  parser.feed('event: done\r\ndata: {"content":"x"}\r\n\r\n')
  parser.end()
  assert.equal(frames.length, 1)
  assert.equal(frames[0].data, '{"content":"x"}')
})

test('多 data 行按规范以 \\n 连接', () => {
  const { frames, parser } = collect()
  parser.feed('data: line1\ndata: line2\n\n')
  parser.end()
  assert.equal(frames.length, 1)
  assert.equal(frames[0].event, 'message')
  assert.equal(frames[0].data, 'line1\nline2')
})

test('冒号注释行与 data: 前导空格剥离', () => {
  const { frames, parser } = collect()
  parser.feed(': heartbeat\ndata: {"a":1}\n\n')
  parser.end()
  assert.equal(frames.length, 1)
  assert.equal(frames[0].data, '{"a":1}')
})

test('end() 冲洗无终止空行的尾帧（网关忘发空行的宽容口径）', () => {
  const { frames, parser } = collect()
  parser.feed('event: token\ndata: {"text":"尾巴"}\n')
  parser.end()
  assert.equal(frames.length, 1)
  assert.equal(frames[0].data, '{"text":"尾巴"}')
})

test('半行留缓冲：chunk 边界切在行中间不产生假帧', () => {
  const { frames, parser } = collect()
  parser.feed('event: token\ndata: {"tex')
  assert.equal(frames.length, 0)
  parser.feed('t":"ok"}\n\n')
  parser.end()
  assert.equal(frames.length, 1)
  assert.equal(frames[0].data, '{"text":"ok"}')
})

test('onFrame 回调异常不拖垮解析器', () => {
  let calls = 0
  const parser = new SseParser(() => {
    calls += 1
    if (calls === 1) throw new Error('handler boom')
  })
  parser.feed('data: one\n\ndata: two\n\n')
  parser.end()
  assert.equal(calls, 2)
})
