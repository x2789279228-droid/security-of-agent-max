import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { useDemoDirector } from '../hooks/useDemoDirector'
import { ThoughtTypewriter } from '../components/demo/ThoughtTypewriter'
import { SealSlam } from '../components/demo/SealSlam'
import { DemoSupplyCard } from '../components/demo/DemoSupplyCard'
import { SCENES, MODE_BADGE } from '../lib/demoScript'
import { AgentCards } from '../components/demo/AgentCards'
import { ROUTES } from '../lib/constants'

/**
 * 攻击剧本沉浸演示(阶段 3) — 全屏暗色作战舞台,六幕讲完「多智能体编排」。
 *
 * 三模数据源(实时/降级/演练)共用导演状态机;模式明示于顶栏徽章。
 * 独立于 RootLayout 挂载,进入即设置 data-mode=battle 并锁定页面滚动。
 */

const fmtElapsed = (ms: number) => {
  const s = ms / 1000
  if (s < 60) return `${s.toFixed(1)}s`
  return `${Math.floor(s / 60)}m${Math.floor(s % 60)}s`
}

// ── 左栏:六幕目录 ──
function SceneRail({ state }: { state: ReturnType<typeof useDemoDirector>['state'] }) {
  return (
    <nav className="flex flex-col gap-1" aria-label="剧本幕次">
      {SCENES.map((scene, i) => {
        const status = state.sceneStatus[scene.id]
        const active = state.sceneIdx === i
        return (
          <div
            key={scene.id}
            className={`relative border px-4 py-3 transition-colors ${
              active
                ? 'border-[#d9b36a]/40 bg-[#263041]'
                : status === 'done' || status === 'skipped'
                  ? 'border-transparent opacity-70'
                  : 'border-transparent opacity-40'
            }`}
          >
            {active && <span className="absolute left-0 top-0 bottom-0 w-[2px] bg-[#d9b36a]" aria-hidden />}
            <p className="flex items-baseline gap-2.5">
              <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#d9b36a]">{scene.num}</span>
              <span className="font-serif text-[16px] font-bold text-[#e9edf2]">{scene.title}</span>
              <span className="ml-auto font-mono text-[11px] text-[#6e7a88]">
                {status === 'done' ? '✓' : status === 'skipped' ? '—' : active ? '▶' : ''}
              </span>
            </p>
            <p className="mt-1 text-[12px] leading-snug text-[#6e7a88]">{scene.caption}</p>
          </div>
        )
      })}
    </nav>
  )
}

// ── 中栏:六个岗位接力（AgentCards 承载，见 components/demo/AgentCards.tsx）──

export default function Demo() {
  const navigate = useNavigate()
  const { state, start, startRehearsal, togglePause, skipScene, reset } = useDemoDirector()

  // ── 舞台/录制模式（?stage=1&autoplay=1）──
  // 不新建页面：URL 参数控制"干净舞台"，默认行为完全不变。
  // 用途：录屏 / 投屏 / 现场演示时隐藏左右技术面板、隐藏鼠标与底栏。
  const [{ stageMode, autoplay }] = useState(() => {
    const q = new URLSearchParams(window.location.search)
    const stage = q.get('stage') === '1'
    return { stageMode: stage, autoplay: stage && q.get('autoplay') !== '0' }
  })

  // 延迟一拍再开演：React StrictMode 会"挂载→清理→再挂载"，
  // 直接同步调用会被导演 hook 的卸载清理清掉时间轴，表现为永远停在第一幕。
  useEffect(() => {
    if (!autoplay) return
    const t = window.setTimeout(() => startRehearsal(), 60)
    return () => window.clearTimeout(t)
  }, [autoplay, startRehearsal])

  useEffect(() => {
    if (!stageMode) return
    const el = document.documentElement
    el.dataset.stage = '1'
    return () => {
      delete el.dataset.stage
    }
  }, [stageMode])

  useEffect(() => {
    if (!stageMode) return
    const onKey = (e: KeyboardEvent) => {
      if (e.code === 'Space') {
        e.preventDefault()
        togglePause()
      } else if (e.key === 'r' || e.key === 'R') {
        reset()
        startRehearsal()
      } else if (e.key === 'Escape') {
        navigate(ROUTES.MONITOR)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [stageMode, togglePause, reset, startRehearsal, navigate])

  // ── 结案 → 作战大屏 接力(阶段 6)──
  // 印章落定即开始 5s 倒计时,倒计时走完自动移交 /screen;
  // 同一事件经 ?event= 深链在大屏思维链主舞台继续呼吸,形成一条不间断的叙事弧。
  const [handoffIn, setHandoffIn] = useState<number | null>(null)
  const handoffCtlRef = useRef<{ stop: () => void } | null>(null)
  const stateEventIdRef = useRef(state.eventId)
  stateEventIdRef.current = state.eventId

  const gotoScreen = useCallback(() => {
    handoffCtlRef.current?.stop()
    const eid = stateEventIdRef.current
    navigate(eid ? `${ROUTES.SCREEN}?event=${eid}` : ROUTES.SCREEN)
  }, [navigate])

  const beginHandoff = useCallback(() => {
    handoffCtlRef.current?.stop()
    let left = 5
    setHandoffIn(left)
    const iv = setInterval(() => {
      left -= 1
      if (left >= 0) setHandoffIn(left)
    }, 1000)
    const to = setTimeout(() => {
      clearInterval(iv)
      gotoScreen()
    }, 5200)
    handoffCtlRef.current = {
      stop: () => {
        clearInterval(iv)
        clearTimeout(to)
        setHandoffIn(null)
      },
    }
  }, [gotoScreen])

  // 卸载兜底:清掉还在跑的倒计时
  useEffect(() => () => handoffCtlRef.current?.stop(), [])

  // 全屏暗色作战场景:token 翻转 + 锁滚动,退出还原
  useEffect(() => {
    const el = document.documentElement
    const prevMode = el.dataset.mode
    el.dataset.mode = 'battle'
    document.body.style.overflow = 'hidden'
    return () => {
      if (prevMode === undefined) delete el.dataset.mode
      else el.dataset.mode = prevMode
      document.body.style.overflow = ''
    }
  }, [])

  const badge = MODE_BADGE[state.mode]
  const notStarted = state.sceneIdx === -1
  const currentScene = state.sceneIdx >= 0 ? SCENES[state.sceneIdx] : null

  return (
    <PageTransition>
      <div
        className={`stage-voice flex min-h-screen flex-col bg-[#0f1216] font-sans text-[#e9edf2] ${
          stageMode ? 'cursor-none select-none' : ''
        }`}
      >
        {/* ── 顶栏 ── */}
        <header className="flex h-14 shrink-0 items-center gap-5 border-b border-[#2a323c] px-6">
          <span className="font-serif text-[18px] font-semibold tracking-[-0.02em]">守望</span>
          <span className="font-mono text-[10px] tracking-[0.26em] uppercase text-[#d9b36a]">
            攻击剧本 · 沉浸演示
          </span>
          <span className={`px-2 py-0.5 font-mono text-[10px] tracking-[0.2em] uppercase ${badge.cls}`}>
            {badge.label}
          </span>
          {state.running && (
            <span className="font-mono text-[11px] tabular-nums text-[#6e7a88]">{fmtElapsed(state.elapsedMs)}</span>
          )}
          {state.degradedNote && (
            <span className="hidden truncate font-mono text-[10px] text-[#e4c489] md:inline">{state.degradedNote}</span>
          )}
          {!stageMode && (
            <div className="ml-auto flex items-center gap-2">
              {state.running && !state.finished && (
                <>
                  <button
                    onClick={togglePause}
                    className="border border-[#2a323c] px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#a7b4bd] hover:border-[#d9b36a]/50 hover:text-[#e9edf2] transition-colors"
                  >
                    {state.paused ? '▶ 继续' : '⏸ 暂停'}
                  </button>
                  <button
                    onClick={skipScene}
                    disabled={state.paused}
                    className="border border-[#2a323c] px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#a7b4bd] hover:border-[#d9b36a]/50 hover:text-[#e9edf2] transition-colors disabled:opacity-40"
                  >
                    ⏭ 跳过本幕
                  </button>
                </>
              )}
              {(state.running || state.finished) && (
                <button
                  onClick={reset}
                  className="border border-[#2a323c] px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#a7b4bd] hover:border-[#d9b36a]/50 hover:text-[#e9edf2] transition-colors"
                >
                  ↺ 重演
                </button>
              )}
              <button
                onClick={() => navigate(ROUTES.MONITOR)}
                className="border border-[#d9b36a]/40 px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#d9b36a] hover:bg-[#263041] transition-colors"
              >
                退出
              </button>
            </div>
          )}
          {stageMode && (
            <span className="ml-auto font-mono text-[10px] tracking-[0.16em] uppercase text-[#6e7a88]">
              空格暂停 · R 重演 · Esc 退出
            </span>
          )}
        </header>

        {/* ── 开场(未开演)── */}
        {notStarted && (
          <div className="flex flex-1 flex-col items-center justify-center px-8 text-center">
            <p className="font-mono text-[11px] tracking-[0.4em] uppercase text-[#d9b36a]">Demo Script · 六幕</p>
            <h1 className="mt-4 font-serif text-[52px] font-semibold leading-tight tracking-[-0.03em]">
              一次 C2 外联的
              <br />
              完整处置
            </h1>
            <p className="mt-5 max-w-[36rem] font-serif text-[15px] leading-relaxed text-[#a7b4bd]">
              注入 → 检测 → 四层 Agent 接力 → 思维链逐字推理 → 响应处置 → 结案盖章。
              实时模式走真实流水线(SSE 驱动,后端不可达时自动降级并明示);演练模式离线运行,供录屏使用。
            </p>
            <div className="mt-9 flex items-center gap-4">
              <button
                onClick={start}
                className="border border-[#d9b36a] bg-[#0f1216] px-8 py-3.5 font-serif text-[16px] font-semibold tracking-[0.06em] text-[#f1e8d6] hover:bg-[#263041] transition-colors"
              >
                ▶ 实时开演
              </button>
              <button
                onClick={startRehearsal}
                className="border border-[#33475a] px-8 py-3.5 font-mono text-[11px] tracking-[0.24em] uppercase text-[#a7b4bd] hover:border-[#d9b36a]/60 hover:text-[#d9b36a] transition-colors"
              >
                演练模式(离线)
              </button>
            </div>
            {state.error && (
              <p className="mt-6 max-w-[32rem] border border-[#d4a054]/40 bg-[#d4a054]/10 px-4 py-2.5 text-[13px] text-[#e4c489]">
                {state.error}
              </p>
            )}

            {/* 演示补给:开场先把空表灌满,感知/运营各页不露怯 */}
            <div className="mt-8 flex justify-center">
              <DemoSupplyCard />
            </div>
          </div>
        )}

        {/* ── 舞台(开演后)── */}
        {!notStarted && (
          <div
            className={`relative grid flex-1 gap-6 overflow-hidden p-6 ${
              stageMode ? 'grid-cols-[280px_1fr]' : 'grid-cols-[280px_1fr_300px]'
            }`}
          >
            {/* 左:幕次目录 */}
            <aside className="overflow-y-auto">
              <SceneRail state={state} />
            </aside>

            {/* 中:当前幕内容 */}
            <main className="relative flex min-w-0 flex-col overflow-hidden border border-[#2a323c] bg-[#14222f] p-7">
              <AnimatePresence mode="wait">
                <motion.div
                  key={state.sceneIdx}
                  initial={{ opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
                  className="flex flex-1 flex-col"
                >
                  {currentScene && (
                    <>
                      <p className="font-mono text-[10px] tracking-[0.3em] uppercase text-[#d9b36a]">
                        {currentScene.num} · {currentScene.title}
                      </p>
                      <p className="mt-1 font-serif text-[22px] font-semibold text-[#e9edf2]">{currentScene.caption}</p>
                      <p className="mt-2 max-w-[46rem] text-[13px] leading-relaxed text-[#8fa0ad]">
                        {currentScene.keyLine}
                      </p>
                    </>
                  )}

                  <div className="mt-7 flex flex-1 flex-col justify-center">
                    {/* 幕 1:事件卡飞入 */}
                    {state.sceneIdx === 0 && (
                      <motion.div
                        initial={{ opacity: 0, x: -70 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
                        className="mx-auto w-full max-w-[30rem] border border-[#e05a4e]/50 bg-[#263041] p-5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="border border-[#e05a4e]/50 bg-[#e05a4e]/10 px-2 py-0.5 font-mono text-[10px] tracking-[0.2em] uppercase text-[#e8887c]">
                            critical
                          </span>
                          <span className="font-mono text-[10px] tracking-[0.18em] uppercase text-[#6e7a88]">
                            {state.eventId ? `事件 #${state.eventId}` : '注入中…'}
                          </span>
                        </div>
                        <p className="mt-3 font-mono text-[15px] font-bold tracking-[0.06em] text-[#e8eee9]">C2_BEACON</p>
                        <p className="mt-2 font-mono text-[13px] text-[#a7b4bd]">
                          {state.event?.src ?? '192.168.1.105'}
                          <span className="mx-2 text-[#d9b36a]">──→</span>
                          {state.event?.dst ?? '23.129.64.33'}
                        </p>
                        <p className="mt-2 text-[13px] leading-relaxed text-[#6e7a88]">
                          {state.event?.message ?? '内部主机疑似与 C2 服务器周期性通信'}
                        </p>
                        <p className="mt-3 border-t border-[#e05a4e]/20 pt-3 font-mono text-[11px] tracking-[0.04em] text-[#c9a574]/90">
                          周期 60s · 出站约 3KB/次 · 目的 IP 无备案 · 命中外联基线（演练口径）
                        </p>
                      </motion.div>
                    )}

                    {/* 幕 2:检测信号 */}
                    {state.sceneIdx === 1 && (
                      <div className="mx-auto w-full max-w-[30rem]">
                        {state.detection ? (
                          <motion.div
                            initial={{ opacity: 0, scale: 0.96 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ duration: 0.3 }}
                            className="border border-[#d9b36a]/40 bg-[#263041] p-5"
                          >
                            <p className="font-mono text-[10px] tracking-[0.24em] uppercase text-[#d9b36a]">检测信号</p>
                            <p className="mt-2 font-serif text-[19px] font-bold text-[#e8eee9]">{state.detection.title}</p>
                            <p className="mt-2 text-[13px] leading-relaxed text-[#a7b4bd]">{state.detection.detail}</p>
                          </motion.div>
                        ) : (
                          <div className="skeleton h-32 !bg-[#263041]" />
                        )}
                      </div>
                    )}

                    {/* 幕 3:六个岗位接力（卡片化，非技术观众也能看懂谁在干什么） */}
                    {state.sceneIdx === 2 && <AgentCards stages={state.stages} />}

                    {/* 幕 4:思维链打字机（签名时刻①）——放大版 + 证据注脚 */}
                    {state.sceneIdx === 3 && (
                      <div className="mx-auto w-full max-w-[54rem]">
                        <div className="mb-4 flex items-center justify-between border-b border-[#2a323c] pb-3">
                          <p className="font-mono text-[10px] tracking-[0.24em] uppercase text-[#d9b36a]">
                            证据链 · 逐步判断
                          </p>
                          <p className="font-mono text-[10px] tabular-nums text-[#6e7a88]">
                            已出现 {state.steps.length} 步
                          </p>
                        </div>
                        <ThoughtTypewriter steps={state.steps} paused={state.paused} large className="w-full" />
                        <div className="mt-5 flex flex-wrap gap-2 border-t border-[#2a323c] pt-4">
                          {[
                            '证据 3 条 · 均可回查',
                            '情报 / 资产 / 知识 三源交叉',
                            'CAD 穿透验证 2/2',
                            '综合置信 0.91',
                          ].map((chip) => (
                            <span
                              key={chip}
                              className="border border-[#d9b36a]/30 bg-[#d9b36a]/[0.06] px-2.5 py-1 font-mono text-[10px] tracking-[0.08em] text-[#d9c08a]"
                            >
                              {chip}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* 幕 5:处置 */}
                    {state.sceneIdx === 4 && (
                      <div className="mx-auto w-full max-w-[30rem]">
                        {state.response ? (
                          <motion.div
                            initial={{ opacity: 0, y: 12 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.32 }}
                            className="border border-[#5da583]/40 bg-[#263041] p-5"
                          >
                            <p className="font-mono text-[10px] tracking-[0.24em] uppercase text-[#5da583]">响应引擎</p>
                            <p className="mt-2 font-serif text-[17px] font-bold text-[#e8eee9]">{state.response.summary}</p>
                            <p className="mt-2 font-mono text-[11px] text-[#6e7a88]">
                              {state.response.blocked ? '动作已执行 · 可回滚' : '等待人工审批 · 工单已建立'}
                            </p>
                            <div className="mt-4 grid grid-cols-3 gap-2 border-t border-[#5da583]/20 pt-3">
                              {[
                                ['策略', '高危 → 审批'],
                                ['动作', state.response.blocked ? '阻断出站' : '转人工'],
                                ['回滚', state.response.blocked ? '可撤销' : '工单跟踪'],
                              ].map(([k, v]) => (
                                <div key={k}>
                                  <p className="font-mono text-[10px] tracking-[0.16em] uppercase text-[#6e7a88]">{k}</p>
                                  <p className="mt-1 font-serif text-[14px] text-[#c9d6cf]">{v}</p>
                                </div>
                              ))}
                            </div>
                          </motion.div>
                        ) : (
                          <div className="skeleton h-28 !bg-[#263041]" />
                        )}
                      </div>
                    )}

                    {/* 幕 6:结案摘要 + 落印（印章为全屏 overlay） */}
                    {state.sceneIdx === 5 && !state.finished && (
                      <div className="mx-auto w-full max-w-[36rem] border border-[#2a323c] bg-[#14222f] p-6">
                        <p className="font-mono text-[10px] tracking-[0.24em] uppercase text-[#d9b36a]">结案摘要</p>
                        <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 text-[13px]">
                          {[
                            ['事件', state.eventId ? `#${state.eventId} · C2_BEACON` : '#— · C2_BEACON'],
                            ['判定', state.response?.blocked ? '威胁 · 已阻断' : '威胁 · 转人工'],
                            ['证据', `${state.steps.length} 步思维链 · 3 条可回查证据`],
                            ['动作', state.response?.blocked ? '阻断出站 · 可回滚' : '生成处置工单'],
                          ].map(([k, v]) => (
                            <div key={k} className="flex flex-col gap-1">
                              <dt className="font-mono text-[10px] tracking-[0.18em] uppercase text-[#6e7a88]">{k}</dt>
                              <dd className="font-serif text-[15px] text-[#e8eee9]">{v}</dd>
                            </div>
                          ))}
                        </dl>
                        <div className="mt-5 border-t border-[#2a323c] pt-4">
                          <p className="text-[12px] leading-relaxed text-[#8fa0ad]">
                            处置报告、审批留痕与回滚凭证正在归档 —— 印章即将落定。
                          </p>
                          <p className="mt-2 font-mono text-[10px] tracking-[0.14em] text-[#c9a574]">
                            演练口径 · 数据来自本场剧本，不冒充生产流水线
                          </p>
                        </div>
                      </div>
                    )}
                    {state.finished && state.seal && (
                      <div className="text-center">
                        <p className="font-serif text-[17px] text-[#c9d6cf]">{state.seal.sub}</p>
                        <div className="mt-6 flex items-center justify-center gap-4">
                          <button
                            onClick={() => {
                              reset()
                              void start()
                            }}
                            className="border border-[#d9b36a] px-6 py-2.5 font-serif text-[14px] font-bold text-[#f1e8d6] hover:bg-[#263041] transition-colors"
                          >
                            ↺ 重演
                          </button>
                          <button
                            onClick={gotoScreen}
                            className="border border-[#33475a] px-6 py-2.5 font-mono text-[11px] tracking-[0.22em] uppercase text-[#a7b4bd] hover:border-[#d9b36a]/60 hover:text-[#d9b36a] transition-colors"
                          >
                            移交作战大屏
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </motion.div>
              </AnimatePresence>
            </main>

            {/* 右:事件档案 + 模式说明（舞台模式隐藏，避免技术说明抢占画面） */}
            {!stageMode && (
              <aside className="flex flex-col gap-4 overflow-y-auto">
                <div className="border border-[#2a323c] bg-[#14222f] p-5">
                  <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-[#6e7a88]">事件档案</p>
                  <dl className="mt-3 space-y-2 text-[12px]">
                    {[
                      ['事件', state.eventId ? `#${state.eventId} · C2_BEACON` : '—'],
                      ['源', '192.168.1.105(内网)'],
                      ['目的', '23.129.64.33(外部)'],
                      ['严重度', 'critical'],
                    ].map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-3">
                        <dt className="font-mono text-[10px] tracking-[0.18em] uppercase text-[#6e7a88]">{k}</dt>
                        <dd className="font-mono tabular-nums text-[#c9d6cf]">{v}</dd>
                      </div>
                    ))}
                  </dl>
                </div>

                <details className="border border-[#2a323c] bg-[#14222f] p-5">
                  <summary className="cursor-pointer font-mono text-[10px] tracking-[0.26em] uppercase text-[#6e7a88] [&::-webkit-details-marker]:hidden">
                    演示口径说明（点开）
                  </summary>
                  <ul className="mt-3 space-y-2.5 text-[12px] leading-relaxed text-[#a7b4bd]">
                    <li><b className="text-[#7fd4a8]">实时</b> — 事件经真实流水线,SSE 驱动画面</li>
                    <li><b className="text-[#e5b96b]">降级</b> — 某幕事件超时,合成信号推进(徽章常驻,不伪装)</li>
                    <li><b className="text-[#d9bc8b]">演练</b> — 纯前端时间轴,无后端,供录屏使用</li>
                  </ul>
                  <p className="mt-3 border-t border-[#2a323c] pt-3 text-[11px] leading-relaxed text-[#6e7a88]">
                    流水线:Decomposer → Tool Builder → Executor → Reviewer → CAD → Response;
                    CAD 为独立监督位,不参与内容生产。
                  </p>
                </details>
              </aside>
            )}

            {/* 结案印章 overlay(签名时刻②;终幕操作区住在 overlay 内) */}
            <AnimatePresence>
              {state.finished && state.seal && (
                <SealSlam
                  text={state.seal.text}
                  sub={state.seal.sub}
                  degradedNote={state.degradedNote ?? (state.mode === 'rehearsal' ? '演练口径 · 非真实流水线' : null)}
                  onDone={beginHandoff}
                  footer={
                    <div className="flex flex-col items-center gap-2.5">
                      <div className="flex items-center gap-3">
                        <button
                          onClick={gotoScreen}
                          className="border border-[#d9b36a]/60 bg-[#0f1216] px-6 py-2.5 font-serif text-[14px] font-bold tracking-[0.06em] text-[#f1e8d6] hover:bg-[#263041] transition-colors"
                        >
                          移交作战大屏 →
                        </button>
                        <button
                          onClick={() => handoffCtlRef.current?.stop()}
                          className="border border-[#33475a] px-4 py-2.5 font-mono text-[10px] tracking-[0.22em] uppercase text-[#6e7a88] hover:border-[#d9b36a]/50 hover:text-[#d9b36a] transition-colors"
                        >
                          留在结案
                        </button>
                      </div>
                      <p className="font-mono text-[11px] tracking-[0.14em] text-[#6e7a88]">
                        {handoffIn !== null
                          ? `${handoffIn}s 后自动移交 · 同一事件将在大屏思维链继续`
                          : '自动移交已取消 · 可随时手动移交'}
                      </p>
                    </div>
                  }
                />
              )}
            </AnimatePresence>
          </div>
        )}

        {/* ── 底部进度（舞台模式隐藏：左栏已承担幕次导航，避免重复）── */}
        {!stageMode && (
          <footer className="flex h-9 shrink-0 items-stretch border-t border-[#2a323c]">
          {SCENES.map((scene, i) => {
            const status = state.sceneStatus[scene.id]
            return (
              <div key={scene.id} className="relative flex-1 border-r border-[#2a323c] last:border-r-0">
                <div
                  className={`absolute inset-0 transition-colors duration-500 ${
                    status === 'done'
                      ? 'bg-[#5da583]/12'
                      : status === 'playing'
                        ? 'bg-[#d9b36a]/14'
                        : status === 'skipped'
                          ? 'bg-[#33475a]/30'
                          : ''
                  }`}
                  aria-hidden
                />
                <p className="relative flex h-full items-center justify-center font-mono text-[10px] tracking-[0.24em] uppercase text-[#6e7a88]">
                  {String(i + 1).padStart(2, '0')} {scene.title}
                </p>
              </div>
            )
          })}
          </footer>
        )}
      </div>
    </PageTransition>
  )
}
