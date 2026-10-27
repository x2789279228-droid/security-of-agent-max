import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { useDemoDirector } from '../hooks/useDemoDirector'
import { ThoughtTypewriter } from '../components/demo/ThoughtTypewriter'
import { SealSlam } from '../components/demo/SealSlam'
import { DemoSupplyCard } from '../components/demo/DemoSupplyCard'
import { SCENES, MODE_BADGE } from '../lib/demoScript'
import { STAGE_LABELS, AGENT_RELAY_STAGES, type AgentRelayStage } from '../lib/agentPipeline'
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
                ? 'border-[#c9a574]/40 bg-[#182838]'
                : status === 'done' || status === 'skipped'
                  ? 'border-transparent opacity-70'
                  : 'border-transparent opacity-40'
            }`}
          >
            {active && <span className="absolute left-0 top-0 bottom-0 w-[2px] bg-[#c9a574]" aria-hidden />}
            <p className="flex items-baseline gap-2.5">
              <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#c9a574]">{scene.num}</span>
              <span className="font-serif text-[16px] font-bold text-[#dfe7e3]">{scene.title}</span>
              <span className="ml-auto font-mono text-[11px] text-[#78889a]">
                {status === 'done' ? '✓' : status === 'skipped' ? '—' : active ? '▶' : ''}
              </span>
            </p>
            <p className="mt-1 text-[12px] leading-snug text-[#78889a]">{scene.caption}</p>
          </div>
        )
      })}
    </nav>
  )
}

// ── 中栏:接力可视化(导演状态驱动,合成信号同样点亮)──
function RelayStage({ stages }: { stages: ReturnType<typeof useDemoDirector>['state']['stages'] }) {
  const activeIdx = AGENT_RELAY_STAGES.findIndex((s) => stages[s].status === 'running')
  const frac = activeIdx >= 0 ? (activeIdx + 0.5) / AGENT_RELAY_STAGES.length : 0
  return (
    <div className="relative">
      <div className="absolute left-0 right-0 top-[22px] h-px bg-[#24384a]" aria-hidden />
      <motion.div
        className="absolute top-[19px] h-[7px] w-[7px] rounded-full bg-[#c9a574]"
        style={{ boxShadow: '0 0 12px rgba(201,165,116,0.8)' }}
        animate={{ left: `calc(${frac * 100}% - 3px)` }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        aria-hidden
      />
      <div className="relative grid grid-cols-6">
        {AGENT_RELAY_STAGES.map((stage: AgentRelayStage) => {
          const cell = stages[stage]
          const color =
            cell.status === 'success'
              ? '#5da583'
              : cell.status === 'running'
                ? '#c9a574'
                : cell.status === 'error' || cell.status === 'timeout'
                  ? '#e05a4e'
                  : '#33475a'
          return (
            <div key={stage} className="flex flex-col items-center gap-2.5">
              <span
                className={`relative mt-[14px] flex h-4 w-4 items-center justify-center rounded-full border-2 transition-colors ${
                  cell.status === 'running' ? 'animate-pulse' : ''
                }`}
                style={{ borderColor: color, background: cell.status === 'idle' ? 'transparent' : color }}
              />
              <span
                className="text-center font-mono text-[10px] leading-tight tracking-[0.14em]"
                style={{ color: cell.status === 'idle' ? '#78889a' : '#a7b4bd' }}
              >
                {STAGE_LABELS[stage] ?? stage}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default function Demo() {
  const navigate = useNavigate()
  const { state, start, startRehearsal, togglePause, skipScene, reset } = useDemoDirector()

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
      <div className="flex min-h-screen flex-col bg-[#0e1a26] font-sans text-[#dfe7e3]">
        {/* ── 顶栏 ── */}
        <header className="flex h-14 shrink-0 items-center gap-5 border-b border-[#24384a] px-6">
          <span className="font-serif text-[18px] font-black tracking-[-0.02em]">守望</span>
          <span className="font-mono text-[10px] tracking-[0.26em] uppercase text-[#c9a574]">
            攻击剧本 · 沉浸演示
          </span>
          <span className={`px-2 py-0.5 font-mono text-[10px] tracking-[0.2em] uppercase ${badge.cls}`}>
            {badge.label}
          </span>
          {state.running && (
            <span className="font-mono text-[11px] tabular-nums text-[#78889a]">{fmtElapsed(state.elapsedMs)}</span>
          )}
          {state.degradedNote && (
            <span className="hidden truncate font-mono text-[10px] text-[#d9b06b] md:inline">{state.degradedNote}</span>
          )}
          <div className="ml-auto flex items-center gap-2">
            {state.running && !state.finished && (
              <>
                <button
                  onClick={togglePause}
                  className="border border-[#24384a] px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#a7b4bd] hover:border-[#c9a574]/50 hover:text-[#dfe7e3] transition-colors"
                >
                  {state.paused ? '▶ 继续' : '⏸ 暂停'}
                </button>
                <button
                  onClick={skipScene}
                  disabled={state.paused}
                  className="border border-[#24384a] px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#a7b4bd] hover:border-[#c9a574]/50 hover:text-[#dfe7e3] transition-colors disabled:opacity-40"
                >
                  ⏭ 跳过本幕
                </button>
              </>
            )}
            {(state.running || state.finished) && (
              <button
                onClick={reset}
                className="border border-[#24384a] px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#a7b4bd] hover:border-[#c9a574]/50 hover:text-[#dfe7e3] transition-colors"
              >
                ↺ 重演
              </button>
            )}
            <button
              onClick={() => navigate(ROUTES.MONITOR)}
              className="border border-[#c9a574]/40 px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] uppercase text-[#c9a574] hover:bg-[#182838] transition-colors"
            >
              退出
            </button>
          </div>
        </header>

        {/* ── 开场(未开演)── */}
        {notStarted && (
          <div className="flex flex-1 flex-col items-center justify-center px-8 text-center">
            <p className="font-mono text-[11px] tracking-[0.4em] uppercase text-[#c9a574]">Demo Script · 六幕</p>
            <h1 className="mt-4 font-serif text-[52px] font-black leading-tight tracking-[-0.03em]">
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
                className="border border-[#c9a574] bg-[#0e1a26] px-8 py-3.5 font-serif text-[16px] font-black tracking-[0.06em] text-[#f1e8d6] hover:bg-[#182838] transition-colors"
              >
                ▶ 实时开演
              </button>
              <button
                onClick={startRehearsal}
                className="border border-[#33475a] px-8 py-3.5 font-mono text-[11px] tracking-[0.24em] uppercase text-[#a7b4bd] hover:border-[#c9a574]/60 hover:text-[#c9a574] transition-colors"
              >
                演练模式(离线)
              </button>
            </div>
            {state.error && (
              <p className="mt-6 max-w-[32rem] border border-[#d4a054]/40 bg-[#d4a054]/10 px-4 py-2.5 text-[13px] text-[#d9b06b]">
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
          <div className="relative grid flex-1 grid-cols-[280px_1fr_300px] gap-6 overflow-hidden p-6">
            {/* 左:幕次目录 */}
            <aside className="overflow-y-auto">
              <SceneRail state={state} />
            </aside>

            {/* 中:当前幕内容 */}
            <main className="relative flex min-w-0 flex-col overflow-hidden border border-[#24384a] bg-[#14222f] p-7">
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
                      <p className="font-mono text-[10px] tracking-[0.3em] uppercase text-[#c9a574]">
                        {currentScene.num} · {currentScene.title}
                      </p>
                      <p className="mt-1 font-serif text-[22px] font-black text-[#dfe7e3]">{currentScene.caption}</p>
                    </>
                  )}

                  <div className="mt-7 flex flex-1 flex-col justify-center">
                    {/* 幕 1:事件卡飞入 */}
                    {state.sceneIdx === 0 && (
                      <motion.div
                        initial={{ opacity: 0, x: -70 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
                        className="mx-auto w-full max-w-[30rem] border border-[#e05a4e]/50 bg-[#182838] p-5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="border border-[#e05a4e]/50 bg-[#e05a4e]/10 px-2 py-0.5 font-mono text-[10px] tracking-[0.2em] uppercase text-[#e8887c]">
                            critical
                          </span>
                          <span className="font-mono text-[10px] tracking-[0.18em] uppercase text-[#78889a]">
                            {state.eventId ? `事件 #${state.eventId}` : '注入中…'}
                          </span>
                        </div>
                        <p className="mt-3 font-mono text-[15px] font-bold tracking-[0.06em] text-[#e8eee9]">C2_BEACON</p>
                        <p className="mt-2 font-mono text-[13px] text-[#a7b4bd]">
                          {state.event?.src ?? '192.168.1.105'}
                          <span className="mx-2 text-[#c9a574]">──→</span>
                          {state.event?.dst ?? '23.129.64.33'}
                        </p>
                        <p className="mt-2 text-[13px] leading-relaxed text-[#78889a]">
                          {state.event?.message ?? '内部主机疑似与 C2 服务器周期性通信'}
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
                            className="border border-[#c9a574]/40 bg-[#182838] p-5"
                          >
                            <p className="font-mono text-[10px] tracking-[0.24em] uppercase text-[#c9a574]">检测信号</p>
                            <p className="mt-2 font-serif text-[19px] font-bold text-[#e8eee9]">{state.detection.title}</p>
                            <p className="mt-2 text-[13px] leading-relaxed text-[#a7b4bd]">{state.detection.detail}</p>
                          </motion.div>
                        ) : (
                          <div className="skeleton h-32 !bg-[#182838]" />
                        )}
                      </div>
                    )}

                    {/* 幕 3:接力管线 */}
                    {state.sceneIdx === 2 && <RelayStage stages={state.stages} />}

                    {/* 幕 4:思维链打字机(签名时刻①) */}
                    {state.sceneIdx === 3 && (
                      <ThoughtTypewriter steps={state.steps} paused={state.paused} className="mx-auto w-full max-w-[38rem]" />
                    )}

                    {/* 幕 5:处置 */}
                    {state.sceneIdx === 4 && (
                      <div className="mx-auto w-full max-w-[30rem]">
                        {state.response ? (
                          <motion.div
                            initial={{ opacity: 0, y: 12 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.32 }}
                            className="border border-[#5da583]/40 bg-[#182838] p-5"
                          >
                            <p className="font-mono text-[10px] tracking-[0.24em] uppercase text-[#5da583]">响应引擎</p>
                            <p className="mt-2 font-serif text-[17px] font-bold text-[#e8eee9]">{state.response.summary}</p>
                            <p className="mt-2 font-mono text-[11px] text-[#78889a]">
                              {state.response.blocked ? '动作已执行 · 可回滚' : '等待人工审批 · 工单已建立'}
                            </p>
                          </motion.div>
                        ) : (
                          <div className="skeleton h-28 !bg-[#182838]" />
                        )}
                      </div>
                    )}

                    {/* 幕 6:等待落印(印章为全屏 overlay) */}
                    {state.sceneIdx === 5 && !state.finished && (
                      <p className="text-center font-serif text-[15px] italic text-[#78889a]">案卷归档中……</p>
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
                            className="border border-[#c9a574] px-6 py-2.5 font-serif text-[14px] font-bold text-[#f1e8d6] hover:bg-[#182838] transition-colors"
                          >
                            ↺ 重演
                          </button>
                          <button
                            onClick={gotoScreen}
                            className="border border-[#33475a] px-6 py-2.5 font-mono text-[11px] tracking-[0.22em] uppercase text-[#a7b4bd] hover:border-[#c9a574]/60 hover:text-[#c9a574] transition-colors"
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

            {/* 右:事件档案 + 模式说明 */}
            <aside className="flex flex-col gap-4 overflow-y-auto">
              <div className="border border-[#24384a] bg-[#14222f] p-5">
                <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-[#78889a]">事件档案</p>
                <dl className="mt-3 space-y-2 text-[12px]">
                  {[
                    ['事件', state.eventId ? `#${state.eventId} · C2_BEACON` : '—'],
                    ['源', '192.168.1.105(内网)'],
                    ['目的', '23.129.64.33(外部)'],
                    ['严重度', 'critical'],
                  ].map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-3">
                      <dt className="font-mono text-[10px] tracking-[0.18em] uppercase text-[#78889a]">{k}</dt>
                      <dd className="font-mono tabular-nums text-[#c9d6cf]">{v}</dd>
                    </div>
                  ))}
                </dl>
              </div>

              <div className="border border-[#24384a] bg-[#14222f] p-5">
                <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-[#78889a]">数据源口径</p>
                <ul className="mt-3 space-y-2.5 text-[12px] leading-relaxed text-[#a7b4bd]">
                  <li><b className="text-[#7fd4a8]">实时</b> — 事件经真实流水线,SSE 驱动画面</li>
                  <li><b className="text-[#e5b96b]">降级</b> — 某幕事件超时,合成信号推进(徽章常驻,不伪装)</li>
                  <li><b className="text-[#d9bc8b]">演练</b> — 纯前端时间轴,无后端,供录屏</li>
                </ul>
                <p className="mt-3 border-t border-[#24384a] pt-3 text-[11px] leading-relaxed text-[#78889a]">
                  流水线:Decomposer → Tool Builder → Executor → Reviewer → CAD → Response;
                  CAD 为独立监督位,不参与内容生产。
                </p>
              </div>
            </aside>

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
                          className="border border-[#c9a574]/60 bg-[#0e1a26] px-6 py-2.5 font-serif text-[14px] font-bold tracking-[0.06em] text-[#f1e8d6] hover:bg-[#182838] transition-colors"
                        >
                          移交作战大屏 →
                        </button>
                        <button
                          onClick={() => handoffCtlRef.current?.stop()}
                          className="border border-[#33475a] px-4 py-2.5 font-mono text-[10px] tracking-[0.22em] uppercase text-[#78889a] hover:border-[#c9a574]/50 hover:text-[#c9a574] transition-colors"
                        >
                          留在结案
                        </button>
                      </div>
                      <p className="font-mono text-[11px] tracking-[0.14em] text-[#78889a]">
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

        {/* ── 底部进度 ── */}
        <footer className="flex h-9 shrink-0 items-stretch border-t border-[#24384a]">
          {SCENES.map((scene, i) => {
            const status = state.sceneStatus[scene.id]
            return (
              <div key={scene.id} className="relative flex-1 border-r border-[#24384a] last:border-r-0">
                <div
                  className={`absolute inset-0 transition-colors duration-500 ${
                    status === 'done'
                      ? 'bg-[#5da583]/12'
                      : status === 'playing'
                        ? 'bg-[#c9a574]/14'
                        : status === 'skipped'
                          ? 'bg-[#33475a]/30'
                          : ''
                  }`}
                  aria-hidden
                />
                <p className="relative flex h-full items-center justify-center font-mono text-[10px] tracking-[0.24em] uppercase text-[#78889a]">
                  {String(i + 1).padStart(2, '0')} {scene.title}
                </p>
              </div>
            )
          })}
        </footer>
      </div>
    </PageTransition>
  )
}
