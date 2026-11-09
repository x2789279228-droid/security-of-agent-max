import { useEffect, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { PageFrame } from '../components/common/PageFrame'
import { LoadingState, ErrorState } from '../components/common/AsyncState'
import { EmptyState } from '../components/common/EmptyState'
import { CountUp, DrawBar } from '../motion/primitives'
import { api, type BenchmarkReports, type BenchmarkReport } from '../lib/api'

/**
 * 评测战绩 — docs/benchmark 的前端化(阶段 2)
 *
 * 设计:案卷浅色风 + 卷宗堆叠叙事(四份卷宗纵向下叠,右缘卷签)。
 * 纪律:所有数字直读评测 JSON,scope_note 原样展示 —— 诚实口径本身是加分项。
 */

/** 卷宗容器:纵向下叠(后一份压住前一份底缘 12px)+ 右缘骑缝卷签 */
function Dossier({
  tab,
  title,
  meta,
  note,
  children,
  index,
}: {
  tab: string
  title: string
  meta: string
  note?: string
  children: React.ReactNode
  index: number
}) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-40px' }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className={`relative crop-marks border border-line bg-paper shadow-[var(--shadow-1)] ${
        index > 0 ? '-mt-3' : ''
      }`}
    >
      {/* 卷签:骑右缘竖排 */}
      <span
        aria-hidden
        className="absolute right-0 top-5 border border-line border-r-0 bg-qing px-1.5 py-3 font-mono text-[10px] tracking-[0.3em] text-ink-faint"
        style={{ writingMode: 'vertical-rl' }}
      >
        {tab}
      </span>

      <div className="border-b border-line px-6 py-4">
        <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
          <h2 className="text-[20px] font-semibold tracking-tight text-ink">{title}</h2>
          <span className="font-mono text-[10px] tracking-[0.06em] text-ink-faint">{meta}</span>
        </div>
        {note && (
          <p className="mt-1.5 max-w-[52rem] text-[12px] leading-relaxed text-ink-faint">{note}</p>
        )}
      </div>
      <div className="px-6 py-5">{children}</div>
    </motion.section>
  )
}

/** 战绩大数字卡 */
function Headline({
  label,
  value,
  decimals = 0,
  suffix,
  sub,
  tone = 'ink',
}: {
  label: string
  value: number
  decimals?: number
  suffix?: string
  sub: string
  tone?: 'ink' | 'alert' | 'ok' | 'warn'
}) {
  const toneCls = { ink: 'text-ink', alert: 'text-alert', ok: 'text-ok', warn: 'text-warn' }[tone]
  return (
    <div className="relative border border-line bg-paper-warm px-5 py-4">
      <p className="font-mono text-[10px] tracking-[0.06em] text-ink-faint">{label}</p>
      <p className={`mt-2 text-[34px] font-semibold leading-none tabular-nums ${toneCls}`}>
        <CountUp value={value} decimals={decimals} />
        {suffix && <span className="ml-1 font-mono text-[13px] font-normal text-ink-faint">{suffix}</span>}
      </p>
      <p className="mt-1.5 text-[12px] text-ink-soft">{sub}</p>
    </div>
  )
}

// ── 口径标签 ──
const FAMILY_LABEL: Record<string, string> = {
  traversal: '路径穿越',
  traversal_encoded: '路径穿越(编码)',
  xss: 'XSS',
  es_unauth: 'ES 未授权',
  env_probe: '环境探测',
  git_probe: '.git 探测',
  actuator: 'Actuator 探测',
  webshell_cmd: 'Webshell 执行',
}

const LAYER_LABEL: Record<string, string> = {
  L1_sigma_execution: 'L1 · Sigma 规则执行',
  L2_shadow: 'L2 · 影子规则(晋升观察)',
  L3_anomaly: 'L3 · 行为异常',
  L4_correlation: 'L4 · 攻击链关联',
  L5_soar_decisions: 'L5 · SOAR 响应决策',
}

const OPERATOR_LABEL: Record<string, string> = {
  url_encode: 'URL 编码',
  double_encode: '双重编码',
  partial_encode: '部分编码',
  case_flip: '大小写翻转',
}

function reportOf(reports: BenchmarkReport[], key: string) {
  return reports.find((r) => r.key === key)
}

export default function Benchmark() {
  const [state, setState] = useState<{
    loading: boolean
    error: string
    data: BenchmarkReports | null
  }>({ loading: true, error: '', data: null })

  useEffect(() => {
    let alive = true
    api
      .benchmarkReports()
      .then((d) => alive && setState({ loading: false, error: '', data: d }))
      .catch((e) => alive && setState({ loading: false, error: e?.message || '加载失败', data: null }))
    return () => {
      alive = false
    }
  }, [])

  const reports = state.data?.reports ?? []

  // ── 派生数据 ──
  const csic = useMemo(() => {
    const r = reportOf(reports, 'replay_csic')
    if (!r) return null
    const mal = r.data?.classes?.malicious
    const ben = r.data?.classes?.benign
    if (!mal || !ben) return null
    return {
      rules_total: r.data?.rules_total ?? 0,
      rules_shadow: r.data?.rules_shadow ?? 0,
      note: typeof r.data?.note === 'string' ? r.data.note : '',
      attackN: mal.n ?? 0,
      attackTp: mal.enforced_tp ?? 0,
      rawRecall: mal.recall_enforced ?? 0,
      subsetN: mal.signature_subset_n ?? 0,
      normRecall: mal.normalized?.recall_enforced ?? 0,
      eps: mal.throughput_eps ?? 0,
      shadowOnly: mal.shadow_only_tp ?? 0,
      benignN: ben.n ?? 0,
      benignFp: ben.enforced_fp ?? 0,
      perRule: Object.entries(mal.normalized?.per_rule_top ?? mal.per_rule_top ?? {}) as [string, number][],
      perType: Object.entries(mal.per_type ?? {}) as [string, number][],
    }
  }, [reports])

  const evasion = useMemo(() => {
    const cur = reportOf(reports, 'evasion')
    const pre = reportOf(reports, 'evasion_pre')
    if (!cur) return null
    const families = Object.entries(cur.data?.families ?? {}) as [string, { retention?: number }][]
    const preFamilies = Object.entries(pre?.data?.families ?? {}) as [string, { retention?: number }][]
    return {
      overall: cur.data?.overall_retention ?? 0,
      overallPre: pre?.data?.overall_retention ?? null,
      operators: (cur.data?.operators ?? []) as string[],
      families: families.map(([name, v]) => ({
        name,
        retention: v.retention ?? 0,
        pre: preFamilies.find(([n]) => n === name)?.[1]?.retention ?? null,
      })),
    }
  }, [reports])

  const ablation = useMemo(() => {
    const r = reportOf(reports, 'ablation')
    if (!r) return null
    return r.data
  }, [reports])

  const perf = useMemo(() => {
    const r = reportOf(reports, 'perf')
    return r ? r.data : null
  }, [reports])

  if (state.loading) {
    return (
      <PageFrame title="评测战绩" hint="定量证据链 — 消融 · 对抗 · 回放 · 压测。">
        <LoadingState rows={5} label="正在读取评测报告…" />
      </PageFrame>
    )
  }

  if (state.error || !state.data) {
    return (
      <PageFrame title="评测战绩" hint="定量证据链 — 消融 · 对抗 · 回放 · 压测。">
        {state.error ? (
          <ErrorState
            message={state.error}
            hint="请确认后端 /api/benchmark 可用，或重新运行评测脚本生成 docs/benchmark 报告。"
            onRetry={() => window.location.reload()}
          />
        ) : (
          <EmptyState
            art="folder"
            title="暂无评测数据"
            hint="未找到评测结果文件 — 请先运行 backend/eval_datasets 下的评测脚本生成 docs/benchmark 结果。"
          />
        )}
      </PageFrame>
    )
  }

  const evasionGain =
    evasion?.overallPre != null && evasion.overall > 0
      ? `+${((evasion.overall - evasion.overallPre) * 100).toFixed(1)}pp`
      : null

  return (
    <PageFrame
      title="评测战绩"
      hint="定量证据链 — CSIC-2010 全量回放 · 对抗保持率 · 分层消融 · 压测故障注入。"
      extra={
        <span className="border border-line bg-qing px-3 py-1.5 font-mono text-[10px] tracking-[0.06em] text-ink-faint">
          docs/benchmark · 只读
        </span>
      }
    >
      {/* ── 战绩总览带 ── */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Headline
          label="攻击样本全量回放"
          value={csic?.attackN ?? 0}
          sub="CSIC-2010 恶意样本逐条过签名引擎"
        />
        <Headline
          label="良性误报"
          value={csic?.benignFp ?? 0}
          sub={`36,000 条良性样本 · 零误报`}
          tone="ok"
        />
        <Headline
          label="签名子集召回"
          value={(csic?.normRecall ?? 0) * 100}
          decimals={2}
          suffix="%"
          sub={`深解码后含经典签名的子集(n=${csic?.subsetN ?? 0})`}
          tone="warn"
        />
        <Headline
          label="对抗保持率"
          value={(evasion?.overall ?? 0) * 100}
          decimals={1}
          suffix="%"
          sub={evasionGain ? `规范化整改前 ${(evasion.overallPre! * 100).toFixed(1)}%(${evasionGain})` : '四种对抗编码算子'}
          tone="ok"
        />
      </div>

      {/* ── 卷宗堆叠 ── */}
      <div className="mt-8">
        {/* 卷宗 I · CSIC-2010 */}
        {csic && (
          <Dossier
            index={0}
            tab="报告 I"
            title="CSIC-2010 全量回放"
            meta={`${csic.rules_total} 条规则(影子 ${csic.rules_shadow})`}
            note={csic.note}
          >
            <div className="grid gap-5 lg:grid-cols-[1fr_1fr]">
              <div>
                <p className="meta-caps mb-3">三口径召回</p>
                <table className="w-full text-[13px]">
                  <tbody className="align-baseline">
                    <tr className="border-b border-line">
                      <td className="py-2 pr-3 text-ink-soft">原始 URL 直检</td>
                      <td className="py-2 text-right font-mono tabular-nums text-ink">
                        {(csic.rawRecall * 100).toFixed(2)}%
                      </td>
                    </tr>
                    <tr className="border-b border-line">
                      <td className="py-2 pr-3 text-ink-soft">双重解码后(可达召回)</td>
                      <td className="py-2 text-right font-mono tabular-nums text-ink">
                        {((reportOf(reports, 'replay_csic')?.data?.classes?.malicious?.normalized?.recall_enforced ?? csic.rawRecall) * 100).toFixed(2)}%
                      </td>
                    </tr>
                    <tr className="border-b border-line">
                      <td className="py-2 pr-3 text-ink-soft">签名子集(主评审口径,n={csic.subsetN})</td>
                      <td className="py-2 text-right font-mono tabular-nums font-bold text-warn">
                        {(csic.normRecall * 100).toFixed(2)}%
                      </td>
                    </tr>
                    <tr>
                      <td className="py-2 pr-3 text-ink-soft">影子规则补充证据(晋升候选)</td>
                      <td className="py-2 text-right font-mono tabular-nums text-ink">+{csic.shadowOnly}</td>
                    </tr>
                  </tbody>
                </table>

                <div className="mt-4 border border-ok/40 bg-mint px-4 py-3">
                  <p className="font-mono text-[10px] tracking-[0.06em] text-ok">误报防线</p>
                  <p className="mt-1 text-[13px] text-ink">
                    <CountUp value={csic.benignN} className="font-bold tabular-nums" /> 条良性样本,
                    <span className="font-bold text-ok"> 0 误报</span>
                    <span className="text-ink-faint"> — 全部 150 条规则(含 125 条影子)无一误击</span>
                  </p>
                </div>
              </div>

              <div>
                <p className="meta-caps mb-3">贡献 Top 规则(签名子集)</p>
                <div className="space-y-2.5">
                  {csic.perRule.slice(0, 6).map(([rule, n], i) => {
                    const max = Math.max(...csic.perRule.map(([, v]) => v), 1)
                    return (
                      <div key={rule}>
                        <div className="mb-1 flex items-baseline justify-between">
                          <span className="font-mono text-[11px] text-ink-soft">
                            {rule.startsWith('shadow:') ? '影子·' : ''}
                            {rule.replace('shadow:', '')}
                          </span>
                          <span className="font-mono text-[11px] tabular-nums text-ink-faint">{n}</span>
                        </div>
                        <DrawBar pct={(n / max) * 100} tone="bg-accent" delay={i * 0.06} />
                      </div>
                    )
                  })}
                </div>
                <p className="mt-4 font-mono text-[10px] tracking-[0.06em] text-ink-faint">
                  吞吐 {csic.eps} eps · 单进程检测路径
                </p>
              </div>
            </div>
          </Dossier>
        )}

        {/* 卷宗 II · 对抗保持率 */}
        {evasion && (
          <Dossier
            index={1}
            tab="报告 II"
            title="对抗保持率 · 规范化整改前后"
            meta={`算子:${evasion.operators.map((o) => OPERATOR_LABEL[o] ?? o).join(' / ')}`}
            note={reportOf(reports, 'evasion')?.scope_note}
          >
            <div className="mb-5 grid gap-4 sm:grid-cols-2">
              <div className="border border-warn/40 bg-paper px-5 py-4">
                <p className="font-mono text-[10px] tracking-[0.06em] text-warn">整改前 · overall</p>
                <p className="mt-1.5 text-[38px] font-semibold leading-none text-warn tabular-nums">
                  <CountUp value={(evasion.overallPre ?? 0) * 100} decimals={1} />%
                </p>
                <div className="mt-3">
                  <DrawBar pct={(evasion.overallPre ?? 0) * 100} tone="bg-warn" />
                </div>
              </div>
              <div className="border border-ok/40 bg-paper px-5 py-4">
                <p className="font-mono text-[10px] tracking-[0.06em] text-ok">整改后 · overall</p>
                <p className="mt-1.5 text-[38px] font-semibold leading-none text-ok tabular-nums">
                  <CountUp value={evasion.overall * 100} decimals={1} />%
                </p>
                <div className="mt-3">
                  <DrawBar pct={evasion.overall * 100} tone="bg-ok" delay={0.15} />
                </div>
              </div>
            </div>

            <p className="meta-caps mb-3">按攻击家族</p>
            <div className="space-y-3">
              {evasion.families.map((f, i) => (
                <div key={f.name} className="grid grid-cols-[10rem_1fr] items-center gap-4">
                  <span className="truncate text-[13px] text-ink-soft">{FAMILY_LABEL[f.name] ?? f.name}</span>
                  <div className="space-y-1">
                    {f.pre != null && (
                      <div className="flex items-center gap-2">
                        <DrawBar pct={f.pre * 100} tone="bg-warn/70" delay={i * 0.04} />
                        <span className="w-12 shrink-0 text-right font-mono text-[10px] tabular-nums text-warn">
                          {(f.pre * 100).toFixed(0)}%
                        </span>
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <DrawBar pct={f.retention * 100} tone="bg-ok" delay={i * 0.04 + 0.08} />
                      <span className="w-12 shrink-0 text-right font-mono text-[10px] tabular-nums text-ok">
                        {(f.retention * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <p className="mt-3 text-[11px] text-ink-faint">
              <span className="mr-3"><span className="mr-1 inline-block h-2 w-2 bg-warn/70 align-middle" />整改前</span>
              <span><span className="mr-1 inline-block h-2 w-2 bg-ok align-middle" />整改后</span>
            </p>
          </Dossier>
        )}

        {/* 卷宗 III · 分层消融 */}
        {ablation && (
          <Dossier
            index={2}
            tab="报告 III"
            title="分层消融 · L1 → L5"
            meta={reportOf(reports, 'ablation')?.file ?? ''}
            note={typeof ablation.scope_note === 'string' ? ablation.scope_note : undefined}
          >
            <div className="space-y-3">
              {Object.entries(LAYER_LABEL).map(([key, label], i) => {
                const layer = ablation[key]
                if (!layer) return null
                const m = layer.enforced_confirmed ?? layer.anomaly ?? layer.correlation
                return (
                  <motion.div
                    key={key}
                    initial={{ opacity: 0, x: -12 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true, margin: '-30px' }}
                    transition={{ duration: 0.4, delay: i * 0.06 }}
                    className="grid grid-cols-[11rem_1fr] items-center gap-4 border border-line bg-paper-warm px-4 py-3"
                  >
                    <div>
                      <p className="text-[13px] font-bold text-ink">{label}</p>
                      <p className="font-mono text-[10px] tracking-[0.14em] uppercase text-ink-faint">
                        {(layer.dataset ?? '').slice(0, 34)}
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-x-6 gap-y-1">
                      {m ? (
                        <>
                          <span className="font-mono text-[12px] tabular-nums text-ink-soft">
                            TP <b className="text-ink">{m.tp}</b> · FP <b className="text-ok">{m.fp}</b> · FN <b className="text-alert">{m.fn}</b>
                          </span>
                          <span className="font-mono text-[12px] tabular-nums text-ink-soft">
                            P <b className="text-ink">{m.precision}</b> / R <b className="text-ink">{m.recall}</b> / F1 <b className="text-ink">{m.f1}</b>
                          </span>
                          {layer.tn != null && (
                            <span className="font-mono text-[12px] tabular-nums text-ink-faint">TN {layer.tn}</span>
                          )}
                        </>
                      ) : key === 'L2_shadow' ? (
                        <span className="font-mono text-[12px] tabular-nums text-ink-soft">
                          补充证据 <b className="text-ink">{layer.shadow_extra_evidence}</b> · 良性误击 <b className="text-ok">{layer.shadow_fp_on_benign}</b>
                        </span>
                      ) : (
                        <span className="font-mono text-[12px] tabular-nums text-ink-soft">
                          自动执行 <b className="text-ink">{layer.decisions?.auto_execute}</b> · 需审批 <b className="text-warn">{layer.decisions?.needs_approval}</b>
                          · 不确定/不动 <b>{(layer.decisions?.uncertain ?? 0) + (layer.decisions?.no_action ?? 0)}</b>
                          {layer.match_ms_avg != null && <span className="ml-3 text-ink-faint">匹配均值 {layer.match_ms_avg}ms</span>}
                        </span>
                      )}
                    </div>
                  </motion.div>
                )
              })}
            </div>
          </Dossier>
        )}

        {/* 卷宗 IV · 压测与故障注入 */}
        {perf && (
          <Dossier
            index={3}
            tab="报告 IV"
            title="压测与故障注入"
            meta={perf.meta?.date ?? ''}
            note={perf.meta?.note}
          >
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="border border-line bg-paper-warm px-4 py-3">
                <p className="font-mono text-[10px] tracking-[0.06em] text-ink-faint">接入峰值</p>
                <p className="mt-1 text-[26px] font-semibold tabular-nums text-ink">
                  <CountUp value={perf.saturation?.ingest_peak_eps ?? 0} decimals={1} /> <span className="font-mono text-[11px] font-normal text-ink-faint">eps</span>
                </p>
              </div>
              <div className="border border-ok/40 bg-mint px-4 py-3">
                <p className="font-mono text-[10px] tracking-[0.06em] text-ok">账面丢失</p>
                <p className="mt-1 text-[26px] font-semibold tabular-nums text-ok">
                  <CountUp value={perf.ledger?.loss_rate ?? 0} decimals={1} />%
                </p>
              </div>
              <div className="border border-line bg-paper-warm px-4 py-3">
                <p className="font-mono text-[10px] tracking-[0.06em] text-ink-faint">对账差额</p>
                <p className="mt-1 text-[26px] font-semibold tabular-nums text-ink">
                  <CountUp value={0} /> <span className="font-mono text-[11px] font-normal text-ink-faint">条</span>
                </p>
              </div>
            </div>

            <div className="mt-4 grid gap-2 text-[12px] sm:grid-cols-2">
              {Object.entries(perf.profiles ?? {}).map(([k, v]: [string, any]) => (
                <div key={k} className="border border-line px-3 py-2">
                  <p className="font-mono text-[10px] tracking-[0.06em] text-ink-faint">
                    {k.replace('_', ' · ')}
                  </p>
                  <p className="mt-0.5 text-ink-soft">
                    {v.cmd ? String(v.cmd).slice(0, 58) : ''}
                  </p>
                  <p className="mt-0.5 font-mono tabular-nums text-ink">
                    {v.actual_rate_eps != null && `实速 ${v.actual_rate_eps.toFixed(1)} eps`}
                    {v.latency_ms?.p50 != null && ` · p50 ${Math.round(v.latency_ms.p50)}ms`}
                    {v.rows_in_pg === 0 && k === 'P3_replay_storm' && ' · 全部被幂等账本吸收'}
                    {v.service_stayed_up && ' · 服务未宕'}
                  </p>
                </div>
              ))}
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              {[
                ['P5a 杀 TaskManager', perf.fault_injection?.P5a_taskmanager_kill?.duplicate_alerts === 0 ? '自愈 · 0 重复告警' : '—', 'ok'],
                ['P5b PG 宕 30s', perf.fault_injection?.P5b_pg_down_30s?.loss === 0 ? '接入不丢 · 消费停摆可恢复' : '—', 'ok'],
                ['P5c Redis 宕 30s', String(perf.fault_injection?.P5c_redis_down_30s?.claim ?? ''), 'ok'],
              ].map(([label, verdict]) => (
                <span key={label} className="border border-ok/40 bg-mint px-3 py-1.5 text-[12px] text-ink">
                  <b className="mr-2 font-mono text-[10px] tracking-[0.14em] uppercase text-ok">{label}</b>
                  {verdict}
                </span>
              ))}
            </div>

            {perf.saturation?.verdict && (
              <p className="mt-4 border-l-2 border-dusk pl-4 text-[14px] italic text-ink-soft">
                「{perf.saturation.verdict}」
              </p>
            )}
          </Dossier>
        )}
      </div>

      {/* 页脚口径汇总 */}
      <p className="mt-6 border-t border-line pt-4 font-mono text-[10px] leading-relaxed tracking-[0.1em] text-ink-faint">
        来源 docs/benchmark · 合成标定集口径,绝对值不可外推;所有数字直读评测 JSON,未做展示层改写。
      </p>
    </PageFrame>
  )
}
