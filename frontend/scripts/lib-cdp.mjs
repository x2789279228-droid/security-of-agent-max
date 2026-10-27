/**
 * CDP 验证公共库 — 供 verify-*.mjs 脚本复用(与 verify-monitor.mjs 同一套模式)
 *
 * 用法:
 *   import { runVerified } from './lib-cdp.mjs'
 *   runVerified(async ({ cdp, text, shot, evaluate }) => { ...checks... })
 *
 * 环境:BASE(默认 http://127.0.0.1:3010)、CHROME_PATH、ADMIN_USER/ADMIN_PASS。
 * 未提供 ADMIN_PASS 时使用哑 token(仅验证前端结构,不验证真实数据)。
 */
import { spawn } from 'child_process'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
export const ROOT = path.resolve(__dirname, '..')

export const BASE = process.env.MONITOR_URL || 'http://127.0.0.1:3010'
export const USER = process.env.ADMIN_USER || 'admin'
export const PASS = process.env.ADMIN_PASS || ''

const CHROME = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

async function waitPort(port, tries = 40) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/json/version`)
      if (r.ok) return r.json()
    } catch {}
    await sleep(250)
  }
  throw new Error('Chrome CDP not ready')
}

class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl)
    this.id = 0
    this.pending = new Map()
    this.ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data.toString())
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id)
        this.pending.delete(msg.id)
        if (msg.error) reject(new Error(JSON.stringify(msg.error)))
        else resolve(msg.result)
      }
    })
  }
  ready() {
    if (this.ws.readyState === WebSocket.OPEN) return Promise.resolve()
    return new Promise((resolve, reject) => {
      this.ws.addEventListener('open', () => resolve(), { once: true })
      this.ws.addEventListener('error', (e) => reject(e), { once: true })
    })
  }
  send(method, params = {}) {
    const id = ++this.id
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.ws.send(JSON.stringify({ id, method, params }))
    })
  }
  close() {
    this.ws.close()
  }
}

/**
 * 主流程:起 headless Chrome → (可选)API 登录或哑 token → 打开页面 → 执行校验回调 → 收尾。
 * 回调拿到 { cdp, evaluate, text, shot, goto }。
 */
export async function runVerified(name, viewport, fn) {
  const userData = path.join(process.env.TEMP || '/tmp', `chrome-${name}-${Date.now()}`)
  fs.mkdirSync(userData, { recursive: true })
  const port = 9333 + Math.floor(Math.random() * 40)
  const chrome = spawn(
    CHROME,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-first-run',
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${userData}`,
      'about:blank',
    ],
    { stdio: ['ignore', 'ignore', 'ignore'] },
  )

  try {
    await waitPort(port)
    const targets = await fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json())
    const page = targets.find((t) => t.type === 'page') || targets[0]
    if (!page?.webSocketDebuggerUrl) throw new Error('no page target')
    const cdp = new CDP(page.webSocketDebuggerUrl)
    await cdp.ready()
    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: false,
    })

    const evaluate = async (expression) => {
      const r = await cdp.send('Runtime.evaluate', { awaitPromise: true, expression })
      return r.result?.value
    }
    const text = async () => String((await evaluate(`document.body?.innerText || ''`)) || '')
    const shot = async (filename) => {
      const s = await cdp.send('Page.captureScreenshot', { format: 'png' })
      const out = path.join(ROOT, 'scripts', filename)
      fs.writeFileSync(out, Buffer.from(s.data, 'base64'))
      console.log('screenshot', out)
      return out
    }
    const goto = async (p, waitMs = 2500) => {
      await cdp.send('Page.navigate', { url: BASE + p })
      await sleep(waitMs)
    }

    // 登录:有 ADMIN_PASS 走真实 API;否则哑 token(仅结构验证)
    if (PASS) {
      const r = await evaluate(`(async () => {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: ${JSON.stringify(USER)}, password: ${JSON.stringify(PASS)} }),
        })
        const d = await res.json()
        if (!d.access_token) return 'fail:' + res.status
        localStorage.setItem('sm_token', d.access_token)
        localStorage.setItem('sm_user', ${JSON.stringify(USER)})
        return 'ok'
      })()`)
      console.log('api-login', r)
      if (r !== 'ok') throw new Error('login failed: ' + r)
    } else {
      console.log('api-login skipped (ADMIN_PASS 未提供,使用哑 token 做结构验证)')
      await goto('/login', 1200)
      await evaluate(`localStorage.setItem('sm_token', 'dummy-verify-token'); localStorage.setItem('sm_user', 'verifier'); 'ok'`)
    }

    await fn({ cdp, evaluate, text, shot, goto })
    cdp.close()
  } finally {
    chrome.kill()
  }
}

export function finish(checks) {
  const failed = Object.entries(checks).filter(([, v]) => !v)
  if (failed.length) {
    console.error('VERIFY_FAILED:', failed.map(([k]) => k).join(', '))
    process.exitCode = 1
  } else {
    console.log('VERIFY_OK')
  }
}
