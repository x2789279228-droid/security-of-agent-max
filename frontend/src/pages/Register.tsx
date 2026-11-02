import { useState } from 'react'
import { Navigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useAuthStore } from '../stores/authStore'
import { AuthShell } from '../components/login/AuthShell'

export default function Register() {
  const token = useAuthStore((s) => s.token)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (token) return <Navigate to="/" replace />

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!username.trim() || !password.trim()) {
      setError('请填写完整')
      return
    }
    if (password.length < 6) {
      setError('密码至少 6 位')
      return
    }
    if (password !== confirm) {
      setError('两次密码不一致')
      return
    }
    setLoading(true)
    try {
      await api.register(username.trim(), password)
      const data = await api.login(username.trim(), password)
      useAuthStore.getState().setAuth(data.access_token, username.trim())
    } catch (err: any) {
      const msg = typeof err?.message === 'string' ? err.message : ''
      if (msg.includes('409') || msg.includes('exists') || msg.includes('已存在')) {
        setError('该用户名已被注册')
      } else if (msg) {
        setError(msg.replace(/^API \d+:\s*/, '') || '注册失败')
      } else {
        setError('注册失败，请稍后再试')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthShell title="注册" subtitle="创建账号，完成后自动登录">
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <Field label="用户名">
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="operator"
            autoComplete="username"
            className="auth-input text-[15px]"
          />
        </Field>
        <Field label="密码">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="至少 6 位"
            autoComplete="new-password"
            className="auth-input text-[15px]"
          />
        </Field>
        <Field label="确认密码">
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="再次输入密码"
            autoComplete="new-password"
            className="auth-input text-[15px]"
          />
        </Field>

        {error && (
          <p className="rounded-[4px] border border-alert/40 bg-alert/10 px-3 py-2 text-[12px] text-alert">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="h-10 w-full rounded-[4px] bg-accent text-[14px] font-medium text-on-accent transition-colors hover:bg-accent-hover disabled:opacity-50"
        >
          {loading ? '注册中…' : '注册'}
        </button>

        <p className="pt-1 text-[13px] text-ink-faint">
          已有账号？前往{' '}
          <a href="/login" className="text-accent hover:opacity-80">
            登录
          </a>
        </p>
      </form>
    </AuthShell>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[12px] text-ink-faint">{label}</span>
      {children}
    </label>
  )
}
