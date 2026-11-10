import { useEffect, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useAuthStore } from '../stores/authStore'
import { AuthShell } from '../components/login/AuthShell'
import LoginForm from '../components/login/LoginForm'

export default function Login() {
  const token = useAuthStore((s) => s.token)
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (token) return <Navigate to="/" replace />

  // 开放体验模式(2026-11-10): 无论因何落到 /login(登出残留/直接输 URL),
  // 探测后端模式并自动送回工作台 —— 开放模式下登录页没有意义
  useEffect(() => {
    let alive = true
    fetch('/api/auth/mode')
      .then((r) => (r.ok ? r.json() : { open_tour: false }))
      .then((d: { open_tour?: boolean }) => {
        if (!alive || !d.open_tour) return
        useAuthStore.getState().setOpenTour(true)
        useAuthStore.getState().setAuth('open-tour', 'Visitor')
        navigate('/', { replace: true })
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [navigate])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !password.trim()) {
      setError('请输入用户名和密码')
      return
    }
    setLoading(true)
    setError('')
    try {
      const data = await api.login(username.trim(), password)
      useAuthStore.getState().setAuth(data.access_token, username.trim())
    } catch (err: any) {
      const msg = typeof err?.message === 'string' ? err.message : ''
      if (msg.includes('401') || msg.includes('认证') || msg.includes('Unauthorized')) {
        setError('用户名或密码错误')
      } else if (msg.includes('Failed to fetch') || msg.includes('Network') || msg.includes('网络')) {
        setError('无法连接服务器，请稍后重试')
      } else if (msg) {
        setError(msg.replace(/^API \d+:\s*/, '') || '用户名或密码错误')
      } else {
        setError('用户名或密码错误')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthShell title="登录" subtitle="输入凭证进入工作台">
      <LoginForm
        username={username}
        password={password}
        error={error}
        loading={loading}
        onUsernameChange={setUsername}
        onPasswordChange={setPassword}
        onSubmit={handleSubmit}
      />
    </AuthShell>
  )
}
