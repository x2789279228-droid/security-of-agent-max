import { useState } from 'react'
import { Navigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useAuthStore } from '../stores/authStore'
import { AuthShell } from '../components/login/AuthShell'
import LoginForm from '../components/login/LoginForm'

export default function Login() {
  const token = useAuthStore((s) => s.token)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (token) return <Navigate to="/" replace />

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
