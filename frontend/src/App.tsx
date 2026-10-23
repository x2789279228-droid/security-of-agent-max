import { lazy, Suspense, type ReactNode } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { RootLayout } from './layouts/RootLayout'
import { ROUTES } from './lib/constants'
import { PageTransition } from './components/common/PageTransition'
import { useAuthStore } from './stores/authStore'


const Login = lazy(() => import('./pages/Login'))
const Register = lazy(() => import('./pages/Register'))
const Home = lazy(() => import('./pages/Home'))
const Logs = lazy(() => import('./pages/Logs'))
const Monitor = lazy(() => import('./pages/Monitor'))
const SecurityAudit = lazy(() => import('./pages/SecurityAudit'))
const Response = lazy(() => import('./pages/Response'))
const RAG = lazy(() => import('./pages/RAG'))
const Operations = lazy(() => import('./pages/Operations'))
const SelfPlay = lazy(() => import('./pages/SelfPlay'))
const Traffic = lazy(() => import('./pages/Traffic'))
const Encrypted = lazy(() => import('./pages/Encrypted'))
const Intel = lazy(() => import('./pages/Intel'))
const Sandbox = lazy(() => import('./pages/Sandbox'))
const EDR = lazy(() => import('./pages/EDR'))
const CapabilitiesDashboard = lazy(() => import('./pages/CapabilitiesDashboard'))

function PageLoader() {
  return (
    <PageTransition>
      <div className="flex h-[60vh] flex-col items-center justify-center gap-3">
        <p className="font-serif text-[28px] font-black text-ink">守望</p>
        <p className="text-sm text-ink-faint">加载中</p>
      </div>
    </PageTransition>
  )
}

function Guard({ children }: { children: ReactNode }) {
  const token = useAuthStore((s) => s.token)
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

/**
 * 业务路由统一挂 Guard。
 *
 * 2026-10-03 修复：此前 `page(el, auth)` 的 auth 参数在【全部 15 条路由】上
 * 都被显式传成 false，Guard 因此从不被渲染 —— 未登录用户能进入 /operations、
 * /rag、/response，看到完整页面外壳，然后各区块各自 401/403，最终呈现为
 * 一个"看起来正常但全是 0 / 暂无"的面板。
 *
 * 现在不再提供跳过鉴权的开关：需要免鉴权的只有 /login 与 /register，
 * 它们在下方直接用 Suspense 包裹，不经过本函数。
 */
function page(el: ReactNode) {
  return (
    <Guard>
      <Suspense fallback={<PageLoader />}>{el}</Suspense>
    </Guard>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Suspense fallback={<PageLoader />}><Login /></Suspense>} />
        <Route path="/register" element={<Suspense fallback={<PageLoader />}><Register /></Suspense>} />
        <Route element={<RootLayout />}>
          <Route index element={page(<Home />)} />
          <Route path={ROUTES.LOGS} element={page(<Logs />)} />
          <Route path={ROUTES.MONITOR} element={page(<Monitor />)} />
          <Route path={ROUTES.SECURITY_AUDIT} element={page(<SecurityAudit />)} />
          <Route path={ROUTES.RESPONSE} element={page(<Response />)} />
          <Route path={ROUTES.OPERATIONS} element={page(<Operations />)} />
          <Route path={ROUTES.SELF_PLAY} element={page(<SelfPlay />)} />
          <Route path={ROUTES.RAG} element={page(<RAG />)} />
          <Route path={ROUTES.TRAFFIC} element={page(<Traffic />)} />
          <Route path={ROUTES.ENCRYPTED} element={page(<Encrypted />)} />
          <Route path={ROUTES.INTEL} element={page(<Intel />)} />
          <Route path={ROUTES.SANDBOX} element={page(<Sandbox />)} />
          <Route path={ROUTES.EDR} element={page(<EDR />)} />
          <Route path={ROUTES.CAPABILITIES} element={page(<CapabilitiesDashboard />)} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

