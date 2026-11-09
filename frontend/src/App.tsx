import { lazy, Suspense, useEffect, type ReactNode } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { RootLayout } from './layouts/RootLayout'
import { ROUTES } from './lib/constants'
import { PageTransition } from './components/common/PageTransition'
import { ErrorBoundary } from './components/common/ErrorBoundary'
import { useAuthStore } from './stores/authStore'
import { applyThemeMode } from './lib/themeMode'


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
const Sensing = lazy(() => import('./pages/Sensing'))
const AntiPhishing = lazy(() => import('./pages/AntiPhishing'))
const Benchmark = lazy(() => import('./pages/Benchmark'))
const Demo = lazy(() => import('./pages/Demo'))
const Screen = lazy(() => import('./pages/Screen'))
const Poster = lazy(() => import('./pages/Poster'))
// 2026-11 AI Web 改造:对话式安全分析 + 接入台(剧本注入/手动录日志)
const Copilot = lazy(() => import('./pages/Copilot'))
const Ingest = lazy(() => import('./pages/Ingest'))

function PageLoader() {
  return (
    <PageTransition>
      <div className="flex h-[60vh] flex-col items-center justify-center gap-3">
        <p className="text-[24px] font-semibold text-ink">守望</p>
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
  // ErrorBoundary 包在 Suspense 外 —— 同时兜住页面渲染异常与 lazy chunk
  // 拉取失败(此前 15 条业务路由任一崩溃/断网加载失败 = 整站白屏)
  return (
    <Guard>
      <ErrorBoundary fallbackTitle="页面渲染异常">
        <Suspense fallback={<PageLoader />}>{el}</Suspense>
      </ErrorBoundary>
    </Guard>
  )
}

/** 主题同步：挂路由层 —— 覆盖 login/register 等不套 RootLayout 的路由（默认暗色，舞台页强制） */
function ThemeSync() {
  const { pathname } = useLocation()
  useEffect(() => {
    applyThemeMode(pathname)
    const onThemeChange = () => applyThemeMode(pathname)
    window.addEventListener('soc:theme-change', onThemeChange)
    return () => window.removeEventListener('soc:theme-change', onThemeChange)
  }, [pathname])
  return null
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeSync />
      <Routes>
        <Route path="/login" element={<Suspense fallback={<PageLoader />}><Login /></Suspense>} />
        <Route path="/register" element={<Suspense fallback={<PageLoader />}><Register /></Suspense>} />
        {/* 攻击剧本:独立全屏舞台,不套 RootLayout(无 TopNav,自带 data-mode=battle) */}
        <Route path={ROUTES.DEMO} element={page(<Demo />)} />
        <Route element={<RootLayout />}>
          <Route index element={page(<Home />)} />
          {/* 接入台:剧本注入/手动录日志(值班主线第一站,对齐"01 接入") */}
          <Route path={ROUTES.INGEST} element={page(<Ingest />)} />
          <Route path={ROUTES.LOGS} element={page(<Logs />)} />
          <Route path={ROUTES.MONITOR} element={page(<Monitor />)} />
          {/* AI 分析 Copilot:对话式安全分析(流式 + 知识引用 + 截图研判) */}
          <Route path={ROUTES.COPILOT} element={page(<Copilot />)} />
          <Route path={ROUTES.SECURITY_AUDIT} element={page(<SecurityAudit />)} />
          <Route path={ROUTES.RESPONSE} element={page(<Response />)} />
          <Route path={ROUTES.OPERATIONS} element={page(<Operations />)} />
          <Route path={ROUTES.SELF_PLAY} element={page(<SelfPlay />)} />
          <Route path={ROUTES.RAG} element={page(<RAG />)} />
          {/* 感知中心:旧六条平页路由重定向至对应标签 */}
          <Route path={ROUTES.SENSING} element={page(<Sensing />)} />
          <Route path={ROUTES.ANTI_PHISHING} element={page(<AntiPhishing />)} />
          <Route path="/traffic" element={<Navigate to="/sensing?t=traffic" replace />} />
          <Route path="/encrypted" element={<Navigate to="/sensing?t=encrypted" replace />} />
          <Route path="/intel" element={<Navigate to="/sensing?t=intel" replace />} />
          <Route path="/sandbox" element={<Navigate to="/sensing?t=sandbox" replace />} />
          <Route path="/edr" element={<Navigate to="/sensing?t=edr" replace />} />
          <Route path="/capabilities" element={<Navigate to="/sensing?t=capabilities" replace />} />
          <Route path={ROUTES.BENCHMARK} element={page(<Benchmark />)} />
        </Route>
        {/* 作战大屏 kiosk:独立全屏舞台,不套 RootLayout、不经 Guard —— 路演机 URL 直达。
            认证可选(?token=),无凭据时幕布由回放口径兜底。 */}
        <Route
          path={ROUTES.SCREEN}
          element={<Suspense fallback={<PageLoader />}><Screen /></Suspense>}
        />
        {/* 系统全景海报:同 kiosk 口径,投屏即海报 */}
        <Route
          path={ROUTES.POSTER}
          element={<Suspense fallback={<PageLoader />}><Poster /></Suspense>}
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

