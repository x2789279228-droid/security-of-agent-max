import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
// MiSans 本地子集（unicode-range 按需加载，仅 400/500/600 三档；OFL 授权随包分发）
import 'misans/lib/Normal/MiSans-Regular.min.css'
import 'misans/lib/Normal/MiSans-Medium.min.css'
import 'misans/lib/Normal/MiSans-Demibold.min.css'
import './index.css'
import { initBrowserTelemetry } from './lib/otel'
import App from './App'

// 初始化浏览器 OTel trace (浏览器 → collector → Jaeger/Tempo), 幂等
initBrowserTelemetry()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
