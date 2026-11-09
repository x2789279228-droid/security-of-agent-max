import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// dev 模式下 vite 容器内 `localhost` 是容器自身, 连不到宿主机 :8001 backend
//   用 `host.docker.internal:8001` 走 Docker Desktop 的 host-gateway DNS 解析
//   prod 模式 (vite build 静态产物) 不依赖 server.proxy, 改这里不影响 prod
const BACKEND_PROXY = process.env.BACKEND_PROXY || 'http://host.docker.internal:8001'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 3001,
    strictPort: true,
    proxy: { '/api': BACKEND_PROXY },
  },
  build: {
    // 2026-11-09 修复: 删除 charts/markdown/motion 三组手动分包 —— Rolldown
    // advancedChunks 依赖捕获语义下它们把 react 核心/jsx-runtime 捕进懒加载
    // 页面的 chunk, 入口被迫静态 import → 首屏 modulepreload 全量 6 chunk
    // (~988KB raw)。改为只保留 react/vendor 两组, recharts/react-markdown
    // 自然跟随 lazy() 页面按需分包; framer-motion 因 PageTransition 在入口
    // 图内, 留在 vendor 属预期。缓存隔离由 nginx /assets/ immutable 承担。
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined
          if (id.includes('react') || id.includes('scheduler')) return 'react'
          return 'vendor'
        },
      },
    },
  },
})
