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
    // 2026-11 AI Web 改造:vendor 手动分包 —— react 系/markdown(仅 Copilot 用)/
    // 图表系各自独立,业务代码改动不再打爆整块 vendor 缓存;首屏只加载 react 系。
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined
          if (id.includes('react-markdown') || id.includes('remark-') || id.includes('unified') || id.includes('micromark') || id.includes('mdast') || id.includes('hast') || id.includes('rehype') || id.includes('parse5') || id.includes('property-information') || id.includes('vfile') || id.includes('unist')) return 'markdown'
          if (id.includes('recharts') || id.includes('d3-') || id.includes('victory-vendor') || id.includes('internmap')) return 'charts'
          if (id.includes('framer-motion') || id.includes('motion-dom') || id.includes('motion-utils')) return 'motion'
          if (id.includes('react') || id.includes('scheduler')) return 'react'
          return 'vendor'
        },
      },
    },
  },
})
