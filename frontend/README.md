# 守望前端 · Night Watch SOC

React 19 + Vite 7 + Tailwind 4 + zustand。设计体系:「机要室/案卷」编辑风(token 化,`[data-mode=battle]` 变量翻转实现全站暗色换肤)。

## 路演直达(作战大屏)

| 入口 | 用途 |
| --- | --- |
| `/screen` | kiosk 直达审计大屏:不经过登录守卫与 TopNav,打开即满屏三列作战网格(F 键/Esc 退出同样有效) |
| `/screen?token=<JWT>` | 携带凭据直达:token 持久化后立即从地址栏抹除;SSE 实时数据上线 |
| `/screen?event=<id>` | 案卷深链:思维链主舞台直接定位该事件(剧本页结案移交即走此链) |
| `/poster` | 系统全景海报:一屏读懂架构流水线,每格挂活数据,投屏即海报、拍屏即可转述(Esc 退出) |
| `/demo` | 攻击剧本沉浸演示(六幕)。结案印章落下后 5s 倒计时自动移交 `/screen`,同一事件在大屏思维链继续;可点「留在结案」取消 |

无凭据(无 token)时大屏照样渲染:后端可达则各数据区显示真实口径;SSE 断流超过 6s 自动切入**回放口径**(`lib/wallReplay.ts`,三场景循环的合成事件,走同一条 ingest 管线,整面墙保持呼吸)。回放事件 event_id 使用 9_000_000+ 保留段、行内带「回放」标记,顶栏徽章与底栏跑马灯明示口径,不计入真实统计。

401 在 kiosk 下不整页跳登录(`lib/api.ts` 的 `setKioskMode`),幕布在任何认证状态下都保持在线。

## 大屏距离字号

作战大屏文字按 3-5m 观看距离校准:BattleScreen 正文 12-13px 起,`KpiStat` 增加 `size="lg"` 档;思维链主舞台经 `.wall-zoom`(CSS zoom 1.35)整体放大 —— ThoughtDag 自带 ResizeObserver,缩放后自动重测连线。

## 开发

```bash
npm run dev      # :3001,/api 代理到 BACKEND_PROXY(默认 host.docker.internal:8001)
npm run check    # tsc -b && oxlint
npm run build    # 产物在 dist/,由 nginx 容器伺服
```

`lib/eventStream.ts` 是实时事件流共享内核(单例 EventSource + zustand):断线续传以 SecurityEvent.id 为业务游标,微批 50ms 合并写入。注意 `flushBatch` 里 batch 必须先 `slice()` 再 `reverse()`(reverse 原地反转返回同一引用,历史上曾因直接截断导致缓冲永远为空)。
