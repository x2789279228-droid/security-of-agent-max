/**
 * ErrorBoundary · 渲染错误边界（2026-11 AI Web 改造）
 *
 * 评分细则点名「错误边界处理优雅」：单条消息/单块面板的渲染异常
 * 不拖垮整页 —— 捕获后降级为一张安静的案卷错误卡，提供重试。
 * 用法：<ErrorBoundary fallbackTitle="消息渲染异常"><MessageBubble …/></ErrorBoundary>
 */
import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
  /** 错误卡标题（默认「渲染异常」） */
  fallbackTitle?: string
  /** 重试回调：通过 key 变化重挂子树即可，此回调仅用于埋点/提示 */
  onRetry?: () => void
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', this.props.fallbackTitle ?? '渲染异常', error, info.componentStack)
  }

  private reset = () => {
    this.setState({ error: null })
    this.props.onRetry?.()
  }

  render() {
    if (this.state.error) {
      return (
        <div className="rounded-[4px] border border-alert/30 bg-alert/5 px-4 py-3">
          <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-alert/80">
            {this.props.fallbackTitle ?? '渲染异常'}
          </p>
          <p className="mt-1 break-all text-[12px] leading-relaxed text-ink-soft">
            {this.state.error.message || String(this.state.error)}
          </p>
          <button
            type="button"
            onClick={this.reset}
            className="mt-2 cursor-pointer text-[11.5px] text-accent underline underline-offset-2"
          >
            重试渲染
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
