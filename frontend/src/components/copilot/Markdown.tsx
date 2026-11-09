/**
 * Markdown · Copilot 回答的流式渲染
 *
 * react-markdown + remark-gfm（表格/任务列表），仅被 /copilot lazy chunk 引入。
 * 流式未闭合的 markdown（半个表格/未闭合代码块）react-markdown 会按已完成
 * 部分渲染 —— 天然适配打字机式输出，无需额外容错。
 * 样式走 token 类，与 v8 编辑部风一致（无 prose 插件，手动映射元素）。
 */
import { memo } from 'react'
import ReactMarkdown, { type Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'

// 2026-11-09: components 提升到模块级 —— 每次渲染新建对象会击穿
// react-markdown 内部缓存, 历史气泡因 done/usage 帧重渲染时全部重解析
const MD_COMPONENTS: Components = {
          p: (props) => <p className="my-2 first:mt-0 last:mb-0" {...props} />,
          ul: (props) => <ul className="my-2 list-disc pl-5 space-y-1" {...props} />,
          ol: (props) => <ol className="my-2 list-decimal pl-5 space-y-1" {...props} />,
          li: (props) => <li className="leading-relaxed" {...props} />,
          h1: (props) => <h3 className="mt-3 mb-1.5 text-[15px] font-semibold text-ink" {...props} />,
          h2: (props) => <h3 className="mt-3 mb-1.5 text-[15px] font-semibold text-ink" {...props} />,
          h3: (props) => <h4 className="mt-2.5 mb-1 text-[13.5px] font-semibold text-ink" {...props} />,
          strong: (props) => <strong className="font-semibold text-ink" {...props} />,
          code: (props) => (
            <code className="rounded-[3px] bg-mist px-1.5 py-0.5 font-mono text-[12px] text-ink" {...props} />
          ),
          pre: (props) => (
            <pre
              className="my-2 overflow-x-auto rounded-[4px] border border-line bg-mist px-3 py-2.5 font-mono text-[12px] leading-relaxed text-ink"
              {...props}
            />
          ),
          table: (props) => (
            <div className="my-2 overflow-x-auto">
              <table className="w-full border-collapse text-[12.5px]" {...props} />
            </div>
          ),
          th: (props) => (
            <th className="border border-line bg-mist px-2.5 py-1.5 text-left font-medium text-ink" {...props} />
          ),
          td: (props) => <td className="border border-line px-2.5 py-1.5 align-top" {...props} />,
          blockquote: (props) => (
            <blockquote className="my-2 border-l-2 border-accent/40 pl-3 text-ink-soft" {...props} />
          ),
          a: (props) => <a className="text-accent underline underline-offset-2" target="_blank" rel="noreferrer" {...props} />,
          hr: () => <hr className="my-3 border-line" />,
}

export const Markdown = memo(function Markdown({ text }: { text: string }) {
  return (
    <div className="copilot-md text-[13.5px] leading-relaxed text-ink">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={MD_COMPONENTS}
      >
        {text}
      </ReactMarkdown>
    </div>
  )
})
