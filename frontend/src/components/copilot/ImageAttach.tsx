/**
 * ImageAttach · Copilot 图片附件（2026-11 传智杯 AI Web 改造 · 多模态）
 *
 * 支持剪贴板粘贴截图与文件选择，转 data URL（PNG/JPEG/WebP/GIF，≤6MB）。
 * 视觉模型未配置时按钮可见但置灰，tooltip 如实说明原因 —— 明示，不伪装。
 */
import { useRef, useState } from 'react'
import { motion } from 'framer-motion'

export interface AttachedImage {
  dataUrl: string
  name: string
}

const MAX_BYTES = 6 * 1024 * 1024
const ALLOWED = ['image/png', 'image/jpeg', 'image/webp', 'image/gif']

export async function fileToAttachedImage(file: File): Promise<AttachedImage> {
  if (!ALLOWED.includes(file.type)) {
    throw new Error('仅支持 PNG / JPEG / WebP / GIF 图片')
  }
  if (file.size > MAX_BYTES) {
    throw new Error('图片超过 6MB 上限，请压缩后重试')
  }
  const dataUrl = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result))
    reader.onerror = () => reject(new Error('图片读取失败'))
    reader.readAsDataURL(file)
  })
  return { dataUrl, name: file.name || '粘贴的截图' }
}

export function ImageAttach({
  visionEnabled,
  disabled,
  image,
  onChange,
  onPasteFile,
}: {
  visionEnabled: boolean
  disabled?: boolean
  image: AttachedImage | null
  onChange: (img: AttachedImage | null) => void
  /** 挂载方把容器 onPaste 转发进来，实现"截图直接 Ctrl+V" */
  onPasteFile?: (file: File) => void
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [err, setErr] = useState('')

  const tip = !visionEnabled
    ? '视觉模型未配置（SHARED_MEMORY_LLM_VISION_MODEL），图片理解暂不可用'
    : '附加攻击截图 / 可疑页面图片（支持直接 Ctrl+V 粘贴）'

  return (
    <div className="flex items-center gap-2">
      <input
        ref={inputRef}
        type="file"
        accept={ALLOWED.join(',')}
        className="hidden"
        onChange={async (e) => {
          const f = e.target.files?.[0]
          if (!f) return
          try {
            onChange(await fileToAttachedImage(f))
            setErr('')
          } catch (ex) {
            setErr(ex instanceof Error ? ex.message : '图片处理失败')
          }
          e.target.value = ''
        }}
      />
      <motion.button
        type="button"
        whileTap={visionEnabled && !disabled ? { scale: 0.96 } : undefined}
        disabled={!visionEnabled || disabled}
        title={tip}
        onClick={() => inputRef.current?.click()}
        className="inline-flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-[4px] border border-line text-ink-soft transition-colors hover:border-ink hover:text-ink disabled:cursor-not-allowed disabled:opacity-40"
      >
        <svg width="15" height="15" viewBox="0 0 16 16" fill="none">
          <rect x="1.8" y="2.8" width="12.4" height="10.4" rx="1.2" stroke="currentColor" strokeWidth="1.2" />
          <circle cx="5.6" cy="6.4" r="1.2" fill="currentColor" />
          <path d="M2.5 11.5L6 8.5L8.5 10.5L11 8L13.5 10.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </motion.button>

      {image && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="group relative h-9 w-9 shrink-0 overflow-hidden rounded-[3px] border border-line"
        >
          <img src={image.dataUrl} alt={image.name} className="h-full w-full object-cover" />
          <button
            type="button"
            onClick={() => onChange(null)}
            title="移除图片"
            className="absolute inset-0 hidden cursor-pointer items-center justify-center bg-ink/60 text-paper group-hover:flex"
          >
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
              <path d="M2 2L8 8M8 2L2 8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            </svg>
          </button>
        </motion.div>
      )}

      {onPasteFile && (
        <span className="hidden text-[11px] text-ink-faint lg:inline">
          {image ? image.name : '可粘贴截图'}
        </span>
      )}
      {err && <span className="text-[11px] text-alert">{err}</span>}
    </div>
  )
}
