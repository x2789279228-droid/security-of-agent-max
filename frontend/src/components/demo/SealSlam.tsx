import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'

/**
 * 结案印章(签名时刻②) — 剧本终幕:一方红印砸落案卷。
 * scale 2.6→1 + 微旋转 + 纸面震颤 + 印泥洇开;reduced-motion 退化为淡入。
 * footer:overlay 之内的终幕操作区(印章盖住舞台,常规按钮不可达,移交控件住这里)。
 */
export function SealSlam({
  text,
  sub,
  degradedNote,
  onDone,
  footer,
}: {
  text: string
  sub: string
  degradedNote?: string | null
  onDone?: () => void
  footer?: React.ReactNode
}) {
  const reduced = useReducedMotion() ?? false
  const [shown, setShown] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => setShown(true), 350)
    return () => clearTimeout(t)
  }, [])

  return (
    <motion.div
      className="absolute inset-0 z-30 flex items-center justify-center"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      {/* 背景压暗(不完全遮蔽后方的思维链舞台) */}
      <div className="absolute inset-0 bg-[#0e1a26]/72" aria-hidden />

      {/* 纸面震颤载体 */}
      <motion.div
        className="relative"
        initial={reduced ? undefined : { x: 0 }}
        animate={reduced ? undefined : { x: [0, -7, 5, -3, 1, 0] }}
        transition={reduced ? undefined : { duration: 0.5, delay: 0.32, ease: 'easeOut' }}
      >
        {/* 印泥洇开 */}
        <motion.div
          aria-hidden
          className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full"
          style={{
            width: 340,
            height: 340,
            background: 'radial-gradient(circle, rgba(224,96,79,0.34) 0%, rgba(224,96,79,0.10) 45%, transparent 70%)',
          }}
          initial={reduced ? { opacity: 0.5 } : { scale: 0.35, opacity: 0 }}
          animate={reduced ? { opacity: 0.6 } : { scale: 1, opacity: 1 }}
          transition={{ duration: reduced ? 0.4 : 0.9, delay: reduced ? 0 : 0.42, ease: 'easeOut' }}
        />

        {/* 印章本体 */}
        <motion.div
          className="relative flex h-[240px] w-[240px] flex-col items-center justify-center border-[3px] border-[#e2604f] text-[#e2604f]"
          style={{ boxShadow: '0 0 0 2px rgba(224,96,79,0.35), 0 0 60px rgba(224,96,79,0.25)' }}
          initial={reduced ? { opacity: 0 } : { scale: 2.6, opacity: 0, rotate: -18 }}
          animate={reduced ? { opacity: 1 } : { scale: 1, opacity: 1, rotate: -7 }}
          transition={reduced ? { duration: 0.5 } : { type: 'spring', stiffness: 320, damping: 22, delay: 0.32 }}
          onAnimationComplete={() => onDone?.()}
        >
          {/* 内框 */}
          <span className="pointer-events-none absolute inset-2 border border-[#e2604f]/45" aria-hidden />
          <span className="font-mono text-[10px] tracking-[0.4em] uppercase text-[#e2604f]/80">Shouwang · 结案</span>
          <span className="mt-2 font-serif text-[64px] font-black leading-none tracking-[0.08em]">{text}</span>
          <span className="mt-3 font-mono text-[10px] tracking-[0.3em] uppercase text-[#e2604f]/70">
            {new Date().toLocaleDateString('zh-CN')}
          </span>
        </motion.div>

        {/* 案卷摘要 */}
        <motion.div
          className="mx-auto mt-8 max-w-[34rem] text-center"
          initial={{ opacity: 0, y: 10 }}
          animate={shown ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.45 }}
        >
          <p className="font-serif text-[15px] leading-relaxed text-[#c9d6cf]">{sub}</p>
          {degradedNote && (
            <p className="mt-2 font-mono text-[11px] tracking-[0.12em] text-[#d9b06b]">{degradedNote}</p>
          )}
          {footer && (
            <motion.div
              className="mt-7"
              initial={{ opacity: 0, y: 8 }}
              animate={shown ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.4, delay: 0.35 }}
            >
              {footer}
            </motion.div>
          )}
        </motion.div>
      </motion.div>
    </motion.div>
  )
}
