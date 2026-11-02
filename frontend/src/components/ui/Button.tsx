import { motion, type HTMLMotionProps } from 'framer-motion'

interface ButtonProps extends HTMLMotionProps<'button'> {
  variant?: 'primary' | 'ghost' | 'danger' | 'outline' | 'underline'
  size?: 'sm' | 'md' | 'lg'
  loading?: boolean
}

/** 守望按钮：暮青印记，几乎无圆角，编辑感 */
export function Button({
  variant = 'primary',
  size = 'md',
  loading = false,
  disabled,
  className = '',
  children,
  ...props
}: ButtonProps) {
  const base =
    'inline-flex items-center justify-center gap-2.5 cursor-pointer whitespace-nowrap transition-colors rounded-[4px] box-border font-medium select-none disabled:opacity-50 disabled:cursor-not-allowed'

  const sizes = {
    sm: 'h-8 px-4 text-[12px]',
    md: 'h-10 px-5 text-[13px]',
    lg: 'h-12 px-7 text-[14px]',
  }

  const variants = {
    primary:
      'bg-accent text-on-accent hover:bg-accent-hover border border-accent',
    outline:
      'bg-transparent text-ink border border-line hover:border-ink hover:text-ink',
    underline:
      '!px-0 bg-transparent text-ink border-b border-ink rounded-none hover:opacity-70',
    ghost: 'bg-transparent text-ink-soft hover:text-ink',
    danger: 'bg-alert text-on-accent hover:opacity-90',
  }

  return (
    <motion.button
      className={`${base} ${sizes[size]} ${variants[variant]} ${className}`}
      whileTap={!disabled && !loading ? { scale: 0.98, opacity: 0.92 } : undefined}
      transition={{ duration: 0.12 }}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <svg
          width="14"
          height="14"
          viewBox="0 0 14 14"
          className="animate-spin"
          aria-hidden
        >
          <circle
            cx="7"
            cy="7"
            r="5.5"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            opacity="0.3"
          />
          <path
            d="M 12.5 7 A 5.5 5.5 0 0 0 7 1.5"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        </svg>
      )}
      {children as React.ReactNode}
    </motion.button>
  )
}
