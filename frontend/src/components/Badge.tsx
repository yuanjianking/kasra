interface BadgeProps {
  variant?: 'default' | 'success' | 'danger' | 'warning' | 'info' | 'purple'
  children: string | number
  size?: 'sm' | 'md'
}

const variants: Record<string, string> = {
  default: 'bg-slate-100 text-slate-700',
  success: 'bg-emerald-100 text-emerald-700',
  danger: 'bg-red-100 text-red-700',
  warning: 'bg-amber-100 text-amber-700',
  info: 'bg-blue-100 text-blue-700',
  purple: 'bg-purple-100 text-purple-700',
}

const severityMap: Record<string, string> = {
  P0: 'danger',
  P1: 'warning',
  P2: 'default',
}

const actionMap: Record<string, string> = {
  block: 'danger',
  warn: 'warning',
  redact: 'info',
  clean: 'success',
  allow: 'success',
}

export default function Badge({ variant = 'default', children, size = 'sm' }: BadgeProps) {
  const resolved = variants[severityMap[String(children)] || actionMap[String(children)] || variant]
  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm'
  return (
    <span className={`${resolved} ${sizeClass} rounded-full font-medium inline-block`}>
      {children}
    </span>
  )
}
