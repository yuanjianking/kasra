interface SkeletonProps {
  rows?: number
  cols?: number
  className?: string
}

export function TableSkeleton({ rows = 5, cols = 6, className = '' }: SkeletonProps) {
  return (
    <div className={`animate-pulse ${className}`}>
      <div className="flex gap-4 mb-3 px-3">
        {Array.from({ length: cols }).map((_, i) => (
          <div key={i} className="h-4 bg-slate-200 rounded flex-1" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-4 px-3 py-3 border-t border-slate-100">
          {Array.from({ length: cols }).map((_, c) => (
            <div key={c} className={`h-3 bg-slate-100 rounded flex-1 ${c === 0 ? 'w-16' : ''}`} />
          ))}
        </div>
      ))}
    </div>
  )
}

export function CardSkeleton({ count = 6 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="h-24 bg-slate-100 rounded-xl animate-pulse" />
      ))}
    </div>
  )
}

export function ChartSkeleton({ height = 250 }: { height?: number }) {
  return (
    <div className="animate-pulse bg-slate-100 rounded-xl" style={{ height }} />
  )
}
