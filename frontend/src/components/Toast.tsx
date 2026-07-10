import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'

type ToastType = 'success' | 'error' | 'warning' | 'info'

interface Toast {
  id: number
  message: string
  type: ToastType
}

interface ToastContextValue {
  toast: (message: string, type?: ToastType) => void
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} })

export const useToast = () => useContext(ToastContext)

let nextId = 0

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([])

  const addToast = useCallback((message: string, type: ToastType = 'info') => {
    const id = nextId++
    setItems(prev => [...prev, { id, message, type }])
    setTimeout(() => {
      setItems(prev => prev.filter(t => t.id !== id))
    }, 4000)
  }, [])

  const remove = (id: number) => setItems(prev => prev.filter(t => t.id !== id))

  const colors: Record<ToastType, string> = {
    success: 'bg-emerald-600',
    error: 'bg-red-600',
    warning: 'bg-amber-500',
    info: 'bg-indigo-600',
  }

  const icons: Record<ToastType, string> = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ',
  }

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
        {items.map(item => (
          <div
            key={item.id}
            className={`${colors[item.type]} text-white px-4 py-3 rounded-xl shadow-lg flex items-center gap-2.5 min-w-[280px] max-w-[400px] animate-slide-up`}
          >
            <span className="text-lg">{icons[item.type]}</span>
            <span className="text-sm flex-1">{item.message}</span>
            <button onClick={() => remove(item.id)} className="text-white/70 hover:text-white text-lg leading-none">&times;</button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}
