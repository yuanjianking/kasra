interface ToggleProps {
  enabled: boolean
  onChange: () => void
  disabled?: boolean
  size?: 'sm' | 'md'
}

export default function Toggle({ enabled, onChange, disabled = false, size = 'sm' }: ToggleProps) {
  const h = size === 'sm' ? 'h-5' : 'h-6'
  const w = size === 'sm' ? 'w-9' : 'w-11'
  const dot = size === 'sm' ? 'h-3.5 w-3.5' : 'h-5 w-5'
  const translateOn = size === 'sm' ? 'translate-x-[18px]' : 'translate-x-5'
  const translateOff = size === 'sm' ? 'translate-x-1' : 'translate-x-0.5'

  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      onClick={disabled ? undefined : onChange}
      disabled={disabled}
      className={`relative inline-flex ${h} ${w} items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-1 ${
        disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
      } ${enabled ? 'bg-indigo-600' : 'bg-slate-300'}`}
    >
      <span className={`inline-block ${dot} transform rounded-full bg-white transition-transform ${enabled ? translateOn : translateOff}`} />
    </button>
  )
}
