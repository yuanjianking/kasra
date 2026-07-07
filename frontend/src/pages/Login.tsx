import { useState } from 'react'
import { useAuth } from '../auth'

export default function Login() {
  const { setApiKey } = useAuth()
  const [key, setKey] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!key.trim()) return

    setLoading(true)
    setError(null)

    try {
      // Verify the key by calling health endpoint
      const res = await fetch('/health', {
        headers: { 'X-API-Key': key.trim() }
      })
      if (res.ok) {
        setApiKey(key.trim())
      } else if (res.status === 401) {
        setError('Invalid API key. Check your key and try again.')
      } else {
        setError(`Server error (${res.status}). Is the Kasra service running?`)
      }
    } catch {
      setError('Cannot connect to Kasra service. Make sure it is running on port 8080.')
    }
    setLoading(false)
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 to-slate-800">
      <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
        {/* Logo / Header */}
        <div className="text-center mb-8">
          <div className="text-4xl mb-2">🔒</div>
          <h1 className="text-2xl font-bold text-slate-800">Kasra</h1>
          <p className="text-sm text-slate-500 mt-1">AI Development Security Governance</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">API Key</label>
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="Enter your Kasra API key"
              className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm"
              autoFocus
            />
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !key.trim()}
            className="w-full py-2.5 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
          >
            {loading ? 'Verifying...' : 'Sign In'}
          </button>
        </form>

        <p className="text-xs text-slate-400 text-center mt-6">
          Default key: <code className="bg-slate-100 px-1.5 py-0.5 rounded text-xs">dev-api-key-change-in-production</code>
        </p>
      </div>
    </div>
  )
}
