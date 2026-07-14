import { useEffect, useState } from 'react'
import { getHealthDetail } from '../api/client'
import type { HealthDetail } from '../api/client'
import { ChartSkeleton, EmptyState } from '../components'

export default function Settings() {
  const [health, setHealth] = useState<HealthDetail | null>(null)
  const [totalRules, setTotalRules] = useState<number>(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [apiKey] = useState(() => typeof window !== 'undefined' ? localStorage.getItem('kasra_api_key') || '' : '')

  useEffect(() => {
    Promise.all([
      getHealthDetail(),
      fetch('/v1/rules?page_size=1', { headers: { 'X-API-Key': typeof window !== 'undefined' ? localStorage.getItem('kasra_api_key') || '' : '' } }).then(r => r.json()).then(d => d.total).catch(() => 0),
    ])
      .then(([h, total]) => { setHealth(h); setTotalRules(total) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div>
        <div className="h-8 bg-slate-200 rounded w-48 mb-6 animate-pulse" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ChartSkeleton height={200} />
          <ChartSkeleton height={200} />
        </div>
      </div>
    )
  }

  if (error) {
    return <EmptyState icon="⚠️" title="Failed to load settings" description={error} />
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Settings</h2>
          <p className="text-sm text-slate-400 mt-0.5">System configuration and status</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`inline-block w-2 h-2 rounded-full ${health?.status === 'healthy' ? 'bg-emerald-500' : 'bg-red-500'}`} />
          <span className="text-sm font-medium">{health?.status || 'unknown'}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* API Key */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
          <h3 className="text-sm font-semibold text-slate-700 mb-3">🔑 API Key</h3>
          <div className="text-xs text-slate-400 mb-2">Current API Key (masked)</div>
          <code className="block bg-slate-50 rounded-lg px-3 py-2 text-sm font-mono border border-slate-200 break-all">
            {apiKey.slice(0, 8)}...{apiKey.slice(-4)}
          </code>
          <p className="text-xs text-slate-400 mt-2">
            Configure via <code className="bg-slate-100 px-1 rounded text-[11px]">KASRA_API_KEY</code> environment variable.
          </p>
        </div>

        {/* Version */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
          <h3 className="text-sm font-semibold text-slate-700 mb-3">📦 Version</h3>
          <div className="text-2xl font-bold text-slate-800">{health?.version || '-'}</div>
          <div className="text-xs text-slate-400 mt-1">Kasra platform version</div>
        </div>

        {/* Database */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
          <h3 className="text-sm font-semibold text-slate-700 mb-3">🗄️ Database</h3>
          <div className="flex items-center gap-2 mb-2">
            <span className={`inline-block w-2 h-2 rounded-full ${health?.database?.status === 'healthy' ? 'bg-emerald-500' : 'bg-red-500'}`} />
            <span className="text-sm font-medium capitalize">{health?.database?.status || '-'}</span>
          </div>
          <div className="text-xs text-slate-500">
            <div>Type: {health?.database?.type || '-'}</div>
            <div className="mt-1 text-slate-400 text-[11px] break-all">{health?.database?.version || '-'}</div>
            {health?.database?.error && (
              <div className="mt-1 text-red-500">{health.database.error}</div>
            )}
          </div>
        </div>

        {/* HTTPS Proxy */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
          <h3 className="text-sm font-semibold text-slate-700 mb-3">🔒 HTTPS Proxy</h3>
          <div className="flex items-center gap-2 mb-2">
            <span className={`inline-block w-2 h-2 rounded-full ${health?.https_proxy?.enabled ? 'bg-emerald-500' : 'bg-slate-300'}`} />
            <span className="text-sm font-medium">{health?.https_proxy?.enabled ? 'Enabled' : 'Disabled'}</span>
          </div>
          {health?.https_proxy?.enabled && (
            <div className="text-xs text-slate-500">
              <div>Port: <code className="bg-slate-100 px-1 rounded">{health.https_proxy.port}</code></div>
              <div className="mt-1">TCP CONNECT tunnel for HTTPS inspection</div>
            </div>
          )}
        </div>

        {/* Rules */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
          <h3 className="text-sm font-semibold text-slate-700 mb-3">🛡️ Rules</h3>
          <div className="text-3xl font-bold text-slate-800">{health?.rules_total || totalRules || 0}</div>
          <div className="text-xs text-slate-400 mt-1">Total rules loaded</div>
          <div className="text-[11px] text-slate-400 mt-0.5">{health?.rules_loaded || 0} I/O detection + {health?.cr_rules_loaded || 0} code review</div>
        </div>

        {/* Audit */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
          <h3 className="text-sm font-semibold text-slate-700 mb-3">📝 Audit</h3>
          <div className="flex items-center gap-2">
            <span className={`inline-block w-2 h-2 rounded-full ${health?.audit_enabled ? 'bg-emerald-500' : 'bg-slate-300'}`} />
            <span className="text-sm font-medium">{health?.audit_enabled ? 'Enabled' : 'Disabled'}</span>
          </div>
          <div className="text-xs text-slate-400 mt-1">
            All detection events are logged to the audit trail
          </div>
        </div>
      </div>
    </div>
  )
}
