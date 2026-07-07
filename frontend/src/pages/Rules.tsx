import { useEffect, useState, useCallback } from 'react'
import type { RuleItem } from '../api/client'
import { getRules, updateRule } from '../api/client'

const SEV_COLORS: Record<string, string> = {
  P0: 'bg-red-100 text-red-800',
  P1: 'bg-amber-100 text-amber-800',
  P2: 'bg-slate-100 text-slate-800',
}

export default function Rules() {
  const [rules, setRules] = useState<RuleItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')
  const [loading, setLoading] = useState(true)
  const [toggling, setToggling] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const pageSize = 20

  const fetchRules = useCallback(() => {
    setLoading(true)
    setError(null)
    getRules({ page, page_size: pageSize, severity: severity || undefined })
      .then((data) => { setRules(data.items); setTotal(data.total) })
      .catch((e) => { setError(e.message) })
      .finally(() => setLoading(false))
  }, [page, pageSize, severity])

  useEffect(() => { fetchRules() }, [fetchRules])

  const handleToggle = async (ruleId: string, currentEnabled: boolean) => {
    setToggling(ruleId)
    // Optimistic update
    setRules(rules.map(r => r.id === ruleId ? { ...r, enabled: !currentEnabled } : r))
    try {
      await updateRule(ruleId, { enabled: !currentEnabled })
    } catch (e) {
      // Revert on failure
      setRules(rules.map(r => r.id === ruleId ? { ...r, enabled: currentEnabled } : r))
      setError(`Failed to update rule ${ruleId}`)
    }
    setToggling(null)
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Rule Management</h2>

      <div className="flex gap-3 mb-4">
        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
          className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white"
        >
          <option value="">All Severities</option>
          <option value="P0">P0 - Critical</option>
          <option value="P1">P1 - High</option>
          <option value="P2">P2 - Medium</option>
        </select>
        <span className="text-sm text-slate-500 self-center">{total} total rules</span>
      </div>

      {error && <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg border border-red-200">Failed to load: {error}</div>}

      <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-500">Loading...</div>
        ) : rules.length === 0 ? (
          <div className="p-8 text-center text-slate-400">No data</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                <th className="p-3 font-medium">ID</th>
                <th className="p-3 font-medium">Name</th>
                <th className="p-3 font-medium">Severity</th>
                <th className="p-3 font-medium">Action</th>
                <th className="p-3 font-medium">Category</th>
                <th className="p-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} className="border-b border-slate-100 hover:bg-slate-50">
                  <td className="p-3 font-mono text-xs">{rule.id}</td>
                  <td className="p-3">
                    {rule.name}
                    {rule.is_custom && <span className="ml-2 text-xs text-indigo-600">(custom)</span>}
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${SEV_COLORS[rule.severity] || ''}`}>
                      {rule.severity}
                    </span>
                  </td>
                  <td className="p-3 text-xs text-slate-500">{rule.action}</td>
                  <td className="p-3 text-xs text-slate-500">
                    {rule.category || '-'}
                  </td>
                  <td className="p-3">
                    <button
                      onClick={() => handleToggle(rule.id, rule.enabled)}
                      disabled={toggling === rule.id}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                        rule.enabled ? 'bg-indigo-600' : 'bg-slate-300'
                      }`}
                    >
                      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                        rule.enabled ? 'translate-x-[18px]' : 'translate-x-1'
                      }`} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="flex justify-center items-center gap-2 mt-4">
        <button
          disabled={page <= 1}
          onClick={() => setPage(page - 1)}
          className="px-3 py-1 text-sm border rounded-lg disabled:opacity-30 hover:bg-slate-100"
        >
          Previous
        </button>
        <span className="text-sm text-slate-500">{page} / {totalPages}</span>
        <button
          disabled={page >= totalPages}
          onClick={() => setPage(page + 1)}
          className="px-3 py-1 text-sm border rounded-lg disabled:opacity-30 hover:bg-slate-100"
        >
          Next
        </button>
      </div>
    </div>
  )
}
