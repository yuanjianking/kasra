import { useEffect, useState, useMemo } from 'react'
import type { UserBehaviorItem } from '../api/client'
import { getUserBehavior } from '../api/client'
import { TableSkeleton, EmptyState, Pagination } from '../components'

function getRiskLevel(score: number): { level: string; color: string; bg: string } {
  if (score >= 70) return { level: 'High Risk', color: 'text-red-600', bg: 'bg-red-50 border-red-200' }
  if (score >= 40) return { level: 'Medium Risk', color: 'text-amber-600', bg: 'bg-amber-50 border-amber-200' }
  return { level: 'Low Risk', color: 'text-emerald-600', bg: 'bg-emerald-50 border-emerald-200' }
}

const PAGE_SIZE = 20
const RISK_LEVELS = ['all', 'high', 'medium', 'low'] as const
type RiskFilter = (typeof RISK_LEVELS)[number]

export default function UserBehavior() {
  const [items, setItems] = useState<UserBehaviorItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [userId, setUserId] = useState('')
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchData = () => {
    setLoading(true)
    setError(null)
    getUserBehavior({ page, user_id: userId || undefined })
      .then((data) => { setItems(data.items); setTotal(data.total) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchData() }, [page, userId])

  // Compute summary stats
  const stats = useMemo(() => {
    const filtered = riskFilter === 'all' ? items : items.filter(item => {
      const { level } = getRiskLevel(item.anomaly_score)
      if (riskFilter === 'high') return level === 'High Risk'
      if (riskFilter === 'medium') return level === 'Medium Risk'
      return level === 'Low Risk'
    })

    const high = items.filter(i => getRiskLevel(i.anomaly_score).level === 'High Risk').length
    const medium = items.filter(i => getRiskLevel(i.anomaly_score).level === 'Medium Risk').length
    const low = items.filter(i => getRiskLevel(i.anomaly_score).level === 'Low Risk').length
    const totalBlocked = items.reduce((acc, i) => acc + i.blocked_requests, 0)
    const totalRequests = items.reduce((acc, i) => acc + i.total_requests, 0)

    return { filtered, high, medium, low, totalBlocked, totalRequests }
  }, [items, riskFilter])

  const filteredCount = riskFilter === 'all' ? total : stats.filtered.length
  const totalPages = Math.max(1, Math.ceil(filteredCount / PAGE_SIZE))

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">User Behavior Analysis</h2>
          <p className="text-sm text-slate-400 mt-0.5">Monitor user risk levels and activity patterns</p>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <SummaryCard label="High Risk" value={stats.high} color="text-red-600" bg="bg-red-50" icon="🔴" />
        <SummaryCard label="Medium Risk" value={stats.medium} color="text-amber-600" bg="bg-amber-50" icon="🟡" />
        <SummaryCard label="Low Risk" value={stats.low} color="text-emerald-600" bg="bg-emerald-50" icon="🟢" />
        <SummaryCard
          label="Block Rate"
          value={stats.totalRequests > 0 ? `${Math.round((stats.totalBlocked / stats.totalRequests) * 100)}%` : '0%'}
          color="text-slate-600"
          bg="bg-slate-50"
          icon="📊"
        />
      </div>

      {/* Risk distribution bar */}
      {items.length > 0 && (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4 mb-4">
          <div className="text-xs text-slate-500 font-medium mb-2">Risk Distribution</div>
          <div className="flex h-3 rounded-full overflow-hidden bg-slate-100">
            {stats.high > 0 && (
              <div
                className="bg-red-500 transition-all duration-500"
                style={{ width: `${(stats.high / items.length) * 100}%` }}
                title={`High: ${stats.high}`}
              />
            )}
            {stats.medium > 0 && (
              <div
                className="bg-amber-500 transition-all duration-500"
                style={{ width: `${(stats.medium / items.length) * 100}%` }}
                title={`Medium: ${stats.medium}`}
              />
            )}
            {stats.low > 0 && (
              <div
                className="bg-emerald-500 transition-all duration-500"
                style={{ width: `${(stats.low / items.length) * 100}%` }}
                title={`Low: ${stats.low}`}
              />
            )}
          </div>
          <div className="flex gap-4 mt-1.5 text-xs text-slate-400">
            <span><span className="inline-block w-2 h-2 rounded-full bg-red-500 mr-1" /> High: {stats.high}</span>
            <span><span className="inline-block w-2 h-2 rounded-full bg-amber-500 mr-1" /> Medium: {stats.medium}</span>
            <span><span className="inline-block w-2 h-2 rounded-full bg-emerald-500 mr-1" /> Low: {stats.low}</span>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-4 items-center">
        <input
          type="text"
          placeholder="Search user ID..."
          value={userId}
          onChange={(e) => { setUserId(e.target.value); setPage(1) }}
          className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white w-60 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
        />

        <div className="flex gap-1 bg-slate-100 p-0.5 rounded-lg">
          {RISK_LEVELS.map(r => (
            <button
              key={r}
              onClick={() => setRiskFilter(r)}
              className={`px-3 py-1 text-sm rounded-md font-medium capitalize transition-colors ${
                riskFilter === r ? 'bg-white text-slate-800 shadow-sm' : 'text-slate-500 hover:text-slate-700'
              }`}
            >
              {r}
            </button>
          ))}
        </div>

        <span className="text-sm text-slate-400 ml-auto">{filteredCount} records</span>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg border border-red-200 text-sm">
          Failed to load: {error}
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4">
          <TableSkeleton rows={8} cols={7} />
        </div>
      ) : stats.filtered.length === 0 ? (
        <EmptyState
          icon="👤"
          title="No user behavior data"
          description={userId ? 'No users match the current search.' : riskFilter !== 'all' ? `No ${riskFilter} risk users found.` : 'Run some security detections to see user behavior here.'}
        />
      ) : (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                <th className="p-3 pl-5 font-medium text-xs uppercase tracking-wider">User</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Date</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Requests</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Blocked</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Warned</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Risk Score</th>
                <th className="p-3 pr-5 font-medium text-xs uppercase tracking-wider">Top Triggers</th>
              </tr>
            </thead>
            <tbody>
              {stats.filtered.map((item) => {
                const { level, color, bg } = getRiskLevel(item.anomaly_score)
                const blockRate = item.total_requests > 0 ? Math.round((item.blocked_requests / item.total_requests) * 100) : 0
                return (
                  <tr key={`${item.user_id}-${item.date}`} className={`border-b border-slate-100 hover:bg-slate-50 transition-colors`}>
                    <td className="p-3 pl-5 font-medium text-slate-700">{item.user_id}</td>
                    <td className="p-3 text-xs text-slate-500">{item.date}</td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <span>{item.total_requests}</span>
                        <div className="w-12 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-indigo-500 rounded-full"
                            style={{ width: `${Math.min(blockRate, 100)}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="p-3">
                      <span className={item.blocked_requests > 0 ? 'text-red-600 font-medium' : ''}>
                        {item.blocked_requests}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={item.warned_requests > 0 ? 'text-amber-600' : ''}>
                        {item.warned_requests}
                      </span>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <div className={`px-2 py-0.5 rounded-full text-xs font-medium ${bg} ${color}`}>
                          {item.anomaly_score}
                        </div>
                        <span className="text-xs text-slate-400">{level}</span>
                      </div>
                    </td>
                    <td className="p-3 pr-5">
                      <div className="flex gap-1 flex-wrap">
                        {item.top_triggers.slice(0, 3).map(({ rule_id, count }) => (
                          <span key={rule_id} className="px-2 py-0.5 bg-slate-100 text-xs rounded-full text-slate-600">
                            {rule_id}: {count}
                          </span>
                        ))}
                        {item.top_triggers.length > 3 && (
                          <span className="text-xs text-slate-400">+{item.top_triggers.length - 3}</span>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {filteredCount > 0 && (
        <Pagination
          page={page}
          totalPages={totalPages}
          total={filteredCount}
          pageSize={PAGE_SIZE}
          onChange={setPage}
        />
      )}
    </div>
  )
}

function SummaryCard({ label, value, color, bg, icon }: {
  label: string; value: string | number; color: string; bg: string; icon: string
}) {
  return (
    <div className={`${bg} rounded-xl p-4 border border-slate-200/60`}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-slate-500 font-medium">{label}</span>
        <span>{icon}</span>
      </div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
    </div>
  )
}
