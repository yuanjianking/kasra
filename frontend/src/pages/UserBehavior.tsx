import { useEffect, useState } from 'react'
import type { UserBehaviorItem } from '../api/client'
import { getUserBehavior } from '../api/client'

export default function UserBehavior() {
  const [items, setItems] = useState<UserBehaviorItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [userId, setUserId] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const pageSize = 20

  const fetchData = () => {
    setLoading(true)
    setError(null)
    getUserBehavior({ page, user_id: userId || undefined })
      .then((data) => { setItems(data.items); setTotal(data.total) })
      .catch((e) => { setError(e.message) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchData() }, [page, userId])

  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  const getAnomalyColor = (score: number) => {
    if (score >= 70) return 'text-red-600 font-bold'
    if (score >= 40) return 'text-amber-600'
    return 'text-slate-500'
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">User Behavior Analysis</h2>

      <div className="flex gap-3 mb-4">
        <input
          type="text"
          placeholder="Filter by user ID..."
          value={userId}
          onChange={(e) => { setUserId(e.target.value); setPage(1) }}
          className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white w-60"
        />
        <span className="text-sm text-slate-500 self-center ml-auto">{total} total records</span>
      </div>

      {error && <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg border border-red-200">Failed to load: {error}</div>}

      <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-500">Loading...</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                <th className="p-3 font-medium">User</th>
                <th className="p-3 font-medium">Date</th>
                <th className="p-3 font-medium">Total Requests</th>
                <th className="p-3 font-medium">Blocked</th>
                <th className="p-3 font-medium">Warned</th>
                <th className="p-3 font-medium">Anomaly Score</th>
                <th className="p-3 font-medium">Top Triggers</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={`${item.user_id}-${item.date}`} className="border-b border-slate-100 hover:bg-slate-50">
                  <td className="p-3 font-medium">{item.user_id}</td>
                  <td className="p-3 text-xs text-slate-500">{item.date}</td>
                  <td className="p-3">{item.total_requests}</td>
                  <td className="p-3 text-red-600">{item.blocked_requests}</td>
                  <td className="p-3 text-amber-600">{item.warned_requests}</td>
                  <td className={`p-3 ${getAnomalyColor(item.anomaly_score)}`}>{item.anomaly_score}</td>
                  <td className="p-3">
                    <div className="flex gap-1 flex-wrap">
                      {item.top_triggers.slice(0, 3).map(({ rule_id, count }) => (
                        <span key={rule_id} className="px-2 py-0.5 bg-slate-100 text-xs rounded-full">
                          {rule_id}: {count}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr><td colSpan={7} className="p-8 text-center text-slate-400">No data</td></tr>
              )}
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
