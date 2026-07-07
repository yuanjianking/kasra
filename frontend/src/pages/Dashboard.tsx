import { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, Legend,
} from 'recharts'
import type { DashboardSummary, DashboardTrend } from '../api/client'
import { getDashboardSummary, getDashboardTrend } from '../api/client'

export default function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [trend, setTrend] = useState<DashboardTrend | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([getDashboardSummary(), getDashboardTrend('7d')])
      .then(([s, t]) => { setSummary(s); setTrend(t) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="text-center py-12 text-slate-500">Loading...</div>
  if (error) return <div className="text-center py-12 text-red-500">Failed to load: {error}</div>
  if (!summary) return null

  const statCards = [
    { label: '24h Requests', value: summary.total_requests_24h, color: 'bg-indigo-500' },
    { label: 'Blocked', value: summary.blocked_count_24h, color: 'bg-red-500' },
    { label: 'Warned', value: summary.warning_count_24h, color: 'bg-amber-500' },
    { label: 'Block Rate', value: `${summary.block_rate_percent}%`, color: 'bg-slate-600' },
    { label: 'Active Users', value: summary.total_users_active_24h, color: 'bg-emerald-500' },
    { label: 'P0 Alerts', value: summary.p0_triggers_24h, color: 'bg-rose-600' },
  ]

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Dashboard</h2>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
        {statCards.map(({ label, value, color }) => (
          <div key={label} className="bg-white rounded-xl shadow-sm p-4 border border-slate-200">
            <div className={`w-2 h-8 rounded ${color} mb-2`} />
            <div className="text-2xl font-bold text-slate-800">{value}</div>
            <div className="text-xs text-slate-500 mt-1">{label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Trend Chart */}
        <div className="bg-white rounded-xl shadow-sm p-4 border border-slate-200">
          <h3 className="text-sm font-semibold text-slate-700 mb-4">7-Day Trend</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={trend?.data || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="date" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="total" stroke="#6366f1" name="Total" strokeWidth={2} />
              <Line type="monotone" dataKey="blocked" stroke="#ef4444" name="Blocked" strokeWidth={2} />
              <Line type="monotone" dataKey="warned" stroke="#f59e0b" name="Warned" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Top Rules */}
        <div className="bg-white rounded-xl shadow-sm p-4 border border-slate-200">
          <h3 className="text-sm font-semibold text-slate-700 mb-4">Top Triggered Rules</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={summary.top_triggered_rules.slice(0, 8)} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis type="number" tick={{ fontSize: 12 }} />
              <YAxis dataKey="rule_id" type="category" width={50} tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="count" fill="#6366f1" name="Trigger Count" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top Users */}
      <div className="bg-white rounded-xl shadow-sm p-4 border border-slate-200">
        <h3 className="text-sm font-semibold text-slate-700 mb-4">Top Users</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-left text-slate-500">
                <th className="pb-2 font-medium">User</th>
                <th className="pb-2 font-medium">Requests</th>
                <th className="pb-2 font-medium">Blocks</th>
              </tr>
            </thead>
            <tbody>
              {summary.top_users.map((u) => (
                <tr key={u.user_id} className="border-b border-slate-100">
                  <td className="py-2">{u.user_id}</td>
                  <td className="py-2">{u.requests}</td>
                  <td className="py-2 text-red-600">{u.blocks}</td>
                </tr>
              ))}
              {summary.top_users.length === 0 && (
                <tr><td colSpan={3} className="py-4 text-center text-slate-400">No data</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
