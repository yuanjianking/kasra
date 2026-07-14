import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Line, Legend, Area, AreaChart } from 'recharts'
import type { DashboardSummary, DashboardTrend } from '../api/client'
import { getDashboardSummary, getDashboardTrend } from '../api/client'
import { CardSkeleton, ChartSkeleton, EmptyState } from '../components'

type Period = '24h' | '7d' | '30d'

export default function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [trend, setTrend] = useState<DashboardTrend | null>(null)
  const [period, setPeriod] = useState<Period>('24h')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    setError(null)
    const trendPeriod = period === '24h' ? '7d' : period
    Promise.all([getDashboardSummary(), getDashboardTrend(trendPeriod)])
      .then(([s, t]) => { setSummary(s); setTrend(t) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [period])

  if (loading) {
    return (
      <div>
        <div className="h-8 bg-slate-200 rounded w-64 mb-6 animate-pulse" />
        <CardSkeleton />
        <div className="mt-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ChartSkeleton />
          <ChartSkeleton />
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <EmptyState
        icon="⚠️"
        title="Failed to load dashboard"
        description={error}
        action={{ label: 'Retry', onClick: () => window.location.reload() }}
      />
    )
  }

  if (!summary) return null

  const totalEvents = summary.total_requests_24h
  const blockRate = summary.block_rate_percent
  const activeUsers = summary.total_users_active_24h
  const p0Count = summary.p0_triggers_24h

  const statCards = [
    {
      label: 'Total Requests',
      value: totalEvents,
      sub: 'past 24 hours',
      icon: '📊',
      color: 'from-indigo-500 to-indigo-600',
      bg: 'bg-indigo-50',
    },
    {
      label: 'Blocked',
      value: summary.blocked_count_24h,
      sub: `${blockRate}% of total`,
      icon: '🚫',
      color: 'from-red-500 to-red-600',
      bg: 'bg-red-50',
    },
    {
      label: 'Warnings',
      value: summary.warning_count_24h,
      sub: 'needs review',
      icon: '⚠️',
      color: 'from-amber-500 to-amber-600',
      bg: 'bg-amber-50',
    },
    {
      label: 'Block Rate',
      value: `${blockRate}%`,
      icon: '🎯',
      sub: blockRate > 50 ? 'elevated' : 'normal',
      color: blockRate > 50 ? 'from-rose-500 to-rose-600' : 'from-emerald-500 to-emerald-600',
      bg: blockRate > 50 ? 'bg-rose-50' : 'bg-emerald-50',
    },
    {
      label: 'Active Users',
      value: activeUsers,
      sub: 'unique users',
      icon: '👥',
      color: 'from-purple-500 to-purple-600',
      bg: 'bg-purple-50',
    },
    {
      label: 'P0 Alerts',
      value: p0Count,
      sub: p0Count > 0 ? 'critical severity' : 'no critical alerts',
      icon: '🔴',
      color: 'from-rose-600 to-rose-700',
      bg: 'bg-rose-50',
    },
  ]

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Dashboard</h2>
          <p className="text-sm text-slate-400 mt-0.5">
            Security analytics overview — {new Date().toLocaleString()}
          </p>
        </div>
        <div className="flex gap-1 bg-slate-100 p-0.5 rounded-lg">
          {(['24h', '7d', '30d'] as Period[]).map(p => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-3 py-1.5 text-sm rounded-md font-medium transition-colors ${
                period === p ? 'bg-white text-slate-800 shadow-sm' : 'text-slate-500 hover:text-slate-700'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {totalEvents === 0 ? (
        <EmptyState
          icon="📈"
          title="No detection events yet"
          description="Run some security scans to see your dashboard data populate here."
        />
      ) : (
        <>
          {/* Summary line */}
          <div className="mb-4 text-sm text-slate-500">
            {totalEvents} events detected · <span className="text-red-600 font-medium">{summary.blocked_count_24h}</span> blocked ·{' '}
            <span className="text-amber-600 font-medium">{summary.warning_count_24h}</span> warned ·{' '}
            <span className="text-indigo-600 font-medium">{activeUsers}</span> active users
          </div>

          {/* Stat Cards */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
            {statCards.map(({ label, value, sub, icon, color, bg }) => (
              <div key={label} className={`${bg} rounded-xl p-4 border border-slate-200/60 relative overflow-hidden group hover:shadow-md transition-shadow`}>
                <div className={`absolute top-0 right-0 w-16 h-16 -mr-6 -mt-6 rounded-full bg-gradient-to-br ${color} opacity-10 group-hover:opacity-20 transition-opacity`} />
                <div className="text-xl mb-2">{icon}</div>
                <div className="text-2xl font-bold text-slate-800">{value}</div>
                <div className="text-xs text-slate-500 mt-0.5">{sub}</div>
              </div>
            ))}
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            {/* Trend Chart */}
            <div className="bg-white rounded-xl shadow-sm p-5 border border-slate-200">
              <h3 className="text-sm font-semibold text-slate-700 mb-1">Detection Trend</h3>
              <p className="text-xs text-slate-400 mb-4">Daily event count over time</p>
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={trend?.data || []}>
                  <defs>
                    <linearGradient id="totalGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.15} />
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.15} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="date" tick={{ fontSize: 11 }} stroke="#94a3b8" />
                  <YAxis tick={{ fontSize: 11 }} stroke="#94a3b8" />
                  <Tooltip
                    contentStyle={{ borderRadius: '8px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}
                  />
                  <Legend />
                  <Area type="monotone" dataKey="total" stroke="#6366f1" fill="url(#totalGrad)" name="Total" strokeWidth={2} />
                  <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="url(#blockedGrad)" name="Blocked" strokeWidth={2} />
                  <Line type="monotone" dataKey="warned" stroke="#f59e0b" name="Warned" strokeWidth={2} dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Top Rules */}
            <div className="bg-white rounded-xl shadow-sm p-5 border border-slate-200">
              <h3 className="text-sm font-semibold text-slate-700 mb-1">Top Triggered Rules</h3>
              <p className="text-xs text-slate-400 mb-4">Most frequently triggered security rules</p>
              {(summary.top_triggered_rules || []).length > 0 ? (
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={summary.top_triggered_rules.slice(0, 8)} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={false} />
                    <XAxis type="number" domain={[0, 'dataMax']} ticks={(() => { const m = Math.max(...summary.top_triggered_rules.slice(0, 8).map(r => r.count), 1); return Array.from({length: m + 1}, (_, i) => i); })()} tick={{ fontSize: 11 }} stroke="#94a3b8" />
                    <YAxis dataKey="rule_id" type="category" width={80} tick={{ fontSize: 11 }} stroke="#94a3b8" />
                    <Tooltip
                      contentStyle={{ borderRadius: '8px', border: '1px solid #e2e8f0' }}
                    />
                    <Bar dataKey="count" fill="#6366f1" name="Trigger Count" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[260px] flex items-center justify-center text-slate-400 text-sm">No rule trigger data yet</div>
              )}
            </div>
          </div>

          {/* Top Users Table */}
          <div className="bg-white rounded-xl shadow-sm border border-slate-200">
            <div className="px-5 py-4 border-b border-slate-100">
              <h3 className="text-sm font-semibold text-slate-700">Top Users</h3>
            </div>
            {(summary.top_users || []).length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 text-left text-slate-500">
                      <th className="px-5 py-3 font-medium text-xs uppercase tracking-wider">User</th>
                      <th className="px-5 py-3 font-medium text-xs uppercase tracking-wider">Requests</th>
                      <th className="px-5 py-3 font-medium text-xs uppercase tracking-wider">Blocks</th>
                      <th className="px-5 py-3 font-medium text-xs uppercase tracking-wider">Block Rate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.top_users.map((u) => {
                      const rate = u.requests > 0 ? Math.round((u.blocks / u.requests) * 100) : 0
                      return (
                        <tr key={u.user_id} className="border-b border-slate-50 hover:bg-slate-50 transition-colors">
                          <td className="px-5 py-3 font-medium text-slate-700">{u.user_id}</td>
                          <td className="px-5 py-3">{u.requests}</td>
                          <td className="px-5 py-3">
                            <span className={u.blocks > 10 ? 'text-red-600 font-medium' : 'text-slate-600'}>{u.blocks}</span>
                          </td>
                          <td className="px-5 py-3">
                            <div className="flex items-center gap-2">
                              <div className="w-20 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${rate > 50 ? 'bg-red-500' : rate > 20 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                                  style={{ width: `${Math.min(rate, 100)}%` }}
                                />
                              </div>
                              <span className="text-xs text-slate-400">{rate}%</span>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="px-5 py-8 text-center text-slate-400 text-sm">No user data yet</div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
