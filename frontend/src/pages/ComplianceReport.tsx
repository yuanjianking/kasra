import { useState, useEffect } from 'react'
import { getComplianceReport, exportAuditLogs } from '../api/client'
import type { ComplianceReport } from '../api/client'
import { ChartSkeleton, EmptyState, useToast } from '../components'

export default function ComplianceReportPage() {
  const { toast } = useToast()
  const [report, setReport] = useState<ComplianceReport | null>(null)
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo] = useState('')
  const [loading, setLoading] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchReport = () => {
    setLoading(true)
    setError(null)
    getComplianceReport(dateFrom || undefined, dateTo || undefined)
      .then(setReport)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchReport() }, [])

  const handleExport = async () => {
    setExporting(true)
    try {
      const csv = await exportAuditLogs({ page_size: 10000 })
      const blob = new Blob([csv], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `kasra-audit-export-${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
      toast('Export downloaded', 'success')
    } catch (e: any) {
      toast('Export failed: ' + e.message, 'error')
    }
    setExporting(false)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Compliance Report</h2>
          <p className="text-sm text-slate-400 mt-0.5">Audit summary for compliance review</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={fetchReport}
            disabled={loading}
            className="px-4 py-1.5 text-sm border border-slate-300 rounded-lg hover:bg-slate-50 transition-colors disabled:opacity-50"
          >
            {loading ? 'Refreshing...' : '🔄 Refresh'}
          </button>
          <button
            onClick={handleExport}
            disabled={exporting || !report}
            className="px-4 py-1.5 text-sm bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors"
          >
            {exporting ? 'Exporting...' : '⬇ Export CSV'}
          </button>
        </div>
      </div>

      <div className="flex gap-3 mb-4">
        <div>
          <label className="block text-xs text-slate-500 mb-1 font-medium">Date From</label>
          <input
            type="date"
            value={dateFrom}
            onChange={e => setDateFrom(e.target.value)}
            className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white"
          />
        </div>
        <div className="self-end">
          <button
            onClick={fetchReport}
            className="px-4 py-1.5 text-sm border border-slate-300 rounded-lg hover:bg-slate-50 transition-colors"
          >
            Apply
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg border border-red-200 text-sm">{error}</div>
      )}

      {loading ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ChartSkeleton height={200} />
          <ChartSkeleton height={200} />
          <div className="lg:col-span-2"><ChartSkeleton height={300} /></div>
        </div>
      ) : !report ? (
        <EmptyState icon="📋" title="No report data" description="Run some security detections first." />
      ) : (
        <>
          {/* Date range */}
          <div className="text-sm text-slate-400 mb-4">
            Report period: <span className="font-medium">{new Date(report.date_range.start).toLocaleDateString()}</span> — <span className="font-medium">{new Date(report.date_range.end).toLocaleDateString()}</span>
            · Generated {new Date(report.generated_at).toLocaleString()}
          </div>

          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <SummaryCard label="Total Events" value={report.total_events} icon="📊" color="text-indigo-600" bg="bg-indigo-50" />
            <SummaryCard label="Blocked" value={report.total_blocked} icon="🚫" color="text-red-600" bg="bg-red-50" />
            <SummaryCard label="Warnings" value={report.total_warnings} icon="⚠️" color="text-amber-600" bg="bg-amber-50" />
            <SummaryCard label="Unique Rules" value={report.unique_rules} icon="🛡️" color="text-purple-600" bg="bg-purple-50" />
          </div>

          {/* Severity breakdown */}
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="bg-rose-50 rounded-xl p-4 border border-rose-200">
              <div className="text-xs text-rose-600 font-medium">P0 (Critical)</div>
              <div className="text-3xl font-bold text-rose-700 mt-1">{report.p0_count}</div>
            </div>
            <div className="bg-amber-50 rounded-xl p-4 border border-amber-200">
              <div className="text-xs text-amber-600 font-medium">P1 (High)</div>
              <div className="text-3xl font-bold text-amber-700 mt-1">{report.p1_count}</div>
            </div>
            <div className="bg-slate-50 rounded-xl p-4 border border-slate-200">
              <div className="text-xs text-slate-600 font-medium">P2 (Medium)</div>
              <div className="text-3xl font-bold text-slate-700 mt-1">{report.p2_count}</div>
            </div>
          </div>

          {/* Users & Rules stats */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
              <h3 className="text-sm font-semibold text-slate-700 mb-3">Coverage</h3>
              <div className="text-2xl font-bold text-slate-800">{report.unique_users}</div>
              <div className="text-xs text-slate-400">Unique users detected</div>
              <div className="mt-3 text-2xl font-bold text-slate-800">{report.unique_rules}</div>
              <div className="text-xs text-slate-400">Unique rules triggered</div>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
              <h3 className="text-sm font-semibold text-slate-700 mb-3">Block Rate</h3>
              <div className="text-4xl font-bold text-slate-800">
                {report.total_events > 0 ? Math.round((report.total_blocked / report.total_events) * 100) : 0}%
              </div>
              <div className="text-xs text-slate-400">
                {report.total_blocked} blocked out of {report.total_events} total events
              </div>
            </div>
          </div>

          {/* Top Rules */}
          <div className="bg-white rounded-xl shadow-sm border border-slate-200">
            <div className="px-5 py-4 border-b border-slate-100">
              <h3 className="text-sm font-semibold text-slate-700">Top Triggered Rules</h3>
            </div>
            {report.top_rules.length > 0 ? (
              <div className="divide-y divide-slate-100">
                {report.top_rules.map((r, i) => {
                  const maxCount = report.top_rules[0].count
                  const pct = (r.count / maxCount) * 100
                  return (
                    <div key={r.rule_id} className="px-5 py-3 flex items-center gap-4">
                      <span className="text-xs text-slate-400 w-6">{i + 1}.</span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-medium text-slate-700">{r.rule_id}</span>
                          <span className="text-xs text-slate-400">{r.rule_name}</span>
                        </div>
                        <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                          <div className="h-full bg-indigo-500 rounded-full" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                      <span className="text-sm font-semibold text-slate-700">{r.count}</span>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="px-5 py-8 text-center text-slate-400 text-sm">No rules triggered</div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function SummaryCard({ label, value, icon, color, bg }: { label: string; value: number; icon: string; color: string; bg: string }) {
  return (
    <div className={`${bg} rounded-xl p-4 border border-slate-200/60`}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-slate-500 font-medium">{label}</span>
        <span>{icon}</span>
      </div>
      <div className={`text-3xl font-bold ${color}`}>{value}</div>
    </div>
  )
}
