import { useEffect, useState } from 'react'
import type { AuditLogEntry } from '../api/client'
import { getAuditLogs } from '../api/client'

const SEVERITY_COLORS: Record<string, string> = {
  P0: 'bg-red-100 text-red-800',
  P1: 'bg-amber-100 text-amber-800',
  P2: 'bg-slate-100 text-slate-800',
}

const ACTION_COLORS: Record<string, string> = {
  block: 'bg-red-100 text-red-800',
  warn: 'bg-amber-100 text-amber-800',
  redact: 'bg-blue-100 text-blue-800',
}

export default function AuditLogs() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')
  const [direction, setDirection] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const pageSize = 15

  const fetchLogs = () => {
    setLoading(true)
    setError(null)
    getAuditLogs({ page, page_size: pageSize, severity: severity || undefined, direction: direction || undefined })
      .then((data) => { setLogs(data.items); setTotal(data.total) })
      .catch((e: Error) => { setError(e.message) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchLogs() }, [page, severity, direction])

  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Audit Logs</h2>

      {/* Filters */}
      <div className="flex gap-3 mb-4 flex-wrap">
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
        <select
          value={direction}
          onChange={(e) => { setDirection(e.target.value); setPage(1) }}
          className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white"
        >
          <option value="">All Directions</option>
          <option value="input">Input</option>
          <option value="output">Output</option>
          <option value="batch">Batch</option>
        </select>
        <span className="text-sm text-slate-500 self-center ml-auto">
          {total} total records
        </span>
      </div>

      {/* Error */}
      {error && <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg border border-red-200">Failed to load: {error}</div>}

      {/* Table */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-500">Loading...</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                <th className="p-3 font-medium">Time</th>
                <th className="p-3 font-medium">Rule</th>
                <th className="p-3 font-medium">Severity</th>
                <th className="p-3 font-medium">Action</th>
                <th className="p-3 font-medium">Direction</th>
                <th className="p-3 font-medium">User</th>
                <th className="p-3 font-medium">Matched</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className="border-b border-slate-100 hover:bg-slate-50">
                  <td className="p-3 text-xs text-slate-500 whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="p-3 font-medium">
                    <span className="text-xs">{log.rule_id}</span>
                    <div className="text-xs text-slate-500">{log.rule_name}</div>
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${SEVERITY_COLORS[log.severity] || ''}`}>
                      {log.severity}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${ACTION_COLORS[log.action] || ''}`}>
                      {log.action}
                    </span>
                  </td>
                  <td className="p-3 text-xs text-slate-500">{log.direction}</td>
                  <td className="p-3 text-xs text-slate-500">{log.user_id || '-'}</td>
                  <td className="p-3 text-xs text-slate-600 max-w-xs truncate">
                    {log.matched_text || '-'}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr><td colSpan={7} className="p-8 text-center text-slate-400">No data</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      <div className="flex justify-center items-center gap-2 mt-4">
        <button
          disabled={page <= 1}
          onClick={() => setPage(page - 1)}
          className="px-3 py-1 text-sm border rounded-lg disabled:opacity-30 hover:bg-slate-100"
        >
          Previous
        </button>
        <span className="text-sm text-slate-500">
          {page} / {totalPages}
        </span>
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
