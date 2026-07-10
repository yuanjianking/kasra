import { useEffect, useState } from 'react'
import type { AuditLogEntry } from '../api/client'
import { getAuditLogs } from '../api/client'
import { Badge, SlideOver, TableSkeleton, EmptyState, Pagination } from '../components'

const SEVERITY_OPTIONS = ['P0', 'P1', 'P2'] as const
const DIRECTION_OPTIONS = ['input', 'output', 'batch', 'behavior'] as const
const PAGE_SIZE = 15

export default function AuditLogs() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')
  const [direction, setDirection] = useState('')
  const [search, setSearch] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null)

  const fetchLogs = () => {
    setLoading(true)
    setError(null)
    getAuditLogs({
      page,
      page_size: PAGE_SIZE,
      severity: severity || undefined,
      direction: direction || undefined,
      user_id: search || undefined,
      start_time: dateFrom || undefined,
      end_time: dateTo || undefined,
    })
      .then((data) => { setLogs(data.items); setTotal(data.total) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchLogs() }, [page, severity, direction, search, dateFrom, dateTo])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const handleSearchChange = (val: string) => {
    setSearch(val)
    setPage(1)
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Audit Logs</h2>
          <p className="text-sm text-slate-400 mt-0.5">Security event history with filters and detail inspection</p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4 mb-4">
        <div className="flex flex-wrap gap-3 items-end">
          {/* Search */}
          <div className="flex-1 min-w-[180px]">
            <label className="block text-xs text-slate-500 mb-1 font-medium">Search User</label>
            <input
              type="text"
              placeholder="Filter by user ID..."
              value={search}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
          </div>

          {/* Severity */}
          <div>
            <label className="block text-xs text-slate-500 mb-1 font-medium">Severity</label>
            <select
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
              className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="">All Severities</option>
              {SEVERITY_OPTIONS.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          {/* Direction */}
          <div>
            <label className="block text-xs text-slate-500 mb-1 font-medium">Direction</label>
            <select
              value={direction}
              onChange={(e) => { setDirection(e.target.value); setPage(1) }}
              className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="">All Directions</option>
              {DIRECTION_OPTIONS.map(d => (
                <option key={d} value={d}>{d}</option>
              ))}
            </select>
          </div>

          {/* Date From */}
          <div>
            <label className="block text-xs text-slate-500 mb-1 font-medium">From</label>
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => { setDateFrom(e.target.value); setPage(1) }}
              className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          {/* Date To */}
          <div>
            <label className="block text-xs text-slate-500 mb-1 font-medium">To</label>
            <input
              type="date"
              value={dateTo}
              onChange={(e) => { setDateTo(e.target.value); setPage(1) }}
              className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          {/* Clear */}
          {(search || severity || direction || dateFrom || dateTo) && (
            <button
              onClick={() => { setSearch(''); setSeverity(''); setDirection(''); setDateFrom(''); setDateTo(''); setPage(1) }}
              className="px-3 py-1.5 text-sm border border-slate-300 rounded-lg hover:bg-slate-50 transition-colors"
            >
              Clear All
            </button>
          )}
        </div>
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
      ) : logs.length === 0 ? (
        <EmptyState
          icon="📋"
          title="No audit logs found"
          description={search || severity || direction || dateFrom || dateTo ? 'Try adjusting your filters.' : 'No security events have been recorded yet.'}
        />
      ) : (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                <th className="p-3 pl-5 font-medium text-xs uppercase tracking-wider">Time</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Rule</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Severity</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Action</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Direction</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">User</th>
                <th className="p-3 pr-5 font-medium text-xs uppercase tracking-wider">Matched</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr
                  key={log.id}
                  className="border-b border-slate-100 hover:bg-indigo-50/30 transition-colors cursor-pointer"
                  onClick={() => setSelectedLog(log)}
                >
                  <td className="p-3 pl-5 text-xs text-slate-500 whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="p-3 font-medium">
                    <span className="text-xs">{log.rule_id}</span>
                    <div className="text-xs text-slate-400">{log.rule_name}</div>
                  </td>
                  <td className="p-3">
                    <Badge>{log.severity}</Badge>
                  </td>
                  <td className="p-3">
                    <Badge>{log.action}</Badge>
                  </td>
                  <td className="p-3">
                    <span className="text-xs text-slate-500 capitalize">{log.direction}</span>
                  </td>
                  <td className="p-3 text-xs text-slate-500">{log.user_id || '-'}</td>
                  <td className="p-3 pr-5 text-xs text-slate-600 max-w-[200px] truncate">
                    {log.matched_text || '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {total > 0 && (
        <Pagination
          page={page}
          totalPages={totalPages}
          total={total}
          pageSize={PAGE_SIZE}
          onChange={setPage}
        />
      )}

      {/* Detail SlideOver */}
      <SlideOver open={!!selectedLog} onClose={() => setSelectedLog(null)} title="Audit Log Detail">
        {selectedLog && (
          <div className="space-y-5">
            <div className="flex items-center gap-2">
              <Badge>{selectedLog.severity}</Badge>
              <Badge>{selectedLog.action}</Badge>
              <span className="text-xs text-slate-400 capitalize">{selectedLog.direction}</span>
            </div>

            <Section label="Rule">
              <p className="text-sm font-medium">{selectedLog.rule_id} — {selectedLog.rule_name}</p>
            </Section>

            <Section label="User">
              <p className="text-sm">{selectedLog.user_id || '-'}</p>
            </Section>

            <Section label="Timestamp">
              <p className="text-sm">{new Date(selectedLog.timestamp).toLocaleString()}</p>
            </Section>

            <Section label="Status">
              <p className="text-sm capitalize">{selectedLog.status}</p>
            </Section>

            <Section label="Match Count">
              <p className="text-sm">{selectedLog.match_count}</p>
            </Section>

            {selectedLog.matched_text && (
              <Section label="Matched Content">
                <pre className="text-sm bg-slate-50 rounded-lg p-3 border border-slate-200 overflow-x-auto whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                  {selectedLog.matched_text}
                </pre>
              </Section>
            )}

            {selectedLog.file_path && (
              <Section label="File Path">
                <code className="text-sm">{selectedLog.file_path}</code>
              </Section>
            )}

            {selectedLog.metadata && (
              <Section label="Metadata">
                <pre className="text-xs bg-slate-50 rounded-lg p-3 border border-slate-200 overflow-x-auto max-h-40">
                  {JSON.stringify(selectedLog.metadata, null, 2)}
                </pre>
              </Section>
            )}
          </div>
        )}
      </SlideOver>
    </div>
  )
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs text-slate-400 font-medium uppercase tracking-wider mb-1">{label}</div>
      {children}
    </div>
  )
}
