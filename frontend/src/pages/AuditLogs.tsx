import { useEffect, useState, useCallback } from 'react'
import type { AuditLogEntry } from '../api/client'
import { getAuditLogs, updateAuditLogStatus } from '../api/client'
import { Badge, SlideOver, TableSkeleton, EmptyState, Pagination, useToast } from '../components'

const SEVERITY_OPTIONS = ['P0', 'P1', 'P2'] as const
const DIRECTION_OPTIONS = ['input', 'output', 'batch', 'behavior'] as const
const STATUS_OPTIONS = ['', 'pending', 'resolved', 'fp'] as const
const PAGE_SIZE = 15

const STATUS_BADGE: Record<string, string> = {
  pending: 'bg-slate-100 text-slate-600',
  resolved: 'bg-emerald-100 text-emerald-700',
  fp: 'bg-amber-100 text-amber-700',
}

export default function AuditLogs() {
  const { toast } = useToast()
  const [logs, setLogs] = useState<AuditLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')
  const [direction, setDirection] = useState('')
  const [search, setSearch] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [status, setStatus] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())

  const fetchLogs = useCallback(() => {
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
      status: status || undefined,
    })
      .then((data) => { setLogs(data.items); setTotal(data.total); setSelectedIds(new Set()) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [page, severity, direction, search, dateFrom, dateTo, status])

  useEffect(() => { fetchLogs() }, [fetchLogs])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const handleStatusChange = async (logId: number, newStatus: string) => {
    try {
      await updateAuditLogStatus(logId, newStatus)
      toast(`Marked as ${newStatus}`, 'success')
      fetchLogs()
    } catch { toast('Failed to update status', 'error') }
  }

  const toggleSelect = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selectedIds.size === logs.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(logs.map(l => l.id)))
    }
  }

  const STATUS_ACTIONS = [
    { value: 'resolved', label: '✓ Resolved', color: 'text-emerald-700 bg-emerald-50 hover:bg-emerald-100' },
    { value: 'fp', label: '✗ False Positive', color: 'text-amber-700 bg-amber-50 hover:bg-amber-100' },
    { value: 'pending', label: '↻ Pending', color: 'text-slate-600 bg-slate-50 hover:bg-slate-100' },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Audit Logs</h2>
          <p className="text-sm text-slate-400 mt-0.5">Review detection events and mark as false positive / resolved</p>
        </div>
        {selectedIds.size > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-slate-500">{selectedIds.size} selected</span>
            {STATUS_ACTIONS.map(a => (
              <button
                key={a.value}
                onClick={() => {
                  selectedIds.forEach(id => handleStatusChange(id, a.value))
                  setSelectedIds(new Set())
                }}
                className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-colors ${a.color}`}
              >
                {a.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4 mb-4">
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex-1 min-w-[160px]">
            <label className="block text-xs text-slate-500 mb-1 font-medium">Search User</label>
            <input type="text" placeholder="Filter by user ID..." value={search}
              onChange={e => { setSearch(e.target.value); setPage(1) }}
              className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500" />
          </div>
          <SelectFilter label="Severity" value={severity} onChange={v => { setSeverity(v); setPage(1) }}
            options={SEVERITY_OPTIONS.map(s => ({ value: s, label: s }))} />
          <SelectFilter label="Direction" value={direction} onChange={v => { setDirection(v); setPage(1) }}
            options={DIRECTION_OPTIONS.map(d => ({ value: d, label: d }))} />
          <SelectFilter label="Status" value={status} onChange={v => { setStatus(v); setPage(1) }}
            options={STATUS_OPTIONS.map(s => ({ value: s, label: s || 'All' }))} />
          <div>
            <label className="block text-xs text-slate-500 mb-1 font-medium">From</label>
            <input type="date" value={dateFrom}
              onChange={e => { setDateFrom(e.target.value); setPage(1) }}
              className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white" />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1 font-medium">To</label>
            <input type="date" value={dateTo}
              onChange={e => { setDateTo(e.target.value); setPage(1) }}
              className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white" />
          </div>
          {(search || severity || direction || dateFrom || dateTo || status) && (
            <button onClick={() => { setSearch(''); setSeverity(''); setDirection(''); setDateFrom(''); setDateTo(''); setStatus(''); setPage(1) }}
              className="px-3 py-1.5 text-sm border border-slate-300 rounded-lg hover:bg-slate-50">Clear</button>
          )}
        </div>
      </div>

      {error && <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg border border-red-200 text-sm">{error}</div>}

      {loading ? (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4"><TableSkeleton rows={8} cols={8} /></div>
      ) : logs.length === 0 ? (
        <EmptyState icon="📋" title="No audit logs found"
          description={(search || severity || direction || dateFrom || dateTo || status) ? 'Try adjusting your filters.' : 'No security events recorded yet.'} />
      ) : (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                <th className="p-3 pl-5 w-8">
                  <input type="checkbox" checked={selectedIds.size === logs.length && logs.length > 0}
                    onChange={toggleSelectAll} className="rounded" />
                </th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Time</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Rule</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Severity</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Action</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Direction</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">User</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Status</th>
                <th className="p-3 pr-5 font-medium text-xs uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className="border-b border-slate-100 hover:bg-slate-50 transition-colors">
                  <td className="p-3 pl-5">
                    <input type="checkbox" checked={selectedIds.has(log.id)}
                      onChange={() => toggleSelect(log.id)} className="rounded" />
                  </td>
                  <td className="p-3 text-xs text-slate-500 whitespace-nowrap">
                    <button onClick={() => setSelectedLog(log)} className="hover:text-indigo-600">
                      {new Date(log.timestamp).toLocaleString()}
                    </button>
                  </td>
                  <td className="p-3 font-medium">
                    <button onClick={() => setSelectedLog(log)} className="hover:text-indigo-600 text-left">
                      <span className="text-xs">{log.rule_id}</span>
                      <div className="text-xs text-slate-400">{log.rule_name}</div>
                    </button>
                  </td>
                  <td className="p-3"><Badge>{log.severity}</Badge></td>
                  <td className="p-3"><Badge>{log.action}</Badge></td>
                  <td className="p-3 text-xs text-slate-500 capitalize">{log.direction}</td>
                  <td className="p-3 text-xs text-slate-500">{log.user_id || '-'}</td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${STATUS_BADGE[log.status] || 'bg-slate-100 text-slate-600'}`}>
                      {log.status}
                    </span>
                  </td>
                  <td className="p-3 pr-5">
                    <div className="flex gap-1">
                      {log.status !== 'resolved' && (
                        <button onClick={() => handleStatusChange(log.id, 'resolved')}
                          className="px-2 py-0.5 text-[10px] rounded bg-emerald-50 text-emerald-700 hover:bg-emerald-100 font-medium">Resolve</button>
                      )}
                      {log.status !== 'fp' && (
                        <button onClick={() => handleStatusChange(log.id, 'fp')}
                          className="px-2 py-0.5 text-[10px] rounded bg-amber-50 text-amber-700 hover:bg-amber-100 font-medium">FP</button>
                      )}
                      {log.status !== 'pending' && (
                        <button onClick={() => handleStatusChange(log.id, 'pending')}
                          className="px-2 py-0.5 text-[10px] rounded bg-slate-50 text-slate-600 hover:bg-slate-100 font-medium">Undo</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {total > 0 && <Pagination page={page} totalPages={totalPages} total={total} pageSize={PAGE_SIZE} onChange={setPage} />}

      {/* Detail SlideOver */}
      <SlideOver open={!!selectedLog} onClose={() => setSelectedLog(null)} title="Audit Log Detail">
        {selectedLog && (
          <div className="space-y-5">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge>{selectedLog.severity}</Badge>
              <Badge>{selectedLog.action}</Badge>
              <span className="text-xs text-slate-400 capitalize">{selectedLog.direction}</span>
            </div>
            <Section label="Rule"><p className="text-sm font-medium">{selectedLog.rule_id} — {selectedLog.rule_name}</p></Section>
            <Section label="User"><p className="text-sm">{selectedLog.user_id || '-'}</p></Section>
            <Section label="Timestamp"><p className="text-sm">{new Date(selectedLog.timestamp).toLocaleString()}</p></Section>
            <Section label="Status">
              <div className="flex gap-1">
                {STATUS_ACTIONS.map(a => (
                  <button key={a.value} onClick={() => { handleStatusChange(selectedLog.id, a.value); setSelectedLog(null) }}
                    className={`px-3 py-1 text-xs rounded-lg font-medium transition-colors ${selectedLog.status === a.value ? 'ring-2 ring-indigo-500 ' + a.color : a.color}`}>
                    {a.label}
                  </button>
                ))}
              </div>
            </Section>
            <Section label="Match Count"><p className="text-sm">{selectedLog.match_count}</p></Section>
            {selectedLog.matched_text && (
              <Section label="Matched Content">
                <pre className="text-sm bg-slate-50 rounded-lg p-3 border border-slate-200 overflow-x-auto max-h-40">{selectedLog.matched_text}</pre>
              </Section>
            )}
            {selectedLog.file_path && <Section label="File Path"><code className="text-sm">{selectedLog.file_path}</code></Section>}
            {selectedLog.metadata && (
              <Section label="Metadata">
                <pre className="text-xs bg-slate-50 rounded-lg p-3 border border-slate-200 max-h-40 overflow-x-auto">{JSON.stringify(selectedLog.metadata, null, 2)}</pre>
              </Section>
            )}
          </div>
        )}
      </SlideOver>
    </div>
  )
}

function SelectFilter({ label, value, onChange, options }: {
  label: string; value: string; onChange: (v: string) => void;
  options: { value: string; label: string }[]
}) {
  return (
    <div>
      <label className="block text-xs text-slate-500 mb-1 font-medium">{label}</label>
      <select value={value} onChange={e => onChange(e.target.value)}
        className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500">
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
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
