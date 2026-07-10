import { useEffect, useState, useCallback } from 'react'
import type { RuleItem } from '../api/client'
import { getRules, updateRule, createRule, deleteRule } from '../api/client'
import { Badge, Toggle, SlideOver, TableSkeleton, EmptyState, Pagination, ConfirmDialog, useToast } from '../components'

type RuleGroup = 'input' | 'output' | 'code_review'

const TABS: { key: RuleGroup; label: string; desc: string; icon: string }[] = [
  { key: 'input', label: 'Input', desc: 'I-series — user input detection', icon: '📥' },
  { key: 'output', label: 'Output', desc: 'O-series — AI output detection', icon: '📤' },
  { key: 'code_review', label: 'Code Review', desc: 'SEC / IAC — security audit', icon: '🔍' },
]

const SEVERITY_OPTIONS = ['P0', 'P1', 'P2'] as const
const PAGE_SIZE = 20

export default function Rules() {
  const { toast } = useToast()
  const [rules, setRules] = useState<RuleItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')
  const [group, setGroup] = useState<RuleGroup>('input')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedRule, setSelectedRule] = useState<RuleItem | null>(null)
  const [confirmRule, setConfirmRule] = useState<RuleItem | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [newRule, setNewRule] = useState({
    id: '', name: '', severity: 'P1' as string, action: 'warn' as string,
    pattern_type: 'regex' as string, pattern_value: '',
    applicable_stages: ['input'] as string[], target_files: '',
  })
  const [creating, setCreating] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<RuleItem | null>(null)

  const fetchRules = useCallback(() => {
    setLoading(true)
    setError(null)
    getRules({ page, page_size: PAGE_SIZE, severity: severity || undefined, group })
      .then((data) => { setRules(data.items); setTotal(data.total) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [page, severity, group])

  useEffect(() => { fetchRules() }, [fetchRules])

  const handleToggle = async (rule: RuleItem) => {
    // Show confirm dialog for disabling P0 rules
    if (rule.enabled && rule.severity === 'P0') {
      setConfirmRule(rule)
      return
    }

    await doToggle(rule)
  }

  const doToggle = async (rule: RuleItem) => {
    const newEnabled = !rule.enabled
    // Optimistic update
    setRules(rules.map(r => r.id === rule.id ? { ...r, enabled: newEnabled } : r))

    try {
      await updateRule(rule.id, { enabled: newEnabled })
      toast(newEnabled ? `Enabled ${rule.id}` : `Disabled ${rule.id}`, 'success')
      // Refresh to ensure sync with DB
      fetchRules()
    } catch {
      setRules(rules.map(r => r.id === rule.id ? { ...r, enabled: rule.enabled } : r))
      toast(`Failed to update rule ${rule.id}`, 'error')
    }
  }

  const handleConfirmToggle = () => {
    if (confirmRule) {
      doToggle(confirmRule)
      setConfirmRule(null)
    }
  }

  const handleCreate = async () => {
    if (!newRule.id.trim() || !newRule.name.trim()) {
      toast('Rule ID and name are required', 'warning')
      return
    }
    setCreating(true)
    try {
      await createRule({
        id: newRule.id,
        name: newRule.name,
        severity: newRule.severity,
        action: newRule.action,
        pattern_type: newRule.pattern_type || undefined,
        pattern_value: newRule.pattern_value || undefined,
        applicable_stages: newRule.applicable_stages,
        target_files: newRule.target_files ? newRule.target_files.split(',').map(s => s.trim()) : undefined,
      })
      toast(`Rule ${newRule.id} created`, 'success')
      setShowCreate(false)
      setNewRule({ id: '', name: '', severity: 'P1', action: 'warn', pattern_type: 'regex', pattern_value: '', applicable_stages: ['input'], target_files: '' })
      fetchRules()
    } catch (e: any) {
      toast('Failed to create rule: ' + e.message, 'error')
    }
    setCreating(false)
  }

  const handleDelete = async (rule: RuleItem) => {
    try {
      await deleteRule(rule.id)
      toast(`Deleted ${rule.id}`, 'success')
      setDeleteConfirm(null)
      setSelectedRule(null)
      fetchRules()
    } catch (e: any) {
      toast('Failed to delete rule: ' + e.message, 'error')
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Rule Management</h2>
          <p className="text-sm text-slate-400 mt-0.5">Configure and manage security detection rules</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="px-4 py-1.5 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors flex items-center gap-1.5"
        >
          <span>+</span>
          <span>Create Rule</span>
        </button>
      </div>

      {/* Three tabs */}
      <div className="flex gap-2 mb-5">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => { setGroup(t.key); setPage(1); setSeverity('') }}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
              group === t.key
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            <span>{t.icon}</span>
            <span>{t.label}</span>
            <span className={`text-xs ${group === t.key ? 'text-indigo-200' : 'text-slate-400'}`}>{t.desc}</span>
          </button>
        ))}
      </div>

      {/* Filters bar */}
      <div className="flex items-center gap-3 mb-4">
        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
          className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">All Severities</option>
          {SEVERITY_OPTIONS.map(s => (
            <option key={s} value={s}>{s} — {s === 'P0' ? 'Critical' : s === 'P1' ? 'High' : 'Medium'}</option>
          ))}
        </select>
        <span className="text-sm text-slate-400 ml-auto">{total} rules</span>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg border border-red-200 text-sm">
          {error}
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4">
          <TableSkeleton rows={8} cols={6} />
        </div>
      ) : rules.length === 0 ? (
        <EmptyState
          icon="🛡️"
          title="No rules found"
          description={severity ? 'No rules match the selected severity filter.' : 'This rule group is empty.'}
        />
      ) : (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                <th className="p-3 pl-5 font-medium text-xs uppercase tracking-wider">ID</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Name</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Severity</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Action</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Category</th>
                <th className="p-3 pr-5 font-medium text-xs uppercase tracking-wider">Status</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr
                  key={rule.id}
                  className="border-b border-slate-100 hover:bg-indigo-50/30 transition-colors"
                >
                  <td className="p-3 pl-5">
                    <button
                      onClick={() => setSelectedRule(rule)}
                      className="font-mono text-xs text-indigo-600 hover:text-indigo-800 hover:underline"
                    >
                      {rule.id}
                    </button>
                  </td>
                  <td className="p-3">
                    <button
                      onClick={() => setSelectedRule(rule)}
                      className="text-left hover:text-indigo-600 transition-colors"
                    >
                      {rule.name}
                      {rule.is_custom && <span className="ml-2 text-xs text-purple-600">(custom)</span>}
                    </button>
                  </td>
                  <td className="p-3">
                    <Badge>{rule.severity}</Badge>
                  </td>
                  <td className="p-3">
                    <Badge>{rule.action}</Badge>
                  </td>
                  <td className="p-3 text-xs text-slate-500">
                    {rule.category || '-'}
                  </td>
                  <td className="p-3 pr-5">
                    <div className="flex items-center gap-2">
                      <Toggle
                        enabled={rule.enabled}
                        onChange={() => handleToggle(rule)}
                      />
                      <span className={`text-xs ${rule.enabled ? 'text-emerald-600' : 'text-slate-400'}`}>
                        {rule.enabled ? 'Active' : 'Disabled'}
                      </span>
                    </div>
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
      <SlideOver open={!!selectedRule} onClose={() => setSelectedRule(null)} title="Rule Detail">
        {selectedRule && (
          <div className="space-y-5">
            <div className="flex items-center gap-2">
              <Badge>{selectedRule.severity}</Badge>
              <Badge>{selectedRule.action}</Badge>
              {selectedRule.is_custom && <Badge variant="purple">Custom</Badge>}
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                selectedRule.enabled ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-600'
              }`}>
                {selectedRule.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>

            <DetailSection label="ID">
              <code className="text-sm font-mono">{selectedRule.id}</code>
            </DetailSection>

            <DetailSection label="Name">
              <p className="text-sm font-medium">{selectedRule.name}</p>
            </DetailSection>

            <DetailSection label="Group">
              <span className="text-sm">{selectedRule.group || '-'}</span>
            </DetailSection>

            <DetailSection label="Category">
              <span className="text-sm">{selectedRule.category || '-'}</span>
            </DetailSection>

            <DetailSection label="Source">
              <span className="text-sm">{selectedRule.source || 'sdk'}</span>
            </DetailSection>

            {selectedRule.is_custom && selectedRule.pattern_type && (
              <>
                <DetailSection label="Pattern Type">
                  <span className="text-sm capitalize">{selectedRule.pattern_type}</span>
                </DetailSection>
                {selectedRule.pattern_value && (
                  <DetailSection label="Pattern Value">
                    <pre className="text-sm bg-slate-50 rounded-lg p-3 border border-slate-200 overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                      {selectedRule.pattern_value}
                    </pre>
                  </DetailSection>
                )}
                {selectedRule.applicable_stages && selectedRule.applicable_stages.length > 0 && (
                  <DetailSection label="Applies To">
                    <div className="flex gap-1">
                      {selectedRule.applicable_stages.map(s => (
                        <span key={s} className="px-2 py-0.5 bg-slate-100 text-xs rounded-full capitalize">{s}</span>
                      ))}
                    </div>
                  </DetailSection>
                )}
                {selectedRule.target_files && selectedRule.target_files.length > 0 && (
                  <DetailSection label="Target Files">
                    <div className="flex gap-1 flex-wrap">
                      {selectedRule.target_files.map(g => (
                        <code key={g} className="px-2 py-0.5 bg-slate-100 text-xs rounded">{g}</code>
                      ))}
                    </div>
                  </DetailSection>
                )}
              </>
            )}

            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">Toggle Rule</span>
              </div>
              <div className="flex items-center gap-3">
                <Toggle
                  enabled={selectedRule.enabled}
                  onChange={() => {
                    handleToggle(selectedRule)
                    setSelectedRule(null)
                  }}
                  size="md"
                />
                <span className="text-sm font-medium">
                  {selectedRule.enabled ? 'Active' : 'Disabled'}
                </span>
              </div>
            </div>

            {selectedRule.is_custom && selectedRule.source === 'user' && (
              <div className="pt-4 border-t border-slate-200">
                <button
                  onClick={() => { setDeleteConfirm(selectedRule); setSelectedRule(null) }}
                  className="text-sm text-red-600 hover:text-red-700 font-medium"
                >
                  Delete this custom rule
                </button>
              </div>
            )}
          </div>
        )}
      </SlideOver>

      {/* P0 disable confirm dialog */}
      <ConfirmDialog
        open={!!confirmRule}
        title="Disable Critical Rule"
        message={`Are you sure you want to disable "${confirmRule?.id} — ${confirmRule?.name}"? This is a P0 (Critical) severity rule and disabling it may expose your system to security risks.`}
        confirmLabel="Yes, Disable"
        variant="danger"
        onConfirm={handleConfirmToggle}
        onCancel={() => setConfirmRule(null)}
      />

      {/* Delete confirm dialog */}
      <ConfirmDialog
        open={!!deleteConfirm}
        title="Delete Custom Rule"
        message={`Are you sure you want to permanently delete "${deleteConfirm?.id}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => deleteConfirm && handleDelete(deleteConfirm)}
        onCancel={() => setDeleteConfirm(null)}
      />

      {/* Create Rule Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center">
          <div className="fixed inset-0 bg-black/40" onClick={() => setShowCreate(false)} />
          <div className="relative bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4 z-10">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-slate-800">Create Custom Rule</h3>
              <button onClick={() => setShowCreate(false)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400">&times;</button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Rule ID</label>
                <input
                  type="text"
                  value={newRule.id}
                  onChange={e => setNewRule(p => ({ ...p, id: e.target.value }))}
                  placeholder="e.g. U-01"
                  className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
                <p className="text-[11px] text-slate-400 mt-0.5">Must start with U- (custom rules)</p>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Name</label>
                <input
                  type="text"
                  value={newRule.name}
                  onChange={e => setNewRule(p => ({ ...p, name: e.target.value }))}
                  placeholder="e.g. Block Test Domain"
                  className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="block text-xs font-medium text-slate-600 mb-1">Severity</label>
                  <select
                    value={newRule.severity}
                    onChange={e => setNewRule(p => ({ ...p, severity: e.target.value }))}
                    className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="P0">P0 — Critical</option>
                    <option value="P1">P1 — High</option>
                    <option value="P2">P2 — Medium</option>
                  </select>
                </div>
                <div className="flex-1">
                  <label className="block text-xs font-medium text-slate-600 mb-1">Action</label>
                  <select
                    value={newRule.action}
                    onChange={e => setNewRule(p => ({ ...p, action: e.target.value }))}
                    className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="block">Block</option>
                    <option value="warn">Warn</option>
                    <option value="redact">Redact</option>
                  </select>
                </div>
              </div>

              {/* Detection Method */}
              <div className="border-t border-slate-100 pt-3">
                <p className="text-xs font-medium text-slate-500 mb-2 uppercase tracking-wider">Detection</p>
                <div className="flex gap-3 mb-3">
                  <div className="flex-1">
                    <label className="block text-xs font-medium text-slate-600 mb-1">Pattern Type</label>
                    <select
                      value={newRule.pattern_type}
                      onChange={e => setNewRule(p => ({ ...p, pattern_type: e.target.value }))}
                      className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    >
                      <option value="regex">Regex — regular expression</option>
                      <option value="keyword">Keyword — exact keyword match</option>
                    </select>
                  </div>
                  <div className="flex-1">
                    <label className="block text-xs font-medium text-slate-600 mb-1">Applies To</label>
                    <select
                      value={newRule.applicable_stages[0]}
                      onChange={e => {
                        const stages = e.target.value === 'batch' ? ['batch'] : [e.target.value]
                        setNewRule(p => ({ ...p, applicable_stages: stages }))
                      }}
                      className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    >
                      <option value="input">Input detection</option>
                      <option value="output">Output detection</option>
                      <option value="batch">Code review</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">
                    {newRule.pattern_type === 'keyword' ? 'Keyword Text' : 'Regex Pattern'}
                  </label>
                  <textarea
                    value={newRule.pattern_value}
                    onChange={e => setNewRule(p => ({ ...p, pattern_value: e.target.value }))}
                    placeholder={newRule.applicable_stages[0] === 'batch'
                      ? 'e.g. (password|secret)\\s*=\\s*[\'"]?[A-Za-z0-9]+'
                      : newRule.pattern_type === 'keyword'
                        ? 'e.g. ignore all instructions, admin password'
                        : 'e.g. password=[A-Za-z0-9]+'
                    }
                    rows={3}
                    className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                {newRule.applicable_stages[0] === 'batch' && (
                  <div className="mt-3">
                    <label className="block text-xs font-medium text-slate-600 mb-1">Target Files (comma-separated globs)</label>
                    <input
                      type="text"
                      value={newRule.target_files}
                      onChange={e => setNewRule(p => ({ ...p, target_files: e.target.value }))}
                      placeholder="**/*.py, **/*.js, **/*.ts"
                      className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                )}
              </div>

              <button
                onClick={handleCreate}
                disabled={creating}
                className="w-full py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 transition-colors"
              >
                {creating ? 'Creating...' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function DetailSection({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs text-slate-400 font-medium uppercase tracking-wider mb-1">{label}</div>
      {children}
    </div>
  )
}
