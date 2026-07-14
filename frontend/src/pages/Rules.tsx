import { useEffect, useState, useCallback, useRef } from 'react'
import type { RuleItem } from '../api/client'
import { getRules, updateRule, createRule, deleteRule, exportRules, importRules } from '../api/client'
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
  const [sourceFilter, setSourceFilter] = useState<'all' | 'builtin' | 'custom'>('all')
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
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedRuleIds, setSelectedRuleIds] = useState<Set<string>>(new Set())
  const [showTestModal, setShowTestModal] = useState(false)
  const [testContent, setTestContent] = useState('')
  const [testResult, setTestResult] = useState<{ blocked: boolean; triggered_rules: { rule_id: string; matched_text: string | null }[] } | null>(null)
  const [testing, setTesting] = useState(false)

  // ── Rule Test ──
  const handleTestRule = async () => {
    if (!testContent.trim()) { toast('Enter content to test', 'warning'); return }
    setTesting(true)
    setTestResult(null)
    try {
      const apiKey = localStorage.getItem('kasra_api_key')
      const res = await fetch('/v1/scan/input', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey || '' },
        body: JSON.stringify({ content: testContent }),
      })
      const data = await res.json()
      setTestResult({ blocked: data.blocked, triggered_rules: data.triggered_rules })
    } catch (e: any) { toast('Test failed: ' + e.message, 'error') }
    setTesting(false)
  }

  // ── Batch operations ──
  const toggleSelectAll = () => {
    if (selectedRuleIds.size === rules.length) { setSelectedRuleIds(new Set()); return }
    setSelectedRuleIds(new Set(rules.map(r => r.id)))
  }
  const toggleSelect = (id: string) => {
    const next = new Set(selectedRuleIds)
    if (next.has(id)) next.delete(id); else next.add(id)
    setSelectedRuleIds(next)
  }
  const handleBatchToggle = async (enabled: boolean) => {
    for (const id of selectedRuleIds) {
      try { await updateRule(id, { enabled }) } catch { /* skip */ }
    }
    toast(`${enabled ? 'Enabled' : 'Disabled'} ${selectedRuleIds.size} rules`, 'success')
    setSelectedRuleIds(new Set())
    fetchRules()
  }

  // ── Import / Export ──
  const [showImport, setShowImport] = useState(false)
  const [showExport, setShowExport] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importTarget, setImportTarget] = useState<'sdk' | 'custom'>('sdk')
  const [importResult, setImportResult] = useState<{ total: number; created: number; updated: number; errors: string[] } | null>(null)
  const [exportSource, setExportSource] = useState<'sdk' | 'custom' | 'all'>('sdk')
  const [exportSeries, setExportSeries] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const fetchRules = useCallback(() => {
    setLoading(true)
    setError(null)
    const params: any = { page, page_size: PAGE_SIZE, severity: severity || undefined, group }
    if (sourceFilter === 'custom') params.custom_only = true
    getRules(params)
      .then((data) => { setRules(data.items); setTotal(data.total) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [page, severity, group, sourceFilter])

  useEffect(() => { fetchRules() }, [fetchRules])

  const handleToggle = async (rule: RuleItem) => {
    if (rule.enabled && rule.severity === 'P0') {
      setConfirmRule(rule)
      return
    }
    await doToggle(rule)
  }

  const doToggle = async (rule: RuleItem) => {
    const newEnabled = !rule.enabled
    setRules(rules.map(r => r.id === rule.id ? { ...r, enabled: newEnabled } : r))
    try {
      await updateRule(rule.id, { enabled: newEnabled })
      toast(newEnabled ? `Enabled ${rule.id}` : `Disabled ${rule.id}`, 'success')
      fetchRules()
    } catch {
      setRules(rules.map(r => r.id === rule.id ? { ...r, enabled: rule.enabled } : r))
      toast(`Failed to update rule ${rule.id}`, 'error')
    }
  }

  const handleConfirmToggle = () => {
    if (confirmRule) { doToggle(confirmRule); setConfirmRule(null) }
  }

  const handleCreate = async () => {
    if (!newRule.id.trim() || !newRule.name.trim()) {
      toast('Rule ID and name are required', 'warning')
      return
    }
    setCreating(true)
    try {
      await createRule({
        id: newRule.id, name: newRule.name,
        severity: newRule.severity, action: newRule.action,
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

  // ── Import ──
  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    if (!file.name.endsWith('.json')) { toast('Only .json files are supported', 'error'); return }
    setImporting(true)
    setImportResult(null)
    try {
      const result = await importRules(file, importTarget)
      setImportResult(result)
      if (result.errors.length > 0) toast(`Imported with ${result.errors.length} errors`, 'warning')
      else toast(`Imported ${result.created} created, ${result.updated} updated`, 'success')
      fetchRules()
    } catch (err: any) { toast('Import failed: ' + err.message, 'error') }
    setImporting(false)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  // ── Export ──
  const handleExport = async () => {
    try {
      const label = { sdk: 'builtin', custom: 'custom', all: 'all' }[exportSource]
      const blob = await exportRules(exportSeries || undefined, undefined, exportSource)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url
      a.download = `kasra-rules-${label}-export.json`
      a.click(); URL.revokeObjectURL(url)
      toast('Rules exported successfully', 'success')
      setShowExport(false)
    } catch (err: any) { toast('Export failed: ' + err.message, 'error') }
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
        <div className="flex items-center gap-2">
          <button onClick={() => { setImportResult(null); setShowImport(true) }}
            className="px-4 py-1.5 border border-slate-300 text-slate-700 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors flex items-center gap-1.5">
            <span>📥</span><span>Import</span>
          </button>
          <button onClick={() => setShowExport(true)}
            className="px-4 py-1.5 border border-slate-300 text-slate-700 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors flex items-center gap-1.5">
            <span>📤</span><span>Export</span>
          </button>
          <button onClick={() => { setTestContent(''); setTestResult(null); setShowTestModal(true) }}
            className="px-4 py-1.5 border border-slate-300 text-slate-700 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors flex items-center gap-1.5">
            <span>🧪</span><span>Test Rule</span>
          </button>
          <button onClick={() => setShowCreate(true)}
            className="px-4 py-1.5 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors flex items-center gap-1.5">
            <span>+</span><span>Create Rule</span>
          </button>
        </div>
      </div>

      {/* Tabs row: Group tabs + source filter */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex gap-2">
          {TABS.map((t) => (
            <button key={t.key} onClick={() => { setGroup(t.key); setPage(1); setSeverity('') }}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                group === t.key ? 'bg-indigo-600 text-white shadow-sm' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}>
              <span>{t.icon}</span><span>{t.label}</span>
              <span className={`text-xs ${group === t.key ? 'text-indigo-200' : 'text-slate-400'}`}>{t.desc}</span>
            </button>
          ))}
        </div>

        {/* Source filter pills */}
        <div className="flex items-center gap-1 bg-slate-100 rounded-lg p-0.5">
          {(['all', 'builtin', 'custom'] as const).map(s => (
            <button key={s} onClick={() => { setSourceFilter(s); setPage(1) }}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                sourceFilter === s
                  ? s === 'custom' ? 'bg-purple-600 text-white shadow-sm'
                    : s === 'builtin' ? 'bg-slate-700 text-white shadow-sm'
                    : 'bg-white text-slate-700 shadow-sm'
                  : 'text-slate-500 hover:text-slate-700'
              }`}>
              {s === 'all' ? 'All' : s === 'builtin' ? 'Built-in' : 'Custom'}
            </button>
          ))}
        </div>
      </div>

      {/* Filters bar */}
      <div className="flex items-center gap-3 mb-4">
        <input type="text" value={searchQuery} onChange={e => { setSearchQuery(e.target.value); setPage(1) }}
          placeholder="Search by name or ID..."
          className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white w-48 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
          className="border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500">
          <option value="">All Severities</option>
          {SEVERITY_OPTIONS.map(s => (
            <option key={s} value={s}>{s} — {s === 'P0' ? 'Critical' : s === 'P1' ? 'High' : 'Medium'}</option>
          ))}
        </select>
        <span className="text-sm text-slate-400 ml-auto">{total} rules</span>
      </div>

      {/* Batch action bar */}
      {selectedRuleIds.size > 0 && (
        <div className="mb-3 flex items-center gap-3 px-4 py-2 bg-indigo-50 rounded-xl border border-indigo-200">
          <span className="text-sm font-medium text-indigo-700">{selectedRuleIds.size} selected</span>
          <button onClick={() => handleBatchToggle(true)} className="px-3 py-1 text-xs bg-emerald-600 text-white rounded-lg hover:bg-emerald-700">Enable all</button>
          <button onClick={() => handleBatchToggle(false)} className="px-3 py-1 text-xs bg-slate-600 text-white rounded-lg hover:bg-slate-700">Disable all</button>
          <button onClick={() => setSelectedRuleIds(new Set())} className="px-3 py-1 text-xs border border-slate-300 rounded-lg hover:bg-slate-50">Clear</button>
        </div>
      )}

      {/* Error */}
      {error && <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg border border-red-200 text-sm">{error}</div>}

      {/* Table */}
      {loading ? (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4"><TableSkeleton rows={8} cols={6} /></div>
      ) : rules.length === 0 ? (
        <EmptyState icon="🛡️" title="No rules found"
          description={sourceFilter === 'custom' ? 'No custom rules created yet. Use "Create Rule" to add one.' : 'No rules match the current filters.'} />
      ) : (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                <th className="p-3 pl-3 w-8">
                  <input type="checkbox" checked={selectedRuleIds.size === rules.length && rules.length > 0}
                    onChange={toggleSelectAll} className="rounded border-slate-300" />
                </th>
                <th className="p-3 pl-1 font-medium text-xs uppercase tracking-wider w-24">ID</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Name</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Severity</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Action</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Category</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Type</th>
                <th className="p-3 pr-5 font-medium text-xs uppercase tracking-wider">Status</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id}
                  className={`border-b border-slate-100 hover:bg-indigo-50/30 transition-colors ${
                    rule.is_custom ? 'bg-purple-50/40' : ''
                  }`}>
                  <td className="p-3 pl-3">
                    <input type="checkbox" checked={selectedRuleIds.has(rule.id)}
                      onChange={() => toggleSelect(rule.id)} className="rounded border-slate-300" />
                  </td>
                  <td className="p-3 pl-1">
                    <button onClick={() => setSelectedRule(rule)}
                      className="font-mono text-xs text-indigo-600 hover:text-indigo-800 hover:underline">
                      {rule.id}
                    </button>
                  </td>
                  <td className="p-3">
                    <button onClick={() => setSelectedRule(rule)} className="text-left hover:text-indigo-600 transition-colors">
                      {rule.name}
                    </button>
                  </td>
                  <td className="p-3"><Badge>{rule.severity}</Badge></td>
                  <td className="p-3"><Badge>{rule.action}</Badge></td>
                  <td className="p-3 text-xs text-slate-500">{rule.category || '-'}</td>
                  <td className="p-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                      rule.is_custom ? 'bg-purple-100 text-purple-700' : 'bg-slate-100 text-slate-600'
                    }`}>
                      {rule.is_custom ? 'Custom' : 'Built-in'}
                    </span>
                  </td>
                  <td className="p-3 pr-5">
                    <div className="flex items-center gap-2">
                      <Toggle enabled={rule.enabled} onChange={() => handleToggle(rule)} />
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
      {total > 0 && <Pagination page={page} totalPages={totalPages} total={total} pageSize={PAGE_SIZE} onChange={setPage} />}

      {/* Detail SlideOver */}
      <SlideOver open={!!selectedRule} onClose={() => setSelectedRule(null)} title="Rule Detail">
        {selectedRule && (
          <div className="space-y-5">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge>{selectedRule.severity}</Badge>
              <Badge>{selectedRule.action}</Badge>
              {selectedRule.is_custom
                ? <Badge variant="purple">Custom Rule</Badge>
                : <Badge variant="default">Built-in Rule</Badge>}
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                selectedRule.enabled ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-600'
              }`}>{selectedRule.enabled ? 'Enabled' : 'Disabled'}</span>
            </div>

            <DetailSection label="ID"><code className="text-sm font-mono">{selectedRule.id}</code></DetailSection>
            <DetailSection label="Name"><p className="text-sm font-medium">{selectedRule.name}</p></DetailSection>
            <DetailSection label="Group"><span className="text-sm">{selectedRule.group || '-'}</span></DetailSection>
            <DetailSection label="Category"><span className="text-sm">{selectedRule.category || '-'}</span></DetailSection>
            <DetailSection label="Source"><span className="text-sm">{selectedRule.is_custom ? 'User-created' : 'SDK Built-in'}</span></DetailSection>

            {selectedRule.is_custom && selectedRule.pattern_type && (
              <>
                <DetailSection label="Pattern Type"><span className="text-sm capitalize">{selectedRule.pattern_type}</span></DetailSection>
                {selectedRule.pattern_value && (
                  <DetailSection label="Pattern Value">
                    <pre className="text-sm bg-slate-50 rounded-lg p-3 border border-slate-200 overflow-x-auto whitespace-pre-wrap break-all max-h-32">{selectedRule.pattern_value}</pre>
                  </DetailSection>
                )}
                {selectedRule.applicable_stages && selectedRule.applicable_stages.length > 0 && (
                  <DetailSection label="Applies To">
                    <div className="flex gap-1">{selectedRule.applicable_stages.map(s => <span key={s} className="px-2 py-0.5 bg-slate-100 text-xs rounded-full capitalize">{s}</span>)}</div>
                  </DetailSection>
                )}
                {selectedRule.target_files && selectedRule.target_files.length > 0 && (
                  <DetailSection label="Target Files">
                    <div className="flex gap-1 flex-wrap">{selectedRule.target_files.map(g => <code key={g} className="px-2 py-0.5 bg-slate-100 text-xs rounded">{g}</code>)}</div>
                  </DetailSection>
                )}
              </>
            )}

            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">Toggle Rule</span>
              </div>
              <div className="flex items-center gap-3">
                <Toggle enabled={selectedRule.enabled} onChange={() => { handleToggle(selectedRule); setSelectedRule(null) }} size="md" />
                <span className="text-sm font-medium">{selectedRule.enabled ? 'Active' : 'Disabled'}</span>
              </div>
            </div>

            {selectedRule.is_custom && (
              <div className="pt-4 border-t border-slate-200">
                <button onClick={() => { setDeleteConfirm(selectedRule); setSelectedRule(null) }}
                  className="text-sm text-red-600 hover:text-red-700 font-medium">Delete this custom rule</button>
              </div>
            )}
          </div>
        )}
      </SlideOver>

      {/* P0 disable confirm */}
      <ConfirmDialog open={!!confirmRule} title="Disable Critical Rule"
        message={`Are you sure you want to disable "${confirmRule?.id} — ${confirmRule?.name}"? This is a P0 (Critical) severity rule and disabling it may expose your system to security risks.`}
        confirmLabel="Yes, Disable" variant="danger" onConfirm={handleConfirmToggle} onCancel={() => setConfirmRule(null)} />

      {/* Delete confirm */}
      <ConfirmDialog open={!!deleteConfirm} title="Delete Custom Rule"
        message={`Are you sure you want to permanently delete "${deleteConfirm?.id}"? This action cannot be undone.`}
        confirmLabel="Delete" variant="danger" onConfirm={() => deleteConfirm && handleDelete(deleteConfirm)} onCancel={() => setDeleteConfirm(null)} />

      {/* ── Import Modal ── */}
      {showImport && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center" onClick={() => setShowImport(false)}>
          <div className="fixed inset-0 bg-black/40" />
          <div className="relative bg-white rounded-2xl shadow-2xl p-6 w-full max-w-lg mx-4 z-10" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-slate-800">Import Rules</h3>
              <button onClick={() => setShowImport(false)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400">&times;</button>
            </div>
            <div className="space-y-4">
              <p className="text-sm text-slate-500">Upload a JSON bundle to import rules. Choose the target type:</p>

              {/* Target selector */}
              <div className="flex gap-3">
                <label className={`flex-1 flex items-center gap-3 p-3 rounded-xl border-2 cursor-pointer transition-colors ${
                  importTarget === 'sdk' ? 'border-slate-700 bg-slate-50' : 'border-slate-200 hover:border-slate-300'
                }`}>
                  <input type="radio" name="importTarget" value="sdk" checked={importTarget === 'sdk'}
                    onChange={() => setImportTarget('sdk')} className="sr-only" />
                  <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center ${importTarget === 'sdk' ? 'border-slate-700' : 'border-slate-300'}`}>
                    {importTarget === 'sdk' && <div className="w-2 h-2 rounded-full bg-slate-700" />}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-slate-700">Built-in Rules</p>
                    <p className="text-xs text-slate-400">Import as SDK rules (rules table)</p>
                  </div>
                </label>
                <label className={`flex-1 flex items-center gap-3 p-3 rounded-xl border-2 cursor-pointer transition-colors ${
                  importTarget === 'custom' ? 'border-purple-500 bg-purple-50' : 'border-slate-200 hover:border-slate-300'
                }`}>
                  <input type="radio" name="importTarget" value="custom" checked={importTarget === 'custom'}
                    onChange={() => setImportTarget('custom')} className="sr-only" />
                  <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center ${importTarget === 'custom' ? 'border-purple-500' : 'border-slate-300'}`}>
                    {importTarget === 'custom' && <div className="w-2 h-2 rounded-full bg-purple-500" />}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-purple-700">Custom Rules</p>
                    <p className="text-xs text-slate-400">Import as user-defined rules</p>
                  </div>
                </label>
              </div>

              <div className="border-2 border-dashed border-slate-300 rounded-xl p-8 text-center hover:border-indigo-400 transition-colors">
                <input ref={fileInputRef} type="file" accept=".json" onChange={handleImport} className="hidden" id="import-file-input" />
                <label htmlFor="import-file-input" className="cursor-pointer flex flex-col items-center gap-2">
                  <span className="text-3xl">📂</span>
                  <span className="text-sm font-medium text-indigo-600">Click to select JSON file</span>
                  <span className="text-xs text-slate-400">Only .json bundle files supported</span>
                </label>
              </div>

              {importing && <div className="flex items-center gap-2 text-sm text-slate-500"><span className="animate-spin text-lg">⏳</span><span>Importing rules...</span></div>}

              {importResult && (
                <div className={`p-4 rounded-xl border ${importResult.errors.length > 0 ? 'bg-amber-50 border-amber-200' : 'bg-emerald-50 border-emerald-200'}`}>
                  <p className="text-sm font-medium mb-1">Import Complete</p>
                  <ul className="text-sm space-y-0.5">
                    <li className="text-emerald-700">✓ {importResult.created} rules created</li>
                    <li className="text-blue-700">✓ {importResult.updated} rules updated</li>
                    {importResult.errors.length > 0 && <li className="text-amber-700">⚠ {importResult.errors.length} errors</li>}
                  </ul>
                  {importResult.errors.length > 0 && (
                    <details className="mt-2"><summary className="text-xs text-amber-600 cursor-pointer">Show errors</summary>
                      <ul className="mt-1 space-y-0.5">{importResult.errors.map((err, i) => <li key={i} className="text-xs text-amber-700">{err}</li>)}</ul>
                    </details>
                  )}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <button onClick={() => { setShowImport(false); setImportResult(null) }} className="px-4 py-2 border border-slate-300 rounded-lg text-sm hover:bg-slate-50">Close</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Export Modal ── */}
      {showExport && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center" onClick={() => setShowExport(false)}>
          <div className="fixed inset-0 bg-black/40" />
          <div className="relative bg-white rounded-2xl shadow-2xl p-6 w-full max-w-lg mx-4 z-10" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-slate-800">Export Rules</h3>
              <button onClick={() => setShowExport(false)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400">&times;</button>
            </div>
            <div className="space-y-4">
              <p className="text-sm text-slate-500">Choose what to export:</p>

              {/* Source selector */}
              <div className="flex gap-3">
                {([{ v: 'sdk', l: 'Built-in', c: 'bg-slate-700', desc: 'SDK built-in rules only' },
                   { v: 'custom', l: 'Custom', c: 'border-purple-500 bg-purple-50', desc: 'Custom rules only' },
                   { v: 'all', l: 'All', c: 'bg-indigo-600', desc: 'Both built-in and custom' }] as const).map(({ v, l, c, desc }) => (
                  <label key={v}
                    className={`flex-1 flex flex-col items-center gap-2 p-3 rounded-xl border-2 cursor-pointer transition-colors ${
                      exportSource === v ? c + ' border-transparent text-white' : 'border-slate-200 hover:border-slate-300'
                    }`}>
                    <input type="radio" name="exportSource" value={v} checked={exportSource === v}
                      onChange={() => setExportSource(v as any)} className="sr-only" />
                    <p className={`text-sm font-medium ${exportSource === v ? 'text-white' : 'text-slate-700'}`}>{l}</p>
                    <p className={`text-xs ${exportSource === v ? 'text-white/80' : 'text-slate-400'}`}>{desc}</p>
                    <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center ${exportSource === v ? 'border-white' : 'border-slate-300'}`}>
                      {exportSource === v && <div className="w-2 h-2 rounded-full bg-white" />}
                    </div>
                  </label>
                ))}
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Filter by Series (optional)</label>
                <select value={exportSeries} onChange={e => setExportSeries(e.target.value)}
                  className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
                  <option value="">All Series</option>
                  <option value="I">I — Input Detection</option>
                  <option value="O">O — Output Detection</option>
                  <option value="SEC">SEC — Code Security</option>
                  <option value="IAC">IAC — Infrastructure as Code</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button onClick={() => setShowExport(false)} className="px-4 py-2 border border-slate-300 rounded-lg text-sm hover:bg-slate-50">Cancel</button>
                <button onClick={handleExport}
                  className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors flex items-center gap-1.5">
                  <span>📤</span><span>Download Bundle</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Test Rule Modal ── */}
      {showTestModal && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center" onClick={() => setShowTestModal(false)}>
          <div className="fixed inset-0 bg-black/40" />
          <div className="relative bg-white rounded-2xl shadow-2xl p-6 w-full max-w-lg mx-4 z-10" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-slate-800">🧪 Test Rules</h3>
              <button onClick={() => setShowTestModal(false)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400">&times;</button>
            </div>
            <div className="space-y-4">
              <p className="text-sm text-slate-500">Enter text content to test which rules trigger:</p>
              <textarea value={testContent} onChange={e => setTestContent(e.target.value)}
                rows={5} placeholder="Type or paste content to scan..."
                className="w-full border border-slate-300 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono" />
              <button onClick={handleTestRule} disabled={testing}
                className="w-full py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 transition-colors">
                {testing ? 'Scanning...' : 'Run Test'}
              </button>
              {testResult && (
                <div className={`p-4 rounded-xl border ${testResult.blocked ? 'bg-red-50 border-red-200' : testResult.triggered_rules.length > 0 ? 'bg-amber-50 border-amber-200' : 'bg-emerald-50 border-emerald-200'}`}>
                  <p className="text-sm font-medium mb-2">
                    {testResult.blocked ? '🚫 Blocked' : testResult.triggered_rules.length > 0 ? `⚠ ${testResult.triggered_rules.length} rule(s) triggered` : '✅ No rules triggered'}
                  </p>
                  {testResult.triggered_rules.map((tr, i) => (
                    <div key={i} className="text-xs text-slate-700 mb-1 flex gap-2">
                      <span className="font-mono font-medium text-indigo-600">{tr.rule_id}</span>
                      {tr.matched_text && <span className="text-slate-400 truncate">"{tr.matched_text}"</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Create Rule Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center" onClick={() => setShowCreate(false)}>
          <div className="fixed inset-0 bg-black/40" />
          <div className="relative bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4 z-10" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-slate-800">Create Custom Rule</h3>
              <button onClick={() => setShowCreate(false)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400">&times;</button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Rule ID</label>
                <input type="text" value={newRule.id} onChange={e => setNewRule(p => ({ ...p, id: e.target.value }))}
                  placeholder="e.g. U-01"
                  className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
                <p className="text-[11px] text-slate-400 mt-0.5">Must start with U- (custom rules)</p>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Name</label>
                <input type="text" value={newRule.name} onChange={e => setNewRule(p => ({ ...p, name: e.target.value }))}
                  placeholder="e.g. Block Test Domain"
                  className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
              </div>
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="block text-xs font-medium text-slate-600 mb-1">Severity</label>
                  <select value={newRule.severity} onChange={e => setNewRule(p => ({ ...p, severity: e.target.value }))}
                    className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
                    <option value="P0">P0 — Critical</option>
                    <option value="P1">P1 — High</option>
                    <option value="P2">P2 — Medium</option>
                  </select>
                </div>
                <div className="flex-1">
                  <label className="block text-xs font-medium text-slate-600 mb-1">Action</label>
                  <select value={newRule.action} onChange={e => setNewRule(p => ({ ...p, action: e.target.value }))}
                    className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
                    <option value="block">Block</option>
                    <option value="warn">Warn</option>
                    <option value="redact">Redact</option>
                  </select>
                </div>
              </div>
              <div className="border-t border-slate-100 pt-3">
                <p className="text-xs font-medium text-slate-500 mb-2 uppercase tracking-wider">Detection</p>
                <div className="flex gap-3 mb-3">
                  <div className="flex-1">
                    <label className="block text-xs font-medium text-slate-600 mb-1">Pattern Type</label>
                    <select value={newRule.pattern_type} onChange={e => setNewRule(p => ({ ...p, pattern_type: e.target.value }))}
                      className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
                      <option value="regex">Regex — regular expression</option>
                      <option value="keyword">Keyword — exact keyword match</option>
                    </select>
                  </div>
                  <div className="flex-1">
                    <label className="block text-xs font-medium text-slate-600 mb-1">Applies To</label>
                    <select value={newRule.applicable_stages[0]}
                      onChange={e => { const stages = e.target.value === 'batch' ? ['batch'] : [e.target.value]; setNewRule(p => ({ ...p, applicable_stages: stages })) }}
                      className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
                      <option value="input">Input detection</option>
                      <option value="output">Output detection</option>
                      <option value="batch">Code review</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">{newRule.pattern_type === 'keyword' ? 'Keyword Text' : 'Regex Pattern'}</label>
                  <textarea value={newRule.pattern_value} onChange={e => setNewRule(p => ({ ...p, pattern_value: e.target.value }))}
                    rows={3}
                    className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500" />
                </div>
              </div>
              <button onClick={handleCreate} disabled={creating}
                className="w-full py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 transition-colors">
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
  return (<div><div className="text-xs text-slate-400 font-medium uppercase tracking-wider mb-1">{label}</div>{children}</div>)
}
