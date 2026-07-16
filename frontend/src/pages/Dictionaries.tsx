import { useEffect, useState, useCallback } from 'react'
import { useToast, TableSkeleton, EmptyState, ConfirmDialog } from '../components'
import type { DictionaryItem } from '../api/client'

const API_BASE = ''

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const apiKey = typeof window !== 'undefined' ? localStorage.getItem('kasra_api_key') : null
  if (apiKey) headers['X-API-Key'] = apiKey
  const res = await fetch(`${API_BASE}${path}`, { headers: { ...headers, ...options?.headers as Record<string, string> }, ...options })
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
  return res.json()
}

interface Category {
  id: number; name: string; label: string
}

export default function Dictionaries() {
  const { toast } = useToast()
  const [dictionaries, setDictionaries] = useState<DictionaryItem[]>([])
  const [categories, setCategories] = useState<Category[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [editDict, setEditDict] = useState<DictionaryItem | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<DictionaryItem | null>(null)
  const [editingEntries, setEditingEntries] = useState<DictionaryItem | null>(null)
  const [newEntryText, setNewEntryText] = useState('')
  const [form, setForm] = useState({ code: '', name: '', description: '', category_id: '' })
  const [saving, setSaving] = useState(false)

  const fetchAll = useCallback(() => {
    setLoading(true)
    Promise.all([
      api<DictionaryItem[]>('/v1/dictionaries'),
      api<Category[]>('/v1/categories'),
    ]).then(([dicts, cats]) => { setDictionaries(dicts); setCategories(cats) })
      .catch(e => toast(e.message, 'error'))
      .finally(() => setLoading(false))
  }, [toast])

  useEffect(() => { fetchAll() }, [fetchAll])

  const catName = (id: number | null) => categories.find(c => c.id === id)?.label || '-'

  const handleCreate = async () => {
    if (!form.code.trim() || !form.name.trim()) { toast('Code and name required', 'warning'); return }
    setSaving(true)
    try {
      await api('/v1/dictionaries', {
        method: 'POST',
        body: JSON.stringify({
          code: form.code.trim(),
          name: form.name.trim(),
          description: form.description.trim() || undefined,
          category_id: form.category_id ? parseInt(form.category_id) : undefined,
        }),
      })
      toast('Dictionary created', 'success')
      setShowCreate(false)
      setForm({ code: '', name: '', description: '', category_id: '' })
      fetchAll()
    } catch (e: any) { toast(e.message, 'error') }
    setSaving(false)
  }

  const handleUpdate = async () => {
    if (!editDict) return
    setSaving(true)
    try {
      await api(`/v1/dictionaries/${editDict.id}`, {
        method: 'PUT',
        body: JSON.stringify({
          name: form.name.trim(),
          description: form.description.trim() || undefined,
          category_id: form.category_id ? parseInt(form.category_id) : null,
        }),
      })
      toast('Dictionary updated', 'success')
      setEditDict(null)
      fetchAll()
    } catch (e: any) { toast(e.message, 'error') }
    setSaving(false)
  }

  const handleDelete = async () => {
    if (!deleteConfirm) return
    try {
      await api(`/v1/dictionaries/${deleteConfirm.id}`, { method: 'DELETE' })
      toast(`Deleted ${deleteConfirm.code}`, 'success')
      setDeleteConfirm(null)
      fetchAll()
    } catch (e: any) { toast(e.message, 'error') }
  }

  const handleAddEntries = async () => {
    if (!editingEntries || !newEntryText.trim()) return
    const entries = newEntryText.split(',').map(s => s.trim()).filter(Boolean)
    if (!entries.length) { toast('Enter at least one keyword', 'warning'); return }
    try {
      await api(`/v1/dictionaries/${editingEntries.id}/entries`, {
        method: 'POST',
        body: JSON.stringify({ entries }),
      })
      toast(`Added ${entries.length} keyword(s)`, 'success')
      setNewEntryText('')
      fetchAll()
    } catch (e: any) { toast(e.message, 'error') }
  }

  const handleRemoveEntry = async (entry: string) => {
    if (!editingEntries) return
    try {
      await api(`/v1/dictionaries/${editingEntries.id}/entries`, {
        method: 'DELETE',
        body: JSON.stringify({ entries: [entry] }),
      })
      toast(`Removed "${entry}"`, 'success')
      fetchAll()
    } catch (e: any) { toast(e.message, 'error') }
  }

  const openEdit = (d: DictionaryItem) => {
    setEditDict(d)
    setForm({
      code: d.code,
      name: d.name,
      description: d.description || '',
      category_id: d.category_id ? String(d.category_id) : '',
    })
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Dictionaries</h2>
          <p className="text-sm text-slate-400 mt-0.5">Keyword dictionaries referenced by security rules</p>
        </div>
        <button onClick={() => setShowCreate(true)}
          className="px-4 py-1.5 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors flex items-center gap-1.5">
          <span>+</span><span>Add Dictionary</span>
        </button>
      </div>

      {loading ? (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4"><TableSkeleton rows={5} cols={5} /></div>
      ) : dictionaries.length === 0 ? (
        <EmptyState icon="📖" title="No dictionaries" description="Add keyword dictionaries that rules can reference." />
      ) : (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                <th className="p-3 pl-5 font-medium text-xs uppercase tracking-wider">Code</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Name</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Category</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Entries</th>
                <th className="p-3 font-medium text-xs uppercase tracking-wider">Version</th>
                <th className="p-3 pr-5 font-medium text-xs uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody>
              {dictionaries.map(d => (
                <tr key={d.id} className="border-b border-slate-100 hover:bg-slate-50/50 transition-colors">
                  <td className="p-3 pl-5">
                    <span className={`font-mono text-xs font-medium ${d.is_active ? 'text-indigo-600' : 'text-slate-400'}`}>
                      {d.code}
                    </span>
                  </td>
                  <td className="p-3 text-sm font-medium text-slate-700">{d.name}</td>
                  <td className="p-3">
                    <span className="text-xs text-slate-500">{catName(d.category_id)}</span>
                  </td>
                  <td className="p-3">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-slate-100 rounded-full text-xs font-medium text-slate-600">
                      {d.entries.length} keywords
                    </span>
                  </td>
                  <td className="p-3 text-xs text-slate-400">v{d.version}</td>
                  <td className="p-3 pr-5">
                    <div className="flex items-center gap-2">
                      <button onClick={() => { setEditingEntries(d); setNewEntryText('') }}
                        className="text-xs text-indigo-600 hover:text-indigo-800 font-medium">Edit Keywords</button>
                      <button onClick={() => openEdit(d)}
                        className="text-xs text-indigo-600 hover:text-indigo-800 font-medium">Edit</button>
                      <button onClick={() => setDeleteConfirm(d)}
                        className="text-xs text-red-600 hover:text-red-800 font-medium">Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center" onClick={() => setShowCreate(false)}>
          <div className="fixed inset-0 bg-black/40" />
          <div className="relative bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4 z-10" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-slate-800">Add Dictionary</h3>
              <button onClick={() => setShowCreate(false)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400">&times;</button>
            </div>
            <div className="space-y-4">
              <FormField label="Code" desc="e.g. gdpr_health, referenced by rules">
                <input type="text" value={form.code} onChange={e => setForm(p => ({ ...p, code: e.target.value.replace(/[^a-z0-9_]/g, '') }))}
                  placeholder="gdpr_health" className="font-mono" />
              </FormField>
              <FormField label="Name" desc="e.g. GDPR Health Data Keywords">
                <input type="text" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="GDPR Health Data Keywords" />
              </FormField>
              <FormField label="Description">
                <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} rows={2} />
              </FormField>
              <FormField label="Category">
                <select value={form.category_id} onChange={e => setForm(p => ({ ...p, category_id: e.target.value }))} className="w-full">
                  <option value="">— No category —</option>
                  {categories.map(c => <option key={c.id} value={c.id}>{c.label} ({c.name})</option>)}
                </select>
              </FormField>
              <button onClick={handleCreate} disabled={saving}
                className="w-full py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50">
                {saving ? 'Saving...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {editDict && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center" onClick={() => setEditDict(null)}>
          <div className="fixed inset-0 bg-black/40" />
          <div className="relative bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4 z-10" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-slate-800">Edit: {editDict.code}</h3>
              <button onClick={() => setEditDict(null)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400">&times;</button>
            </div>
            <div className="space-y-4">
              <FormField label="Code">
                <input type="text" value={form.code} disabled className="bg-slate-50 font-mono" />
              </FormField>
              <FormField label="Name">
                <input type="text" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} />
              </FormField>
              <FormField label="Description">
                <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} rows={2} />
              </FormField>
              <FormField label="Category">
                <select value={form.category_id} onChange={e => setForm(p => ({ ...p, category_id: e.target.value }))} className="w-full">
                  <option value="">— No category —</option>
                  {categories.map(c => <option key={c.id} value={c.id}>{c.label} ({c.name})</option>)}
                </select>
              </FormField>
              <button onClick={handleUpdate} disabled={saving}
                className="w-full py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50">
                {saving ? 'Saving...' : 'Update'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Keywords SlideOver */}
      {editingEntries && (
        <div className="fixed inset-0 z-[60] flex justify-end" onClick={() => setEditingEntries(null)}>
          <div className="fixed inset-0 bg-black/40" />
          <div className="relative bg-white w-full max-w-lg shadow-2xl z-10 overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="sticky top-0 bg-white border-b border-slate-200 px-6 py-4 flex items-center justify-between z-10">
              <div>
                <h3 className="text-lg font-semibold text-slate-800">Keywords: {editingEntries.code}</h3>
                <p className="text-xs text-slate-400">{editingEntries.entries.length} entries (v{editingEntries.version})</p>
              </div>
              <button onClick={() => setEditingEntries(null)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400 text-xl">&times;</button>
            </div>

            <div className="p-6">
              {/* Add entries */}
              <div className="mb-6">
                <label className="block text-xs font-medium text-slate-600 mb-1">Add Keywords</label>
                <div className="flex gap-2">
                  <input type="text" value={newEntryText} onChange={e => setNewEntryText(e.target.value)}
                    placeholder="keyword1, keyword2, keyword3"
                    className="flex-1 text-sm"
                    onKeyDown={e => { if (e.key === 'Enter') handleAddEntries() }} />
                  <button onClick={handleAddEntries}
                    className="px-3 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 shrink-0">
                    Add
                  </button>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">Separate multiple keywords with commas</p>
              </div>

              {/* Entry list */}
              {editingEntries.entries.length === 0 ? (
                <div className="text-center py-8 text-slate-400 text-sm">No keywords yet</div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {editingEntries.entries.map((entry, i) => (
                    <span key={`${entry}-${i}`}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-indigo-50 text-indigo-700 rounded-full text-xs font-medium group">
                      <span>{entry}</span>
                      <button onClick={() => handleRemoveEntry(entry)}
                        className="text-indigo-400 hover:text-red-500 transition-colors leading-none">
                        &times;
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Delete confirm */}
      <ConfirmDialog open={!!deleteConfirm} title="Delete Dictionary" variant="danger"
        confirmLabel="Delete"
        message={`Delete "${deleteConfirm?.code}"? Rules using this dictionary will no longer resolve keywords from it.`}
        onConfirm={handleDelete} onCancel={() => setDeleteConfirm(null)} />
    </div>
  )
}

function FormField({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-600 mb-1">{label}</label>
      {children}
      {desc && <p className="text-[11px] text-slate-400 mt-0.5">{desc}</p>}
    </div>
  )
}
