import { useEffect, useState, useCallback } from 'react'
import { useToast, TableSkeleton, EmptyState, ConfirmDialog } from '../components'

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
  id: number; name: string; label: string; description: string | null; color: string; created_at: string | null
}

export default function Categories() {
  const { toast } = useToast()
  const [categories, setCategories] = useState<Category[]>([])
  const [patternTypes, setPatternTypes] = useState<{ id: number; name: string; label: string }[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [showEdit, setShowEdit] = useState<Category | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<Category | null>(null)
  const [form, setForm] = useState({ name: '', label: '', description: '', color: '#6366f1' })
  const [saving, setSaving] = useState(false)
  const [tab, setTab] = useState<'categories' | 'pattern-types'>('categories')

  const fetch = useCallback(() => {
    setLoading(true)
    Promise.all([
      api<Category[]>('/v1/categories'),
      api<{ id: number; name: string; label: string }[]>('/v1/categories/pattern-types'),
    ]).then(([cats, pts]) => { setCategories(cats); setPatternTypes(pts) })
      .catch(e => toast(e.message, 'error'))
      .finally(() => setLoading(false))
  }, [toast])

  useEffect(() => { fetch() }, [fetch])

  const handleCreate = async () => {
    if (!form.name.trim() || !form.label.trim()) { toast('Name and label required', 'warning'); return }
    setSaving(true)
    try {
      await api('/v1/categories', { method: 'POST', body: JSON.stringify(form) })
      toast('Category created', 'success'); setShowCreate(false); setForm({ name: '', label: '', description: '', color: '#6366f1' }); fetch()
    } catch (e: any) { toast(e.message, 'error') }
    setSaving(false)
  }

  const handleUpdate = async () => {
    if (!showEdit) return
    setSaving(true)
    try {
      await api(`/v1/categories/${showEdit.id}`, { method: 'PUT', body: JSON.stringify({ label: form.label, description: form.description, color: form.color }) })
      toast('Category updated', 'success'); setShowEdit(null); fetch()
    } catch (e: any) { toast(e.message, 'error') }
    setSaving(false)
  }

  const handleDelete = async () => {
    if (!deleteConfirm) return
    try {
      await api(`/v1/categories/${deleteConfirm.id}`, { method: 'DELETE' })
      toast(`Deleted ${deleteConfirm.name}`, 'success'); setDeleteConfirm(null); fetch()
    } catch (e: any) { toast(e.message, 'error') }
  }

  const openEdit = (c: Category) => { setShowEdit(c); setForm({ name: c.name, label: c.label, description: c.description || '', color: c.color }) }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Categories</h2>
          <p className="text-sm text-slate-400 mt-0.5">Manage rule classification categories and pattern types</p>
        </div>
        {tab === 'categories' && (
          <button onClick={() => setShowCreate(true)}
            className="px-4 py-1.5 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors flex items-center gap-1.5">
            <span>+</span><span>Add Category</span>
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-5">
        {([{ k: 'categories', l: 'Categories', d: 'Rule classification master data', i: '📁' },
           { k: 'pattern-types', l: 'Pattern Types', d: 'Detection method types', i: '🔍' }] as const).map(t => (
          <button key={t.k} onClick={() => setTab(t.k)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
              tab === t.k ? 'bg-indigo-600 text-white shadow-sm' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}>
            <span>{t.i}</span><span>{t.l}</span>
            <span className={`text-xs ${tab === t.k ? 'text-indigo-200' : 'text-slate-400'}`}>{t.d}</span>
          </button>
        ))}
      </div>

      {loading ? (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4"><TableSkeleton rows={5} cols={4} /></div>
      ) : tab === 'categories' ? (
        /* ── Categories table ── */
        categories.length === 0 ? (
          <EmptyState icon="📁" title="No categories" description="Add your first category to classify rules." />
        ) : (
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                  <th className="p-3 pl-5 font-medium text-xs uppercase tracking-wider">Name</th>
                  <th className="p-3 font-medium text-xs uppercase tracking-wider">Label</th>
                  <th className="p-3 font-medium text-xs uppercase tracking-wider">Description</th>
                  <th className="p-3 font-medium text-xs uppercase tracking-wider">Color</th>
                  <th className="p-3 pr-5 font-medium text-xs uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {categories.map(c => (
                  <tr key={c.id} className="border-b border-slate-100 hover:bg-slate-50/50 transition-colors">
                    <td className="p-3 pl-5 font-mono text-xs font-medium">{c.name}</td>
                    <td className="p-3 text-sm">{c.label}</td>
                    <td className="p-3 text-xs text-slate-500 max-w-xs truncate">{c.description || '-'}</td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <div className="w-5 h-5 rounded-full border border-slate-200" style={{ backgroundColor: c.color }} />
                        <span className="text-xs font-mono">{c.color}</span>
                      </div>
                    </td>
                    <td className="p-3 pr-5">
                      <div className="flex items-center gap-2">
                        <button onClick={() => openEdit(c)} className="text-xs text-indigo-600 hover:text-indigo-800 font-medium">Edit</button>
                        <button onClick={() => setDeleteConfirm(c)} className="text-xs text-red-600 hover:text-red-800 font-medium">Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : (
        /* ── Pattern Types table ── */
        patternTypes.length === 0 ? (
          <EmptyState icon="🔍" title="No pattern types" description="Add detection pattern types." />
        ) : (
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-left text-slate-500">
                  <th className="p-3 pl-5 font-medium text-xs uppercase tracking-wider">ID</th>
                  <th className="p-3 font-medium text-xs uppercase tracking-wider">Name</th>
                  <th className="p-3 font-medium text-xs uppercase tracking-wider">Label</th>
                </tr>
              </thead>
              <tbody>
                {patternTypes.map(pt => (
                  <tr key={pt.id} className="border-b border-slate-100 hover:bg-slate-50/50 transition-colors">
                    <td className="p-3 pl-5 text-xs font-mono text-slate-400">{pt.id}</td>
                    <td className="p-3 font-mono text-xs font-medium">{pt.name}</td>
                    <td className="p-3 text-sm">{pt.label}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Create Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center" onClick={() => setShowCreate(false)}>
          <div className="fixed inset-0 bg-black/40" />
          <div className="relative bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4 z-10" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-slate-800">Add Category</h3>
              <button onClick={() => setShowCreate(false)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400">&times;</button>
            </div>
            <div className="space-y-4">
              <FormField label="Name (short code)" desc="e.g. BEHAVIOR"><input type="text" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value.toUpperCase() }))} placeholder="BEHAVIOR" /></FormField>
              <FormField label="Label" desc="e.g. Behavior Monitoring"><input type="text" value={form.label} onChange={e => setForm(p => ({ ...p, label: e.target.value }))} placeholder="Behavior Monitoring" /></FormField>
              <FormField label="Description"><textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} rows={2} /></FormField>
              <FormField label="Color">
                <div className="flex items-center gap-3">
                  <input type="color" value={form.color} onChange={e => setForm(p => ({ ...p, color: e.target.value }))} className="w-10 h-10 rounded cursor-pointer" />
                  <input type="text" value={form.color} onChange={e => setForm(p => ({ ...p, color: e.target.value }))} className="flex-1 font-mono text-sm" />
                </div>
              </FormField>
              <button onClick={handleCreate} disabled={saving} className="w-full py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50">{saving ? 'Saving...' : 'Create'}</button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {showEdit && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center" onClick={() => setShowEdit(null)}>
          <div className="fixed inset-0 bg-black/40" />
          <div className="relative bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4 z-10" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-slate-800">Edit Category: {showEdit.name}</h3>
              <button onClick={() => setShowEdit(null)} className="p-1 hover:bg-slate-100 rounded-lg text-slate-400">&times;</button>
            </div>
            <div className="space-y-4">
              <FormField label="Label"><input type="text" value={form.label} onChange={e => setForm(p => ({ ...p, label: e.target.value }))} /></FormField>
              <FormField label="Description"><textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} rows={2} /></FormField>
              <FormField label="Color">
                <div className="flex items-center gap-3">
                  <input type="color" value={form.color} onChange={e => setForm(p => ({ ...p, color: e.target.value }))} className="w-10 h-10 rounded cursor-pointer" />
                  <input type="text" value={form.color} onChange={e => setForm(p => ({ ...p, color: e.target.value }))} className="flex-1 font-mono text-sm" />
                </div>
              </FormField>
              <button onClick={handleUpdate} disabled={saving} className="w-full py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50">{saving ? 'Saving...' : 'Update'}</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirm */}
      <ConfirmDialog open={!!deleteConfirm} title="Delete Category" variant="danger"
        confirmLabel="Delete"
        message={`Delete "${deleteConfirm?.name}"? Rules using this category will become uncategorized.`}
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
