import { useState, useRef } from 'react'
import { scanInput, scanOutput, scanBatch } from '../api/client'
import type { ScanResult, BatchScanResult } from '../api/client'
import { Badge, useToast } from '../components'

type ScanMode = 'input' | 'output' | 'code_review'

export default function ScanConsole() {
  const { toast } = useToast()
  const [mode, setMode] = useState<ScanMode>('input')
  const [content, setContent] = useState('')
  const [batchPath, setBatchPath] = useState('')
  const [userId, setUserId] = useState('test-user')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [batchResult, setBatchResult] = useState<BatchScanResult[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<{ mode: ScanMode; content: string; blocked: boolean; time: string }[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleScan = async () => {
    if (mode === 'code_review') {
      if (!batchPath.trim()) { toast('Enter a file or directory path', 'warning'); return }
    } else {
      if (!content.trim()) { toast('Enter content to scan', 'warning'); return }
    }

    setLoading(true)
    setError(null)
    setResult(null)
    setBatchResult(null)

    try {
      if (mode === 'input') {
        const r = await scanInput(content, userId || undefined)
        setResult(r)
        setHistory(prev => [{ mode, content: content.slice(0, 60), blocked: r.blocked, time: new Date().toLocaleTimeString() }, ...prev.slice(0, 19)])
      } else if (mode === 'output') {
        const r = await scanOutput(content, userId || undefined)
        setResult(r)
        setHistory(prev => [{ mode, content: content.slice(0, 60), blocked: r.blocked, time: new Date().toLocaleTimeString() }, ...prev.slice(0, 19)])
      } else {
        const r = await scanBatch(batchPath, userId || undefined)
        setBatchResult(r.results)
        setHistory(prev => [{ mode, content: batchPath, blocked: r.summary.total_findings > 0, time: new Date().toLocaleTimeString() }, ...prev.slice(0, 19)])
        toast(`Scanned ${r.summary.files_scanned} files, ${r.summary.total_findings} findings`, r.summary.total_findings > 0 ? 'warning' : 'success')
      }
    } catch (e: any) {
      setError(e.message)
    }
    setLoading(false)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Scan Console</h2>
          <p className="text-sm text-slate-400 mt-0.5">Test security rules interactively</p>
        </div>
        <div className="flex gap-1 bg-slate-100 p-0.5 rounded-lg">
          {([
            { key: 'input', label: 'Input Scan', icon: '📥' },
            { key: 'output', label: 'Output Scan', icon: '📤' },
            { key: 'code_review', label: 'Code Review', icon: '🔍' },
          ] as const).map(t => (
            <button
              key={t.key}
              onClick={() => { setMode(t.key); setResult(null); setBatchResult(null); setError(null) }}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-md font-medium transition-colors ${
                mode === t.key ? 'bg-white text-slate-800 shadow-sm' : 'text-slate-500 hover:text-slate-700'
              }`}
            >
              <span>{t.icon}</span>
              <span>{t.label}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left: Input */}
        <div className="lg:col-span-3 space-y-4">
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
            <h3 className="text-sm font-semibold text-slate-700 mb-3">
              {mode === 'input' ? 'Input Content' : mode === 'output' ? 'Output Content' : 'File / Directory Path'}
            </h3>

            {mode === 'code_review' ? (
              <div>
                <div className="flex gap-2 mb-3">
                  <input
                    type="text"
                    placeholder="/path/to/file.py or /path/to/directory"
                    value={batchPath}
                    onChange={e => setBatchPath(e.target.value)}
                    className="flex-1 border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                  <input
                    type="file"
                    ref={fileInputRef}
                    className="hidden"
                    onChange={e => {
                      const file = e.target.files?.[0]
                      if (file) {
                        // Can't get real path from browser, so just show what was selected
                        setBatchPath(file.name)
                      }
                    }}
                  />
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="px-3 py-2 text-sm border border-slate-300 rounded-lg hover:bg-slate-50"
                  >
                    Browse
                  </button>
                </div>
                <p className="text-xs text-slate-400">Enter a server-side path the Kasra API can access, or select a filename.</p>
              </div>
            ) : (
              <textarea
                value={content}
                onChange={e => setContent(e.target.value)}
                placeholder={mode === 'input'
                  ? 'Paste user input to test...\n\ne.g. password=secret123'
                  : 'Paste AI output to test...\n\ne.g. Here is your API key: sk-proj-...'
                }
                rows={10}
                className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-y"
              />
            )}

            <div className="flex items-center gap-3 mt-3">
              <div className="flex-1">
                <label className="text-xs text-slate-500 mb-1 block">User ID (optional)</label>
                <input
                  type="text"
                  value={userId}
                  onChange={e => setUserId(e.target.value)}
                  placeholder="user-id"
                  className="w-full border border-slate-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>
              <button
                onClick={handleScan}
                disabled={loading}
                className="self-end px-5 py-1.5 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 disabled:opacity-50 transition-colors flex items-center gap-2"
              >
                {loading ? (
                  <><span className="inline-block w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Scanning...</>
                ) : (
                  <>{mode === 'code_review' ? '🔍 Scan' : '🚀 Scan'}</>
                )}
              </button>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="p-3 bg-red-50 text-red-700 rounded-lg border border-red-200 text-sm">
              {error}
            </div>
          )}

          {/* Result */}
          {result && (
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
              <div className={`px-5 py-3 border-b flex items-center justify-between ${
                result.blocked ? 'bg-red-50 border-red-200' : 'bg-emerald-50 border-emerald-200'
              }`}>
                <div className="flex items-center gap-2">
                  <span className="text-lg">{result.blocked ? '🚫' : result.triggered_rules.length > 0 ? '⚠️' : '✅'}</span>
                  <span className={`font-semibold text-sm ${result.blocked ? 'text-red-700' : 'text-emerald-700'}`}>
                    {result.blocked ? 'Blocked' : result.triggered_rules.length > 0 ? 'Flagged' : 'Passed'}
                  </span>
                </div>
                <span className="text-xs text-slate-400">{result.execution_time_ms.toFixed(1)} ms</span>
              </div>

              {result.triggered_rules.length > 0 ? (
                <div className="divide-y divide-slate-100">
                  {result.triggered_rules.map((tr, i) => (
                    <div key={i} className="px-5 py-3">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge>{tr.severity}</Badge>
                        <Badge>{tr.action}</Badge>
                        <span className="text-sm font-medium text-slate-700">{tr.rule_id}</span>
                      </div>
                      <p className="text-xs text-slate-500 mb-1">{tr.rule_name}</p>
                      <p className="text-xs text-slate-400">Matched: "{tr.matched_text}" ({tr.match_count}x)</p>
                      {tr.evidence.map((ev, j) => (
                        <p key={j} className="text-xs text-slate-400 mt-0.5">[{ev.source_layer}] {ev.reason}</p>
                      ))}
                    </div>
                  ))}
                  {result.warnings.length > 0 && (
                    <div className="px-5 py-2 bg-amber-50 text-xs text-amber-700">
                      {result.warnings.map((w, i) => <p key={i}>⚠ {w}</p>)}
                    </div>
                  )}
                </div>
              ) : (
                <div className="px-5 py-4 text-sm text-slate-500">No rules triggered.</div>
              )}
            </div>
          )}

          {/* Batch Result */}
          {batchResult && batchResult.length > 0 && (
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
              <div className="px-5 py-3 bg-slate-50 border-b border-slate-200 font-semibold text-sm text-slate-700">
                Code Review Results ({batchResult.length} files)
              </div>
              {batchResult.map((br, i) => (
                <div key={i} className="border-b border-slate-100 px-5 py-3">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-mono text-indigo-600">{br.file}</span>
                    {br.error && <span className="text-xs text-red-500">{br.error}</span>}
                  </div>
                  {br.triggered_rules.map((tr, j) => (
                    <div key={j} className="flex items-center gap-2 ml-4 mt-1 text-xs">
                      <Badge>{tr.severity}</Badge>
                      <span className="text-slate-600">{tr.rule_id}</span>
                      <span className="text-slate-400">{tr.rule_name}</span>
                    </div>
                  ))}
                  {br.triggered_rules.length === 0 && !br.error && (
                    <p className="text-xs text-slate-400 ml-4">No findings</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: History */}
        <div className="lg:col-span-2">
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4">
            <h3 className="text-sm font-semibold text-slate-700 mb-3">Scan History</h3>
            {history.length === 0 ? (
              <p className="text-xs text-slate-400 text-center py-8">Run some scans to see history</p>
            ) : (
              <div className="space-y-2">
                {history.map((h, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs border-b border-slate-50 pb-2">
                    <span>{h.blocked ? '🚫' : '✅'}</span>
                    <span className="text-slate-500 font-medium uppercase text-[10px] w-12">{h.mode === 'code_review' ? 'CR' : h.mode}</span>
                    <span className="text-slate-600 truncate flex-1">{h.content}</span>
                    <span className="text-slate-400">{h.time}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
