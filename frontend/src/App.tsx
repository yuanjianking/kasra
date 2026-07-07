import { useState, lazy, Suspense } from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth'
import Login from './pages/Login'
import ErrorBoundary from './ErrorBoundary'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const AuditLogs = lazy(() => import('./pages/AuditLogs'))
const Rules = lazy(() => import('./pages/Rules'))
const UserBehavior = lazy(() => import('./pages/UserBehavior'))

function LoadingSkeleton() {
  return (
    <div className="animate-pulse space-y-4 p-4">
      <div className="h-8 bg-slate-200 rounded w-48" />
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="h-24 bg-slate-200 rounded-xl" />
        ))}
      </div>
      <div className="h-64 bg-slate-200 rounded-xl" />
    </div>
  )
}

const navItems = [
  { path: '/', label: 'Dashboard', icon: '📊' },
  { path: '/audit-logs', label: 'Audit Logs', icon: '📋' },
  { path: '/rules', label: 'Rules', icon: '🛡️' },
  { path: '/user-behavior', label: 'User Behavior', icon: '👤' },
]

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ErrorBoundary>
  )
}

function AppContent() {
  const { isAuthenticated, logout } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  if (!isAuthenticated) {
    return <Login />
  }

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <nav className={`
        fixed md:static inset-y-0 left-0 z-40 w-56 bg-slate-900 text-white flex flex-col
        transform transition-transform duration-200 ease-in-out
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
        md:translate-x-0
      `}>
        <div className="p-4 border-b border-slate-700">
          <h1 className="text-lg font-bold">Kasra</h1>
          <p className="text-xs text-slate-400 mt-1">AI Development Security Governance Platform</p>
        </div>
        <div className="flex-1 p-2 space-y-1">
          {navItems.map(({ path, label, icon }) => (
            <NavLink
              key={path}
              to={path}
              end={path === '/'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-300 hover:bg-slate-800'
                }`
              }
            >
              <span>{icon}</span>
              {label}
            </NavLink>
          ))}
        </div>
        <div className="mt-auto pt-4 border-t border-slate-700 px-2">
          <button
            onClick={logout}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
          >
            <span>🚪</span>
            <span>Sign Out</span>
          </button>
        </div>
        <div className="p-4 border-t border-slate-700 text-xs text-slate-500">
          v0.1.0
        </div>
      </nav>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-30 md:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* Hamburger button */}
      <button
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="md:hidden fixed top-4 left-4 z-50 p-2 bg-slate-800 text-white rounded-lg"
      >
        {sidebarOpen ? '✕' : '☰'}
      </button>

      {/* Content */}
      <main className="flex-1 overflow-auto">
        <div className="p-6 max-w-7xl mx-auto">
          <Suspense fallback={<LoadingSkeleton />}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/audit-logs" element={<AuditLogs />} />
              <Route path="/rules" element={<Rules />} />
              <Route path="/user-behavior" element={<UserBehavior />} />
            </Routes>
          </Suspense>
        </div>
      </main>
    </div>
  )
}
