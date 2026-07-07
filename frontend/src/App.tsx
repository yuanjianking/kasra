import { Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import AuditLogs from './pages/AuditLogs'
import Rules from './pages/Rules'
import UserBehavior from './pages/UserBehavior'

const navItems = [
  { path: '/', label: 'Dashboard', icon: '📊' },
  { path: '/audit-logs', label: 'Audit Logs', icon: '📋' },
  { path: '/rules', label: 'Rules', icon: '🛡️' },
  { path: '/user-behavior', label: 'User Behavior', icon: '👤' },
]

function App() {
  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <nav className="w-56 bg-slate-900 text-white flex flex-col">
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
        <div className="p-4 border-t border-slate-700 text-xs text-slate-500">
          v0.1.0
        </div>
      </nav>

      {/* Content */}
      <main className="flex-1 overflow-auto">
        <div className="p-6 max-w-7xl mx-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/audit-logs" element={<AuditLogs />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/user-behavior" element={<UserBehavior />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}

export default App
