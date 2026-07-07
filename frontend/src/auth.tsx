import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'

interface AuthContextType {
  apiKey: string | null
  setApiKey: (key: string | null) => void
  isAuthenticated: boolean
  logout: () => void
}

const AuthContext = createContext<AuthContextType>({
  apiKey: null,
  setApiKey: () => {},
  isAuthenticated: false,
  logout: () => {},
})

export function AuthProvider({ children }: { children: ReactNode }) {
  const [apiKey, setApiKeyState] = useState<string | null>(() => {
    return localStorage.getItem('kasra_api_key')
  })

  const setApiKey = (key: string | null) => {
    setApiKeyState(key)
    if (key) {
      localStorage.setItem('kasra_api_key', key)
    } else {
      localStorage.removeItem('kasra_api_key')
    }
  }

  const logout = () => setApiKey(null)

  return (
    <AuthContext.Provider value={{ apiKey, setApiKey, isAuthenticated: !!apiKey, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
