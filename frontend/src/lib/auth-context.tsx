import { createContext, useContext, useState, type ReactNode } from 'react'

import * as api from '@/lib/api'

interface AuthContextValue {
  isAuthenticated: boolean
  login: (username: string, password: string, honeypot?: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(() => !!api.getToken())

  async function login(username: string, password: string, honeypot = '') {
    const token = await api.login(username, password, honeypot)
    api.setToken(token)
    setIsAuthenticated(true)
  }

  function logout() {
    api.clearToken()
    setIsAuthenticated(false)
  }

  return <AuthContext.Provider value={{ isAuthenticated, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth deve ser usado dentro de um AuthProvider')
  return ctx
}
