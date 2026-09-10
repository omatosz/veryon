import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'

import * as api from '@/lib/api'

interface AuthContextValue {
  isAuthenticated: boolean
  /** Quem está logado. Fica null enquanto o /auth/me não respondeu. */
  user: api.ApiUser | null
  /** Falso enquanto o papel ainda não chegou, para a tela não piscar botão de
   *  admin na cara de quem é analista. */
  isAdmin: boolean
  carregandoUsuario: boolean
  login: (username: string, password: string, honeypot?: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(() => !!api.getToken())
  const [user, setUser] = useState<api.ApiUser | null>(null)
  const [carregandoUsuario, setCarregandoUsuario] = useState(false)

  // O papel vem do servidor a cada carga da página, e não do token. É o que
  // faz "tiraram meu admin" valer no próximo F5 em vez de daqui a uma hora.
  const carregarUsuario = useCallback(async () => {
    if (!api.getToken()) {
      setUser(null)
      return
    }
    setCarregandoUsuario(true)
    try {
      setUser(await api.getMe())
    } catch {
      // Token velho ou conta desligada. O interceptor da api já derruba a
      // sessão nesse caso; aqui só não deixamos um usuário fantasma na tela.
      setUser(null)
    } finally {
      setCarregandoUsuario(false)
    }
  }, [])

  useEffect(() => {
    if (isAuthenticated) void carregarUsuario()
  }, [isAuthenticated, carregarUsuario])

  async function login(username: string, password: string, honeypot = '') {
    const token = await api.login(username, password, honeypot)
    api.setToken(token)
    setIsAuthenticated(true)
    await carregarUsuario()
  }

  function logout() {
    api.clearToken()
    setUser(null)
    setIsAuthenticated(false)
  }

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        user,
        isAdmin: user?.role === 'admin',
        carregandoUsuario,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth deve ser usado dentro de um AuthProvider')
  return ctx
}
