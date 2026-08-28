import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'motion/react'
import { Eye, EyeOff, Loader2, X } from 'lucide-react'

import { BeamsBackground } from '@/components/ui/beams-background'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'
import { ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth-context'

type FormState = 'idle' | 'loading' | 'error'

export function LoginPage() {
  const [showPassword, setShowPassword] = useState(false)
  const [formState, setFormState] = useState<FormState>('idle')
  const [errorMessage, setErrorMessage] = useState('')
  const [shakeKey, setShakeKey] = useState(0)
  const { isAuthenticated, login } = useAuth()
  const navigate = useNavigate()

  if (isAuthenticated) return <Navigate to="/dashboard" replace />

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (formState === 'loading') return

    const data = new FormData(event.currentTarget)
    const username = String(data.get('username') ?? '')
    const password = String(data.get('password') ?? '')
    const honeypot = String(data.get('website') ?? '')

    setFormState('loading')
    try {
      await login(username, password, honeypot)
      navigate('/dashboard')
    } catch (err) {
      let message = 'Não foi possível conectar ao servidor'
      if (err instanceof ApiError) {
        if (err.status === 401) message = 'Usuário ou senha incorretos'
        else if (err.status === 429) message = 'Muitas tentativas — aguarde um minuto e tente de novo'
      }
      setErrorMessage(message)
      setFormState('error')
      setShakeKey((k) => k + 1)
      setTimeout(() => setFormState('idle'), 2000)
    }
  }

  return (
    <BeamsBackground intensity="medium">
      <div className="flex w-full max-w-[400px] flex-col items-center gap-8 px-4">
        <motion.div
          className="flex flex-col items-center gap-3.5"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <img src="/brand/veryon-mark-256.png" alt="" className="h-24 w-24" draggable={false} />
          <div className="text-center">
            <div className="font-heading text-[22px] font-semibold tracking-tight text-foreground">
              Veryon
            </div>
            <div className="mt-1 font-mono text-[11px] tracking-wide text-muted-foreground">
              PAINEL DE OPERAÇÕES
            </div>
          </div>
        </motion.div>

        <motion.form
          onSubmit={handleSubmit}
          className="flex w-full flex-col gap-5 rounded-2xl border border-white/10 bg-card/80 p-8 shadow-[0_24px_60px_rgba(0,0,0,0.4)] backdrop-blur-md"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
        >
          {/* honeypot anti-bot: invisível e inalcançável por teclado para gente de verdade */}
          <input
            type="text"
            name="website"
            tabIndex={-1}
            autoComplete="off"
            aria-hidden="true"
            className="absolute left-[-9999px] top-auto h-0 w-0 overflow-hidden opacity-0"
          />

          <div className="flex flex-col gap-2">
            <Label htmlFor="username" className="text-xs text-muted-foreground">
              Usuário
            </Label>
            <Input id="username" name="username" placeholder="admin" autoComplete="username" className="h-11" />
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="password" className="text-xs text-muted-foreground">
              Senha
            </Label>
            <div className="relative flex items-center">
              <Input
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                placeholder="••••••••"
                autoComplete="current-password"
                className="h-11 pr-11"
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                className="absolute right-2.5 flex items-center justify-center rounded-md p-1.5 text-muted-foreground transition-colors hover:text-foreground"
              >
                {showPassword ? <EyeOff className="h-[18px] w-[18px]" /> : <Eye className="h-[18px] w-[18px]" />}
              </button>
            </div>
          </div>

          <div className="-mt-1 flex items-center justify-between">
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
              <input type="checkbox" className="h-3.5 w-3.5 accent-primary" />
              Lembrar de mim
            </label>
            <a href="#" className="text-xs text-primary hover:underline">
              Esqueceu a senha?
            </a>
          </div>

          <motion.button
            key={shakeKey}
            type="submit"
            disabled={formState === 'loading'}
            animate={formState === 'error' ? { x: [0, -10, 10, -8, 8, -5, 5, -2, 2, 0] } : { x: 0 }}
            transition={{ duration: 0.5, ease: 'easeInOut' }}
            className={cn(
              'flex h-[46px] items-center justify-center gap-2 rounded-lg font-heading text-sm font-semibold transition-colors active:translate-y-px disabled:opacity-80',
              formState === 'error'
                ? 'bg-destructive text-white'
                : 'bg-primary text-primary-foreground hover:bg-primary/90',
            )}
          >
            <AnimatePresence mode="wait" initial={false}>
              {formState === 'loading' ? (
                <motion.span
                  key="loading"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-2"
                >
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Entrando…
                </motion.span>
              ) : formState === 'error' ? (
                <motion.span
                  key="error"
                  initial={{ opacity: 0, scale: 0.6 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.6 }}
                  className="flex items-center gap-2"
                >
                  <X className="h-4 w-4" strokeWidth={2.5} />
                  Credenciais inválidas
                </motion.span>
              ) : (
                <motion.span key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  Entrar
                </motion.span>
              )}
            </AnimatePresence>
          </motion.button>

          <AnimatePresence>
            {formState === 'error' && (
              <motion.p
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="text-center text-xs text-destructive"
              >
                {errorMessage}
              </motion.p>
            )}
          </AnimatePresence>
        </motion.form>
      </div>
    </BeamsBackground>
  )
}
