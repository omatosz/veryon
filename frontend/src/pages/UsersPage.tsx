import { useCallback, useEffect, useState } from 'react'
import { KeyRound, Loader2, Plus, ShieldCheck, UserCheck, UserX, Users } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { StatPill } from '@/components/ui/stat-pill'
import { useAuth } from '@/lib/auth-context'
import { createUser, listUsers, updateUser, type ApiUser, type UserRole } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

const PAPEL: Record<UserRole, { nome: string; explica: string }> = {
  admin: {
    nome: 'Administrador',
    explica: 'bloqueia IP, liga política, mexe em retenção e gerencia usuários',
  },
  analyst: {
    nome: 'Analista',
    explica: 'lê tudo e tria alerta, vulnerabilidade e achado de API',
  },
}

const SENHA_MINIMA = 12

function Formulario({
  onCriado,
  onCancelar,
}: {
  onCriado: () => void
  onCancelar: () => void
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<UserRole>('analyst')
  const [erro, setErro] = useState<string | null>(null)
  const [salvando, setSalvando] = useState(false)

  async function salvar() {
    setErro(null)
    if (password.length < SENHA_MINIMA) {
      setErro(`A senha precisa de pelo menos ${SENHA_MINIMA} caracteres.`)
      return
    }
    setSalvando(true)
    try {
      await createUser({ username: username.trim().toLowerCase(), password, role })
      onCriado()
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Não foi possível criar')
    } finally {
      setSalvando(false)
    }
  }

  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <h2 className="font-heading text-sm font-semibold text-foreground">Novo usuário</h2>

      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <div>
          <label className="text-[11.5px] text-muted-foreground">Nome de acesso</label>
          <Input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="joana.silva"
            autoComplete="off"
          />
          <p className="mt-1 text-[11px] text-muted-foreground">
            Letras minúsculas, números, ponto, hífen e sublinhado. É o nome que vai aparecer no
            histórico de quem fez cada ação.
          </p>
        </div>

        <div>
          <label className="text-[11.5px] text-muted-foreground">Senha</label>
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
          />
          <p className="mt-1 text-[11px] text-muted-foreground">
            Mínimo de {SENHA_MINIMA} caracteres. Esta senha abre um painel que bloqueia IP e
            desliga defesa, e não há segundo fator para compensar.
          </p>
        </div>
      </div>

      <div className="mt-3">
        <label className="text-[11.5px] text-muted-foreground">Papel</label>
        <div className="mt-1 flex flex-wrap gap-2">
          {(Object.keys(PAPEL) as UserRole[]).map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => setRole(p)}
              className={
                role === p
                  ? 'rounded-md border border-primary bg-primary/12 px-3 py-1.5 text-xs font-medium text-primary'
                  : 'rounded-md border border-border px-3 py-1.5 text-xs font-medium text-muted-foreground transition-opacity hover:opacity-80'
              }
            >
              {PAPEL[p].nome}
            </button>
          ))}
        </div>
        <p className="mt-1 text-[11px] text-muted-foreground">{PAPEL[role].explica}</p>
      </div>

      {erro && <p className="mt-3 text-[12px] text-destructive">{erro}</p>}

      <div className="mt-4 flex gap-2">
        <Button onClick={() => void salvar()} disabled={salvando || !username.trim() || !password}>
          {salvando && <Loader2 className="h-4 w-4 animate-spin" />}
          Criar
        </Button>
        <Button variant="outline" onClick={onCancelar} disabled={salvando}>
          Cancelar
        </Button>
      </div>
    </div>
  )
}

function Linha({
  usuario,
  souEu,
  ultimoAdmin,
  onMudou,
}: {
  usuario: ApiUser
  souEu: boolean
  ultimoAdmin: boolean
  onMudou: () => void
}) {
  const [ocupado, setOcupado] = useState(false)
  const [erro, setErro] = useState<string | null>(null)
  const [trocandoSenha, setTrocandoSenha] = useState(false)
  const [senha, setSenha] = useState('')

  async function aplicar(mudanca: Partial<{ role: UserRole; is_active: boolean; password: string }>) {
    setOcupado(true)
    setErro(null)
    try {
      await updateUser(usuario.id, mudanca)
      setTrocandoSenha(false)
      setSenha('')
      onMudou()
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Não foi possível salvar')
    } finally {
      setOcupado(false)
    }
  }

  // As duas travas do servidor, repetidas aqui só para explicar o botão
  // apagado. Quem manda continua sendo a API.
  const travaPapel = souEu
    ? 'Você não pode mudar o próprio papel. Peça a outro administrador.'
    : ultimoAdmin
      ? 'É o último administrador ativo. Promova outro antes.'
      : null
  const travaAtivo = souEu
    ? 'Você não pode desligar a própria conta.'
    : ultimoAdmin
      ? 'É o último administrador ativo. Promova outro antes.'
      : null

  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[13px] font-medium text-foreground">
              {usuario.username}
            </span>
            {souEu && (
              <span className="rounded-full border border-primary/40 px-1.5 py-0.5 text-[10px] text-primary">
                você
              </span>
            )}
            {!usuario.is_active && (
              <span className="rounded-full border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">
                desligado
              </span>
            )}
          </div>
          <p className="mt-0.5 text-[11.5px] text-muted-foreground">
            {PAPEL[usuario.role].explica} · desde {formatDateTime(usuario.created_at)}
          </p>
        </div>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={ocupado || !!travaPapel}
            title={travaPapel ?? undefined}
            onClick={() => void aplicar({ role: usuario.role === 'admin' ? 'analyst' : 'admin' })}
            className="flex h-8 items-center gap-1.5 rounded-md border border-border px-3 text-xs font-medium text-foreground transition-opacity hover:opacity-85 disabled:opacity-40"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            {usuario.role === 'admin' ? 'Rebaixar a analista' : 'Promover a admin'}
          </button>

          <button
            type="button"
            disabled={ocupado || (usuario.is_active && !!travaAtivo)}
            title={usuario.is_active ? (travaAtivo ?? undefined) : undefined}
            onClick={() => void aplicar({ is_active: !usuario.is_active })}
            className="flex h-8 items-center gap-1.5 rounded-md border border-border px-3 text-xs font-medium text-foreground transition-opacity hover:opacity-85 disabled:opacity-40"
          >
            {usuario.is_active ? (
              <>
                <UserX className="h-3.5 w-3.5" />
                Desligar
              </>
            ) : (
              <>
                <UserCheck className="h-3.5 w-3.5" />
                Religar
              </>
            )}
          </button>

          <button
            type="button"
            disabled={ocupado}
            onClick={() => setTrocandoSenha((v) => !v)}
            className="flex h-8 items-center gap-1.5 rounded-md border border-border px-3 text-xs font-medium text-foreground transition-opacity hover:opacity-85 disabled:opacity-40"
          >
            <KeyRound className="h-3.5 w-3.5" />
            Trocar senha
          </button>
        </div>
      </div>

      {trocandoSenha && (
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <div className="min-w-[240px] flex-1">
            <label className="text-[11.5px] text-muted-foreground">Senha nova</label>
            <Input
              type="password"
              value={senha}
              onChange={(e) => setSenha(e.target.value)}
              autoComplete="new-password"
            />
          </div>
          <Button
            onClick={() => void aplicar({ password: senha })}
            disabled={ocupado || senha.length < SENHA_MINIMA}
          >
            {ocupado && <Loader2 className="h-4 w-4 animate-spin" />}
            Salvar senha
          </Button>
          <span className="text-[11px] text-muted-foreground">
            Mínimo de {SENHA_MINIMA} caracteres. A sessão aberta da pessoa continua valendo até o
            token expirar; para cortar na hora, desligue e religue a conta.
          </span>
        </div>
      )}

      {erro && <p className="mt-2 text-[12px] text-destructive">{erro}</p>}
    </div>
  )
}

export function UsersPage() {
  const { user: eu } = useAuth()
  const [usuarios, setUsuarios] = useState<ApiUser[] | null>(null)
  const [erro, setErro] = useState<string | null>(null)
  const [criando, setCriando] = useState(false)

  const carregar = useCallback(async () => {
    try {
      setUsuarios(await listUsers())
      setErro(null)
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Falha ao carregar')
    }
  }, [])

  useEffect(() => {
    void carregar()
  }, [carregar])

  if (erro && !usuarios) return <ErrorState message={erro} />
  if (!usuarios) return <LoadingState />

  const adminsAtivos = usuarios.filter((u) => u.role === 'admin' && u.is_active)

  return (
    <AppShell title="Usuários">
      <p className="text-[13px] text-muted-foreground">
        Quem entra no Veryon e o que cada um pode fazer. Analista lê tudo e tria; administrador
        também bloqueia IP, liga política e mexe em retenção.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <StatPill
          icon={Users}
          tone="text-primary"
          bg="bg-primary/12"
          value={usuarios.filter((u) => u.is_active).length}
          label="contas ativas"
          hint={`${usuarios.length} no total`}
        />
        <StatPill
          icon={ShieldCheck}
          tone="text-success"
          bg="bg-success/12"
          value={adminsAtivos.length}
          label="administradores"
          hint={adminsAtivos.length === 1 ? 'só um: promova outro' : 'podem tudo'}
        />

        <div className="ml-auto">
          <Button onClick={() => setCriando((v) => !v)}>
            <Plus className="h-4 w-4" />
            Novo usuário
          </Button>
        </div>
      </div>

      {erro && <ErrorState message={erro} />}

      {criando && (
        <Formulario
          onCriado={() => {
            setCriando(false)
            void carregar()
          }}
          onCancelar={() => setCriando(false)}
        />
      )}

      <div className="flex flex-col gap-2">
        {usuarios.map((u) => (
          <Linha
            key={u.id}
            usuario={u}
            souEu={u.id === eu?.id}
            ultimoAdmin={u.role === 'admin' && u.is_active && adminsAtivos.length <= 1}
            onMudou={() => void carregar()}
          />
        ))}
      </div>

      <p className="text-[11.5px] text-muted-foreground">
        Conta desligada perde acesso na hora, inclusive com o token que já estava aberto. Não
        existe apagar usuário de propósito: o nome de quem bloqueou um IP ou fechou um alerta fica
        gravado no histórico, e nome sem dono é pior que conta desligada.
      </p>
    </AppShell>
  )
}
