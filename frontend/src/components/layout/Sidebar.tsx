import { useEffect, useState } from 'react'
import { useNavigate, NavLink } from 'react-router-dom'
import { Activity, FileText, LayoutGrid, LogOut, ShieldAlert, ShieldCheck, Telescope, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { listAlerts } from '@/lib/api'
import { useAuth } from '@/lib/auth-context'

interface SidebarProps {
  open?: boolean
  onClose?: () => void
}

export function Sidebar({ open = false, onClose }: SidebarProps) {
  const [openAlertCount, setOpenAlertCount] = useState<number | null>(null)
  const { logout } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    let cancelled = false
    listAlerts({ limit: 500 })
      .then((alerts) => {
        if (!cancelled) setOpenAlertCount(alerts.filter((a) => a.status !== 'closed').length)
      })
      .catch(() => {
        if (!cancelled) setOpenAlertCount(null)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const navGroups: { label: string | null; items: { to: string; label: string; icon: typeof LayoutGrid; badge?: number | null }[] }[] = [
    { label: null, items: [{ to: '/dashboard', label: 'Dashboard', icon: LayoutGrid }] },
    {
      label: 'Monitoramento',
      items: [
        { to: '/alerts', label: 'Alertas', icon: ShieldAlert, badge: openAlertCount },
        { to: '/events', label: 'Eventos', icon: Activity },
      ],
    },
    { label: 'Inteligência', items: [{ to: '/threat-intel', label: 'Threat Intel', icon: Telescope }] },
    { label: 'Operação', items: [{ to: '/reports', label: 'Relatórios', icon: FileText }] },
  ]

  function handleLogout() {
    logout()
    navigate('/')
  }

  return (
    <>
      {open && (
        <div onClick={onClose} className="fixed inset-0 z-30 bg-black/50 backdrop-blur-[1px] lg:hidden" />
      )}

      <div
        className={cn(
          'fixed inset-y-0 left-0 z-40 flex w-[240px] shrink-0 flex-col border-r border-border bg-sidebar p-3.5 transition-transform duration-300 ease-out lg:relative lg:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex items-center justify-between gap-2.5 px-2 pb-5 pt-1.5">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="h-[26px] w-[26px] text-primary" strokeWidth={2.2} />
            <span className="font-heading text-[15px] font-semibold tracking-tight text-foreground">Veryon</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-muted-foreground transition-colors hover:text-foreground lg:hidden"
          >
            <X className="h-[18px] w-[18px]" />
          </button>
        </div>

        <nav className="flex flex-col gap-3.5 overflow-y-auto">
          {navGroups.map((group, i) => (
            <div key={group.label ?? `group-${i}`} className="flex flex-col gap-0.5">
              {group.label && (
                <span className="px-3 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                  {group.label}
                </span>
              )}
              {group.items.map(({ to, label, icon: Icon, badge }) => (
                <NavLink
                  key={to}
                  to={to}
                  onClick={onClose}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-3 rounded-lg border-l-2 border-transparent px-3 py-2.5 text-[13.5px] font-medium text-muted-foreground transition-colors hover:bg-white/[0.04]',
                      isActive && 'border-primary bg-primary/10 text-primary',
                    )
                  }
                >
                  <Icon className="h-[18px] w-[18px]" strokeWidth={1.75} />
                  <span>{label}</span>
                  {!!badge && (
                    <span className="ml-auto rounded-full bg-destructive/16 px-1.5 py-0.5 font-mono text-[10.5px] text-destructive">
                      {badge}
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="grow" />

        <div className="flex items-center gap-2.5 border-t border-border px-2 py-2.5">
          <div className="flex h-[30px] w-[30px] items-center justify-center rounded-lg bg-primary/14 font-heading text-xs font-semibold text-primary">
            AD
          </div>
          <div className="flex flex-col leading-tight">
            <span className="text-[12.5px] font-medium text-foreground">admin</span>
            <span className="text-[10.5px] text-muted-foreground">Analista SOC</span>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            title="Sair"
            className="ml-auto flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive"
          >
            <LogOut className="h-[15px] w-[15px]" strokeWidth={1.75} />
          </button>
        </div>
      </div>
    </>
  )
}
