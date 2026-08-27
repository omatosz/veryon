import { useState, type ReactNode } from 'react'
import { Bell, Menu, Search } from 'lucide-react'

import { Sidebar } from '@/components/layout/Sidebar'

interface AppShellProps {
  title: string
  children: ReactNode
}

export function AppShell({ title, children }: AppShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="flex min-w-0 grow flex-col">
        <div className="flex h-16 shrink-0 items-center justify-between border-b border-border px-4 sm:px-8">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setSidebarOpen(true)}
              className="text-muted-foreground transition-colors hover:text-foreground lg:hidden"
            >
              <Menu className="h-[18px] w-[18px]" strokeWidth={1.75} />
            </button>
            <h1 className="font-heading text-[19px] font-semibold text-foreground">{title}</h1>
          </div>
          <div className="flex items-center gap-4">
            <Search className="hidden h-[18px] w-[18px] cursor-pointer text-muted-foreground sm:block" strokeWidth={1.75} />
            <Bell className="h-[18px] w-[18px] cursor-pointer text-muted-foreground" strokeWidth={1.75} />
            <div className="flex h-[30px] w-[30px] items-center justify-center rounded-full bg-primary/14 font-heading text-xs font-semibold text-primary">
              AD
            </div>
          </div>
        </div>

        {children}
      </div>
    </div>
  )
}
