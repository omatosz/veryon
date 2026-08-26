import { AlertTriangle, Loader2 } from 'lucide-react'

export function LoadingState({ label = 'Carregando…' }: { label?: string }) {
  return (
    <div className="flex grow flex-col items-center justify-center gap-2.5 text-muted-foreground">
      <Loader2 className="h-5 w-5 animate-spin" />
      <span className="text-sm">{label}</span>
    </div>
  )
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex grow flex-col items-center justify-center gap-2 text-center">
      <AlertTriangle className="h-6 w-6 text-destructive" strokeWidth={1.5} />
      <span className="text-sm text-foreground">Não foi possível carregar os dados</span>
      <span className="max-w-sm text-xs text-muted-foreground">{message}</span>
    </div>
  )
}
