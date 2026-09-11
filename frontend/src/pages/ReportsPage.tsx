import { FileText, FolderOpen, ListChecks, Terminal } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'

// A tela mostrava dois relatórios, contagens e botões de download vindos de
// mock-data.ts, e nada disso existia. Enquanto não houver rota de API para
// listar e baixar (está no roadmap do README), o honesto é dizer como gerar e
// onde o arquivo cai, em vez de inventar número.
const PASSOS = [
  {
    icone: Terminal,
    titulo: 'Como gerar',
    texto: 'Num terminal (Git Bash ou PowerShell), dentro da pasta do projeto:',
    codigo: 'docker compose --profile tools run --rm reports',
    rodape: 'O padrão são os últimos 7 dias. Para outro período, acrescente --days 30 no fim do comando.',
  },
  {
    icone: FolderOpen,
    titulo: 'Onde o arquivo cai',
    texto: 'Na pasta reports/output, dentro do projeto. Sai um HTML e um PDF, com data e hora no nome.',
    codigo: 'reports/output/relatorio-soc-AAAAMMDD-HHMMSS.pdf',
    rodape: 'A pasta está no .gitignore: relatório gerado não vai para o repositório.',
  },
  {
    icone: ListChecks,
    titulo: 'O que tem dentro',
    texto: 'Eventos do período, alertas por severidade, técnicas MITRE que apareceram e achados do scanner.',
    codigo: null,
    rodape: 'O serviço de relatório não fica ligado: sobe, gera e sai. Por isso ele não aparece no docker compose ps.',
  },
]

export function ReportsPage() {
  return (
    <AppShell title="Relatórios">
      <div className="grow overflow-y-auto px-4 pb-14 pt-7 sm:px-8">
        <div className="flex items-start gap-3.5 rounded-xl border border-border bg-card p-5.5">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
            <FileText className="h-[18px] w-[18px] text-primary" strokeWidth={1.75} />
          </div>
          <div>
            <h2 className="font-heading text-[14.5px] font-semibold text-foreground">
              O relatório sai pelo terminal, não por esta tela
            </h2>
            <p className="mt-1 text-[12.5px] text-muted-foreground">
              Ainda não existe rota de API para listar ou baixar relatório, então esta tela não mostra contagem
              nem arquivo: qualquer número aqui seria inventado. O relatório de verdade é gerado por um serviço
              à parte, sob demanda, em HTML e PDF.
            </p>
          </div>
        </div>

        <div className="mt-5 grid gap-3.5 lg:grid-cols-3">
          {PASSOS.map((p) => (
            <div key={p.titulo} className="flex flex-col gap-3 rounded-xl border border-border bg-card p-5.5">
              <div className="flex items-center gap-2">
                <p.icone className="h-4 w-4 text-primary" strokeWidth={1.75} />
                <h3 className="font-heading text-[13.5px] font-semibold text-foreground">{p.titulo}</h3>
              </div>
              <p className="text-[12.5px] text-muted-foreground">{p.texto}</p>
              {p.codigo && (
                <code className="block overflow-x-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-[11.5px] text-foreground">
                  {p.codigo}
                </code>
              )}
              <p className="mt-auto text-[11.5px] text-muted-foreground">{p.rodape}</p>
            </div>
          ))}
        </div>
      </div>
    </AppShell>
  )
}
