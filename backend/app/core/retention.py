"""Retencao e compressao: quem decide quanto tempo o dado fica.

A maquinaria mora no banco, ligada pela migration 0014. Este modulo e a parte
que o .env controla.

O problema que ele resolve: politica do Timescale e um registro dentro do
banco, entao trocar "90 dias" por "30 dias" exigiria migration nova, ou um
psql na mao em producao. Aqui, a cada boot, o backend compara o que o .env
pede com o que existe no banco e corrige a diferenca. Editar o .env e
reiniciar passa a ser suficiente.

Reconciliar, e nao criar: rodar duas vezes seguidas nao faz nada na segunda.
Isso importa porque roda em todo startup, inclusive nos restarts em cascata do
compose.

RETENTION_ENABLED=false nao e "nao mexer". E "parar de apagar e de comprimir",
e por isso remove as politicas que encontrar. Politica de retencao apaga dado
de verdade; se alguem desliga a chave, o que essa pessoa quer e que nada mais
seja apagado, nao que continue apagando em silencio.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import async_session

log = logging.getLogger("veryon.retention")

# Ordem fixa, do mais volumoso ao menos, que e como a tela mostra.
TABELAS = ("api_requests", "raw_events", "alerts")

RESUMO = {
    "api_requests": "trafego de API, uma linha por requisicao",
    "raw_events": "evento cru do honeypot e dos coletores",
    "alerts": "alerta gerado pelas regras",
}

# Os dois tipos de politica, com o nome de cada peca no Timescale.
POLITICAS = {
    "compress": {
        "proc": "policy_compression",
        "add": "add_compression_policy",
        "remove": "remove_compression_policy",
        "campo": "compress_after",
        "rotulo": "compressao",
    },
    "drop": {
        "proc": "policy_retention",
        "add": "add_retention_policy",
        "remove": "remove_retention_policy",
        "campo": "drop_after",
        "rotulo": "retencao",
    },
}


def desejado() -> dict[str, dict[str, int]]:
    """O que o .env pede, em dias. Zero quer dizer politica desligada."""
    return {
        "api_requests": {
            "compress": settings.api_requests_compress_after_days,
            "drop": settings.api_requests_drop_after_days,
        },
        "raw_events": {
            "compress": settings.raw_events_compress_after_days,
            "drop": settings.raw_events_drop_after_days,
        },
        "alerts": {
            "compress": settings.alerts_compress_after_days,
            "drop": settings.alerts_drop_after_days,
        },
    }


LER_POLITICAS = text(
    """
    SELECT j.hypertable_name,
           j.proc_name,
           j.job_id,
           (j.config->>'compress_after')::interval AS compress_after,
           (j.config->>'drop_after')::interval     AS drop_after,
           s.next_start,
           s.last_run_status,
           s.total_failures
      FROM timescaledb_information.jobs j
      LEFT JOIN timescaledb_information.job_stats s USING (job_id)
     WHERE j.proc_name IN ('policy_compression', 'policy_retention')
    """
)


async def _ler(sessao: AsyncSession) -> dict[tuple[str, str], dict[str, Any]]:
    """Politicas que existem hoje, indexadas por (tabela, tipo)."""
    achadas: dict[tuple[str, str], dict[str, Any]] = {}
    for linha in (await sessao.execute(LER_POLITICAS)).mappings():
        for tipo, spec in POLITICAS.items():
            if linha["proc_name"] != spec["proc"]:
                continue
            achadas[(linha["hypertable_name"], tipo)] = {
                "job_id": linha["job_id"],
                "prazo": linha[spec["campo"]],
                "next_start": linha["next_start"],
                "last_run_status": linha["last_run_status"],
                "total_failures": linha["total_failures"],
            }
    return achadas


async def aplicar() -> dict[str, Any]:
    """Deixa o banco igual ao .env. Devolve so o que mudou.

    Cada politica e tratada isolada, dentro do proprio try. Uma tabela sem
    compressao ligada (migration que caiu no bloco tolerante) nao pode impedir
    que as outras duas sejam ajustadas.
    """
    mudancas: list[str] = []
    falhas: list[str] = []

    async with async_session() as sessao:
        atuais = await _ler(sessao)
        alvo = desejado()

        for tabela in TABELAS:
            for tipo, spec in POLITICAS.items():
                # Com a chave geral desligada, o alvo de tudo passa a ser zero.
                dias = alvo[tabela][tipo] if settings.retention_enabled else 0
                atual = atuais.get((tabela, tipo))
                rotulo = spec["rotulo"]

                try:
                    if dias <= 0:
                        if atual is not None:
                            await sessao.execute(
                                text(f"SELECT {spec['remove']}('{tabela}', if_exists => true)")
                            )
                            mudancas.append(f"{tabela}: {rotulo} removida")
                        continue

                    if atual is not None and atual["prazo"] == timedelta(days=dias):
                        continue

                    if atual is not None:
                        # Nao existe "alterar prazo": a politica e um job, e o
                        # caminho suportado e trocar o job inteiro.
                        await sessao.execute(
                            text(f"SELECT {spec['remove']}('{tabela}', if_exists => true)")
                        )

                    await sessao.execute(
                        text(f"SELECT {spec['add']}('{tabela}', make_interval(days => :d))"),
                        {"d": dias},
                    )
                    antes = "nenhuma" if atual is None else f"{atual['prazo'].days}d"
                    mudancas.append(f"{tabela}: {rotulo} {antes} -> {dias}d")
                except Exception as exc:  # noqa: BLE001
                    await sessao.rollback()
                    falhas.append(f"{tabela}/{rotulo}: {exc}")

        await sessao.commit()

    for m in mudancas:
        log.info("retencao ajustada, %s", m)
    for f in falhas:
        log.warning("retencao nao aplicada, %s", f)

    return {"ligada": settings.retention_enabled, "mudancas": mudancas, "falhas": falhas}


ESTADO = text(
    """
    SELECT h.hypertable_name                                   AS tabela,
           hypertable_size(h.hypertable_name::regclass)        AS bytes_agora,
           c.total_chunks,
           COALESCE(c.number_compressed_chunks, 0)             AS chunks_comprimidos,
           COALESCE(c.before_compression_total_bytes, 0)       AS bytes_antes,
           COALESCE(c.after_compression_total_bytes, 0)        AS bytes_depois,
           (SELECT min(range_start)
              FROM timescaledb_information.chunks ch
             WHERE ch.hypertable_name = h.hypertable_name)     AS mais_antigo
      FROM timescaledb_information.hypertables h
      LEFT JOIN LATERAL hypertable_compression_stats(h.hypertable_name::regclass) c ON true
     WHERE h.hypertable_name = ANY(:tabelas)
    """
)


async def status() -> list[dict[str, Any]]:
    """Foto de cada tabela: tamanho, quanto a compressao ja economizou e qual
    politica esta valendo.

    E a resposta para "o banco vai encher?" sem ninguem precisar abrir psql.

    Tamanho vem de hypertable_size, que ja conta o chunk comprimido pelo que
    ele ocupa hoje. bytes_antes e bytes_depois falam so dos chunks que foram
    comprimidos, entao a economia mostrada e sempre a real, nunca projetada.

    A contagem e count(*) exato, e nao approximate_row_count, que mente feio
    depois que a compressao entra: neste banco ele devolveu 172 para uma
    tabela com 11936 linhas, porque so enxerga a linha fisica do chunk
    comprimido, e uma linha fisica guarda ate mil linhas logicas. O count
    exato sai barato justamente por causa da compressao: no chunk comprimido
    ele le a contagem que ja esta gravada em cada lote, sem descomprimir nada.
    """
    async with async_session() as sessao:
        atuais = await _ler(sessao)
        linhas = (
            await sessao.execute(ESTADO, {"tabelas": list(TABELAS)})
        ).mappings().all()
        # Nome de tabela vem da constante TABELAS, nunca de quem chamou.
        contagem = {
            tabela: (await sessao.execute(text(f"SELECT count(*) FROM {tabela}"))).scalar_one()
            for tabela in TABELAS
        }

    por_tabela = {l["tabela"]: l for l in linhas}
    alvo = desejado()
    saida: list[dict[str, Any]] = []

    for tabela in TABELAS:
        l = por_tabela.get(tabela)
        if l is None:
            continue

        economia = None
        antes, depois = l["bytes_antes"], l["bytes_depois"]
        if antes and depois:
            economia = round(antes / depois, 1)

        politicas: dict[str, Any] = {}
        for tipo, spec in POLITICAS.items():
            atual = atuais.get((tabela, tipo))
            pedido = alvo[tabela][tipo] if settings.retention_enabled else 0
            politicas[tipo] = {
                "dias_no_banco": atual["prazo"].days if atual else None,
                "dias_no_env": pedido or None,
                # Divergencia so aparece se alguem mexeu no banco na mao depois
                # do boot, ou se o aplicar() falhou naquela tabela.
                "em_dia": (atual["prazo"].days if atual else 0) == pedido,
                "proxima_execucao": atual["next_start"] if atual else None,
                "ultima_execucao": atual["last_run_status"] if atual else None,
                "falhas": atual["total_failures"] if atual else None,
            }

        saida.append(
            {
                "tabela": tabela,
                "resumo": RESUMO[tabela],
                "linhas": contagem[tabela],
                "bytes": l["bytes_agora"],
                "chunks": l["total_chunks"] or 0,
                "chunks_comprimidos": l["chunks_comprimidos"],
                "bytes_antes_da_compressao": antes or None,
                "bytes_depois_da_compressao": depois or None,
                "economia": economia,
                "dado_mais_antigo": l["mais_antigo"],
                "politicas": politicas,
            }
        )

    return saida


async def rodar_agora(incluir_retencao: bool = False) -> dict[str, Any]:
    """Executa as politicas na hora, sem esperar o agendador.

    Serve para duas coisas: demonstrar o efeito sem esperar um dia, e esvaziar
    o acumulado antes de uma manutencao. Nao burla prazo nenhum, so antecipa o
    relogio: um chunk dentro do prazo continua intocado.

    Por padrao roda so a compressao, que e reversivel. A retencao apaga chunk,
    e antecipar isso em um clique e o tipo de coisa que ninguem quer descobrir
    depois. Quem quiser precisa pedir, e por isso incluir_retencao nasce falso.

    run_job nao roda dentro de transacao, entao cada um vai no proprio
    autocommit.
    """
    resultado: list[dict[str, Any]] = []

    async with async_session() as sessao:
        atuais = await _ler(sessao)

    for (tabela, tipo), politica in sorted(atuais.items()):
        if tabela not in TABELAS:
            continue
        if tipo == "drop" and not incluir_retencao:
            continue
        try:
            async with async_session() as sessao:
                conexao = await sessao.connection(
                    execution_options={"isolation_level": "AUTOCOMMIT"}
                )
                await conexao.execute(
                    text("CALL run_job(:job)"), {"job": politica["job_id"]}
                )
            ok, detalhe = True, "ok"
        except Exception as exc:  # noqa: BLE001
            ok, detalhe = False, str(exc)[:300]
        resultado.append(
            {
                "tabela": tabela,
                "politica": POLITICAS[tipo]["rotulo"],
                "ok": ok,
                "detalhe": detalhe,
            }
        )

    return {"execucoes": resultado}
