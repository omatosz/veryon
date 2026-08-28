"""
Entrada de log de acesso vinda de fora.

E por aqui que o Veryon deixa de analisar so a si mesmo. O gateway, o nginx ou
o middleware da aplicacao do cliente manda os acessos em lote, e eles caem na
mesma tabela que o trafego observado localmente. Dali pra frente o motor de
sinais nao sabe nem se importa de onde veio.

Autenticacao e por chave estatica no cabecalho, nao pelo JWT do painel: quem
chama isso e servidor, nao pessoa, e servidor nao faz login.
"""

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException

from app.core import api_signals, api_traffic
from app.core.config import settings
from app.schemas import IngestBatch, IngestResult

router = APIRouter(prefix="/ingest", tags=["ingest"])


def _autorizar(chave: str | None) -> None:
    esperada = settings.ingest_api_key
    if not esperada:
        raise HTTPException(
            status_code=503,
            detail="Ingestao desligada. Defina INGEST_API_KEY no ambiente do backend.",
        )
    # compare_digest em vez de ==: comparacao normal sai mais cedo no primeiro
    # byte diferente, e isso da pra medir e usar pra adivinhar a chave.
    if not chave or not secrets.compare_digest(chave, esperada):
        raise HTTPException(status_code=401, detail="Chave de ingestao invalida")


@router.post("/api-logs", response_model=IngestResult)
async def ingest_api_logs(
    batch: IngestBatch,
    x_veryon_key: str | None = Header(default=None, alias="X-Veryon-Key"),
):
    """Recebe ate 500 acessos por chamada.

    Cai na mesma fila em memoria do trafego local, entao um lote grande nao
    segura a resposta esperando o banco."""
    _autorizar(x_veryon_key)

    agora = datetime.now(timezone.utc)
    aceitas = 0
    descartadas = 0

    for item in batch.requests:
        caminho = item.path or "/"
        if not caminho.startswith("/"):
            descartadas += 1
            continue

        api_traffic.enqueue(
            {
                "ts": item.ts or agora,
                "source": "ingest",
                "client_ip": item.client_ip,
                "method": (item.method or "GET").upper()[:8],
                "path": caminho[:300],
                # Sem tabela de rotas do cliente, o agrupamento sai da
                # normalizacao do caminho.
                "route": api_signals.normalize_route(caminho),
                "status_code": item.status_code,
                "duration_ms": item.duration_ms,
                "response_bytes": item.response_bytes,
                "user_agent": item.user_agent,
                "query": item.query,
                # O corpo entra so na busca por padrao de injecao e nao e
                # guardado. Log de acesso de cliente pode ter dado pessoal
                # dentro, e guardar isso seria criar um problema novo.
                "flags": {
                    "injection": api_signals.detect_injection(caminho, item.query, item.body)
                },
            }
        )
        aceitas += 1

    return IngestResult(aceitas=aceitas, descartadas=descartadas)
