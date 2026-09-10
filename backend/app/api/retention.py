"""Estado do armazenamento e das politicas de retencao.

Responde a pergunta que ninguem faz antes de precisar: quanto o banco esta
ocupando e quando ele vai parar de crescer. Hoje a unica forma de saber e
abrir psql e conhecer os catalogos do Timescale, o que serve para o dono do
projeto e para mais ninguem.

O que os tres endpoints fazem, e por que sao tres:

  GET  /retention/status  le. Nao muda nada.
  POST /retention/apply   reconcilia o banco com o .env, igual ao que roda no
                          boot. Existe para nao ter que reiniciar o backend
                          depois de editar um prazo.
  POST /retention/run     antecipa a proxima execucao das politicas. Por
                          padrao so a compressao; a retencao, que apaga, so
                          entra se for pedida.

NOTA DE ESTRUTURA: mesma escolha do router de notificacoes, e pelo mesmo
motivo. Schemas neste arquivo e consultas em text(), porque db/models.py e
schemas.py tem alteracao nao commitada do rastreamento de ator, e misturar as
frentes num mesmo diff impediria separa-las depois.
"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.deps import get_current_user, require_admin
from app.core import retention
from app.core.config import settings

router = APIRouter(
    prefix="/retention",
    tags=["retention"],
    dependencies=[Depends(get_current_user)],
)


class Politica(BaseModel):
    # Quantos dias a politica que existe no banco esta usando. None quer dizer
    # que nao existe politica desse tipo nesta tabela.
    dias_no_banco: int | None = None
    # Quantos dias o .env pede. None quer dizer desligada na configuracao.
    dias_no_env: int | None = None
    # Falso significa que banco e .env discordam: ou alguem mexeu no banco na
    # mao, ou a reconciliacao falhou naquela tabela.
    em_dia: bool
    proxima_execucao: datetime | None = None
    ultima_execucao: str | None = None
    falhas: int | None = None


class Tabela(BaseModel):
    tabela: str
    resumo: str
    linhas: int
    bytes: int
    chunks: int
    chunks_comprimidos: int
    # Os dois campos abaixo falam so dos chunks ja comprimidos, entao a
    # economia e medida e nao projetada. Ficam nulos enquanto nada comprimiu.
    bytes_antes_da_compressao: int | None = None
    bytes_depois_da_compressao: int | None = None
    economia: float | None = None
    dado_mais_antigo: datetime | None = None
    politicas: dict[str, Politica]


class Estado(BaseModel):
    ligada: bool
    tabelas: list[Tabela]
    bytes_total: int
    # Quanto o banco teria a mais se nada estivesse comprimido. Zero enquanto
    # nao houver chunk comprimido.
    bytes_economizados: int


@router.get("/status", response_model=Estado)
async def ver_status():
    tabelas = await retention.status()

    total = sum(t["bytes"] for t in tabelas)
    economizado = sum(
        (t["bytes_antes_da_compressao"] or 0) - (t["bytes_depois_da_compressao"] or 0)
        for t in tabelas
    )

    return Estado(
        ligada=settings.retention_enabled,
        tabelas=[Tabela(**t) for t in tabelas],
        bytes_total=total,
        bytes_economizados=max(economizado, 0),
    )


@router.post("/apply", dependencies=[Depends(require_admin)])
async def aplicar_politicas() -> dict[str, Any]:
    """Reconcilia o banco com o .env agora, sem reiniciar o backend.

    Mesma funcao que roda no startup. Rodar duas vezes seguidas nao faz nada
    na segunda: a lista de mudancas volta vazia.
    """
    return await retention.aplicar()


@router.post("/run", dependencies=[Depends(require_admin)])
async def rodar_politicas(
    incluir_retencao: bool = Query(
        False,
        description=(
            "Roda tambem a politica que apaga dado. Falso por padrao: "
            "compressao e reversivel, apagar chunk nao e."
        ),
    ),
) -> dict[str, Any]:
    return await retention.rodar_agora(incluir_retencao=incluir_retencao)
