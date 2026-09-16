import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import oauth2_scheme, require_admin
from app.core import demo
from app.core.config import settings

log = logging.getLogger("veryon.demo")

router = APIRouter(prefix="/demo", tags=["demo"])


def _exigir_demo_mode() -> None:
    # 404 e nao 403: com a flag desligada, a rota nao deveria nem parecer
    # existir. E o mesmo raciocinio do require_admin, na direcao oposta: la o
    # recurso existe e falta permissao, aqui o recurso simplesmente nao esta
    # instalado neste ambiente.
    if not settings.demo_mode_enabled:
        raise HTTPException(status_code=404, detail="Não encontrado")


@router.get("/status", dependencies=[Depends(require_admin)])
async def status():
    _exigir_demo_mode()
    return {"em_andamento": demo.em_andamento()}


@router.post("/run-attacks", status_code=202, dependencies=[Depends(require_admin)])
async def run_attacks(token: str = Depends(oauth2_scheme)):
    _exigir_demo_mode()

    if demo.em_andamento():
        raise HTTPException(status_code=409, detail="A demonstração já está em andamento.")

    # Devolve na hora; quem chamou acompanha pelas telas de Eventos e Alertas
    # enchendo nos proximos segundos, nao esperando esta chamada responder.
    asyncio.create_task(demo.run_full_demo(token))
    return {
        "iniciado": True,
        "mensagem": "Demonstração disparada. Acompanhe pelas telas de Eventos e Alertas.",
    }
