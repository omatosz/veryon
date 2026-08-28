import asyncio
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text

from app.api import (
    alerts,
    api_analysis,
    auth,
    blocklist as blocklist_api,
    enrichment,
    events,
    ingest,
    prevention as prevention_api,
    scans,
    stats,
    vulnerabilities,
)
from app.core import api_analyzer, api_traffic, blocklist, prevention
from app.core.cache import redis_client
from app.core.config import settings
from app.core.limiter import limiter
from app.core.seed import seed_admin_user
from app.db.session import engine
from app.middleware.api_logger import APILoggerMiddleware
from app.middleware.blocklist import BlocklistMiddleware

log = logging.getLogger("veryon")

app = FastAPI(title="Veryon API")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# A ordem importa e e de dentro pra fora: o ultimo add_middleware vira o mais
# externo. O bloqueio fica por dentro do CORS de proposito, senao o 403 sairia
# sem cabecalho CORS e o navegador mostraria erro de CORS no lugar do motivo.
#
# O coletor de trafego fica por fora do bloqueio e do limitador de taxa de
# proposito: assim ele tambem registra a requisicao que levou 403 e a que
# levou 429. Tentativa recusada e justamente o que interessa numa
# investigacao, seria perda registrar so o que passou. Ele fica por dentro do
# CORS so pra nao encher a tabela de preflight OPTIONS, que o CORS responde
# sozinho e nao diz nada sobre comportamento.
app.add_middleware(BlocklistMiddleware)
app.add_middleware(SlowAPIMiddleware)
if settings.api_traffic_capture:
    app.add_middleware(APILoggerMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(enrichment.router)
app.include_router(stats.router)
app.include_router(blocklist_api.router)
app.include_router(vulnerabilities.router)
app.include_router(scans.router)
app.include_router(api_analysis.router)
app.include_router(ingest.router)
app.include_router(prevention_api.router)


def rotas_registradas() -> list[tuple[str, str]]:
    """As rotas que a aplicacao declara ter, no mesmo formato em que o
    middleware grava o trafego. E a lista que separa rota conhecida de API
    fantasma no inventario."""
    out: list[tuple[str, str]] = []
    for rota in app.routes:
        caminho = getattr(rota, "path", None)
        metodos = getattr(rota, "methods", None)
        if not caminho or not metodos:
            continue
        for metodo in metodos:
            if metodo in ("HEAD", "OPTIONS"):
                continue
            out.append((metodo, caminho))
    return out


@app.on_event("startup")
async def on_startup():
    await seed_admin_user()
    # Carrega antes de aceitar trafego: subir com a lista vazia deixaria uma
    # janela em que quem esta bloqueado passa.
    await blocklist.refresh()
    app.state.blocklist_task = asyncio.create_task(blocklist.refresh_loop())

    await api_traffic.seed_documented_routes(rotas_registradas())
    app.state.api_tasks = [
        asyncio.create_task(api_traffic.flush_loop()),
        asyncio.create_task(api_analyzer.analyze_loop()),
        asyncio.create_task(prevention.evaluate_loop()),
    ]


@app.on_event("shutdown")
async def on_shutdown():
    tarefas = [getattr(app.state, "blocklist_task", None)]
    tarefas += getattr(app.state, "api_tasks", [])
    for task in tarefas:
        if task is None:
            continue
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@app.get("/health")
async def health():
    status = {"api": "ok"}

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        status["database"] = "ok"
    except Exception as exc:
        status["database"] = f"error: {exc}"

    try:
        await redis_client.ping()
        status["redis"] = "ok"
    except Exception as exc:
        status["redis"] = f"error: {exc}"

    snap = blocklist.snapshot()
    status["blocklist"] = {
        "entries": snap.size,
        "loaded_at": snap.loaded_at.isoformat() if snap.loaded_at else None,
    }
    # dropped subindo quer dizer que a coleta esta perdendo amostra: ou o banco
    # esta lento, ou o volume passou do que a fila aguenta.
    status["api_traffic"] = api_traffic.stats()

    return status
