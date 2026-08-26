import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text

from app.api import alerts, auth, blocklist, enrichment, events, stats
from app.core.config import settings
from app.core.limiter import limiter
from app.core.seed import seed_admin_user
from app.db.session import engine

app = FastAPI(title="Veryon API")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

redis_client = redis.from_url(settings.redis_url)

app.include_router(auth.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(enrichment.router)
app.include_router(stats.router)
app.include_router(blocklist.router)


@app.on_event("startup")
async def on_startup():
    await seed_admin_user()


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

    return status
