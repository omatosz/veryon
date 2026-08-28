"""
Middleware que observa o proprio trafego da API do Veryon.

Existe pra que a analise de API tenha o que analisar sem depender de ninguem
configurar gateway nenhum: o sistema observa a si mesmo. Trafego de cliente
externo entra pela mesma tabela, pelo POST /ingest/api-logs.

Tambem e ASGI puro, pelo mesmo motivo do middleware de bloqueio: roda em toda
requisicao e nao pode custar mais que a requisicao.
"""

import time
from datetime import datetime, timezone

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core import api_signals, api_traffic
from app.middleware.blocklist import client_ip


class APILoggerMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/")
        if api_traffic.should_ignore(path):
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 0
        body_bytes = 0

        async def instrumented(message: Message) -> None:
            nonlocal status_code, body_bytes
            if message["type"] == "http.response.start":
                status_code = message["status"]
            elif message["type"] == "http.response.body":
                body_bytes += len(message.get("body", b"") or b"")
            await send(message)

        try:
            await self.app(scope, receive, instrumented)
        finally:
            # Fica no finally pra requisicao que estourou excecao tambem virar
            # registro. Erro nao tratado e justamente o tipo de coisa que um
            # atacante provoca de proposito.
            self._record(scope, path, status_code, body_bytes, started)

    def _record(self, scope: Scope, path: str, status: int, size: int, started: float) -> None:
        query = (scope.get("query_string") or b"").decode("latin-1")[:500] or None

        # O Starlette preenche scope["route"] durante o roteamento, e o dict e
        # o mesmo objeto, entao depois da chamada ele ja esta la. Usar a rota
        # que casou de verdade e mais confiavel que adivinhar pelo caminho.
        matched = scope.get("route")
        template = getattr(matched, "path", None)
        route = template if template else api_signals.normalize_route(path)

        headers = dict(scope.get("headers", []))
        agent = headers.get(b"user-agent", b"").decode("latin-1")[:300] or None

        api_traffic.enqueue(
            {
                "ts": datetime.now(timezone.utc),
                "source": "self",
                "client_ip": client_ip(scope),
                "method": (scope.get("method") or "GET").upper()[:8],
                "path": path[:300],
                "route": route[:300],
                "status_code": status or None,
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "response_bytes": size,
                "user_agent": agent,
                "query": query,
                "flags": {"injection": api_signals.detect_injection(path, query)},
            }
        )
