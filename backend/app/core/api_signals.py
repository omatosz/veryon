"""
Motor de sinais da analise de API.

Aqui mora a parte que decide se um chamador esta se comportando como cliente
ou como atacante. Nao guarda estado nem toca no banco de proposito: recebe as
requisicoes de uma janela, devolve pontuacao e evidencia. Isso deixa o motor
testavel sozinho e deixa claro onde cada ponto foi parar.

A conta e soma de pesos com teto em 100. Peso alto e sinal que sozinho ja
justifica olhar; peso baixo so importa quando acompanha outro. Injecao vale
40 porque uma requisicao basta; endpoint sensivel vale 15 porque bater em
/auth/login e o que todo mundo faz o dia inteiro.
"""

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus

# Janela de analise. Dez minutos e curto o bastante pra rajada aparecer
# concentrada e longo o bastante pra varredura devagar nao se diluir.
WINDOW_MINUTES = 10

# A partir daqui vira alerta na tela de Alertas.
ALERT_THRESHOLD = 70
# A partir daqui e caso pra prevencao de ameaca tratar.
PREVENTION_THRESHOLD = 90

# --- Padroes de injecao -----------------------------------------------------
#
# Ficam propositalmente estreitos. Padrao largo demais marca requisicao normal
# como ataque, e analista que recebe alerta falso tres vezes para de ler o
# quarto.

INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "sqli": re.compile(
        r"(?i)(\bunion\s+select\b"
        r"|'\s*or\s*'?\s*\d*\s*'?\s*=\s*'?\s*\d*"
        r"|\bor\s+1\s*=\s*1\b"
        r"|;\s*drop\s+table\b"
        r"|\bpg_sleep\s*\("
        r"|\bsleep\s*\(\s*\d+\s*\)"
        r"|\bbenchmark\s*\("
        r"|\binformation_schema\b)"
    ),
    "xss": re.compile(
        r"(?i)(<script\b|</script>|javascript:|onerror\s*=|onload\s*=|<svg[^>]+onload)"
    ),
    "traversal": re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e[/\\%])"),
    "lfi": re.compile(r"(?i)(/etc/passwd|/etc/shadow|/proc/self/environ|php://|file://)"),
    "cmdi": re.compile(
        r"(?i)([;|&]\s*(cat|ls|whoami|id|uname|curl|wget|nc|bash|sh)\b|\$\([^)]+\)|`[^`]+`)"
    ),
    "ssti": re.compile(r"(\{\{[^}]{1,80}\}\}|\$\{[^}]{1,80}\})"),
    "nosqli": re.compile(r"(?i)(\$where\b|\$ne\b|\$gt\b|\$regex\b|\$exists\b)"),
}

# Rota que mexe com credencial, identidade, dinheiro ou administracao.
SENSITIVE_ROUTE = re.compile(
    r"(?i)(auth|login|logout|token|password|passwd|secret|credential|apikey|api_key"
    r"|admin|user|account|session|export|backup|dump|billing|payment|invoice|blocklist)"
)

# Rota de autenticacao, pra contar falha de login separado do resto.
AUTH_ROUTE = re.compile(r"(?i)(auth|login|token|session|oauth)")

# Metodo que nao tem uso legitimo em API de negocio.
FORBIDDEN_METHODS = {"TRACE", "TRACK", "CONNECT"}

_UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX = re.compile(r"(?i)^[0-9a-f]{16,}$")
_DIGITS = re.compile(r"^\d+$")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

MAX_ROUTE_SEGMENTS = 20


def normalize_route(path: str) -> str:
    """/users/42/orders/7 vira /users/{id}/orders/{id}.

    Sem isso o inventario de rotas encheria de linha unica por id e nenhum
    agrupamento faria sentido."""
    path = (path or "/").split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    parts = path.split("/")[:MAX_ROUTE_SEGMENTS]
    out = []
    for seg in parts:
        if not seg:
            out.append(seg)
        elif _DIGITS.match(seg):
            out.append("{id}")
        elif _IPV4.match(seg):
            out.append("{ip}")
        elif _UUID.match(seg):
            out.append("{uuid}")
        elif _HEX.match(seg):
            out.append("{hash}")
        elif "@" in seg:
            out.append("{email}")
        else:
            out.append(seg)
    normalized = "/".join(out) or "/"
    return normalized[:300]


def detect_injection(path: str, query: str | None, body: str | None = None) -> list[str]:
    """Devolve os nomes dos padroes que casaram. Roda na hora da escrita, com
    o texto ainda na mao, pra nao precisar guardar corpo de requisicao.

    Casa contra a forma decodificada. Atacante que sabe o minimo manda o
    payload em percent-encoding (%27%20OR), e o padrao cru nunca casaria com
    isso. Decodificar uma vez cobre o caso comum sem virar caca a evasao
    infinita, que nao e o proposito de uma ferramenta de portfolio."""
    bruto = f"{path or ''}?{query or ''}"
    if body:
        bruto += " " + body[:2000]
    haystack = bruto + " " + unquote_plus(bruto)
    return [name for name, pattern in INJECTION_PATTERNS.items() if pattern.search(haystack)]


def is_sensitive(route: str) -> bool:
    return bool(SENSITIVE_ROUTE.search(route or ""))


def numeric_segments(path: str) -> list[int]:
    """Os ids inteiros que aparecem no caminho, pra detectar varredura
    sequencial de objeto."""
    out = []
    for seg in (path or "").split("/"):
        if _DIGITS.match(seg):
            try:
                out.append(int(seg))
            except ValueError:
                pass
    return out


# --- Limiares dos sinais ----------------------------------------------------

AUTH_FAIL_THRESHOLD = 8          # falhas de login na janela
ENUM_ROUTE_THRESHOLD = 15        # rotas distintas tentadas
ENUM_NOTFOUND_RATIO = 0.5        # metade delas voltando 404
WALK_ID_THRESHOLD = 6            # ids distintos na mesma rota
WALK_DENSITY = 3                 # quao apertada a sequencia precisa ser
VOLUME_TOTAL_BYTES = 5_000_000   # 5 MB puxados na janela
VOLUME_SPIKE_FACTOR = 20         # uma resposta 20x maior que o normal da rota
VOLUME_MIN_BASELINE = 200        # referencia abaixo disso nao serve de base
VOLUME_MIN_SAMPLES = 4           # amostras na janela pra mediana valer algo

SIGNAL_LABELS = {
    "injection": ("Tentativa de injecao", 40),
    "auth_burst": ("Rajada de falha de autenticacao", 30),
    "enumeration": ("Varredura de rotas", 25),
    "shadow_api": ("API fantasma respondendo", 25),
    "object_walk": ("Acesso sequencial a objetos", 20),
    "volume_anomaly": ("Volume de resposta fora do padrao", 20),
    "sensitive_hit": ("Acesso a endpoint sensivel", 15),
    "odd_method": ("Metodo HTTP fora do esperado", 10),
}


def severity_for(score: int) -> str:
    if score >= PREVENTION_THRESHOLD:
        return "critical"
    if score >= ALERT_THRESHOLD:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _signal(sid: str, evidence: str) -> dict:
    label, weight = SIGNAL_LABELS[sid]
    return {"id": sid, "label": label, "weight": weight, "evidence": evidence}


def _mediana(valores: list[int]) -> int:
    ordenados = sorted(valores)
    meio = len(ordenados) // 2
    if len(ordenados) % 2:
        return ordenados[meio]
    return (ordenados[meio - 1] + ordenados[meio]) // 2


def _detectar_pico(
    tamanhos: dict[tuple[str, str], list[int]],
    baselines: dict[tuple[str, str], int],
) -> tuple[str, int, int] | None:
    """Acha a resposta desproporcional pro que a rota costuma devolver.

    A referencia e mediana, nao media, e por um motivo que custou um teste
    falhando pra ficar obvio: a media da rota absorve o proprio pico. Doze
    respostas de 1 KB com uma de 900 KB no meio dao media de 76 KB, e ai o
    pico deixa de parecer pico. A mediana nao se mexe com um valor extremo.

    Primeiro tenta a mediana das outras respostas da mesma rota dentro da
    janela, que nao depende de historico nenhum. So quando a janela tem
    amostra de menos e que cai pro historico anterior a ela."""
    melhor: tuple[str, int, int] | None = None

    for (metodo, rota), valores in tamanhos.items():
        maior = max(valores)
        if len(valores) >= VOLUME_MIN_SAMPLES:
            # Tira o proprio pico antes de calcular, senao ele entra na conta
            # da referencia que deveria julga-lo.
            restantes = sorted(valores)[:-1]
            referencia = _mediana(restantes) if restantes else 0
        else:
            referencia = baselines.get((metodo, rota), 0)

        if referencia < VOLUME_MIN_BASELINE:
            continue
        if maior < referencia * VOLUME_SPIKE_FACTOR:
            continue
        if melhor is None or maior > melhor[1]:
            melhor = (f"{metodo} {rota}", maior, referencia)

    return melhor


def score_requests(
    rows: list[dict],
    documented: set[tuple[str, str]],
    baselines: dict[tuple[str, str], int] | None = None,
) -> dict:
    """Pontua a janela de um chamador.

    rows      requisicoes ja filtradas por IP e por janela, cada uma um dict
              com method, path, route, status_code, response_bytes, flags.
    documented  pares (metodo, rota) que o sistema declara conhecer.
    baselines   media de bytes por (metodo, rota), pra comparar pico.

    Devolve pontuacao, severidade, sinais com evidencia e um resumo do que o
    chamador fez. Quem escreve no banco e quem chama."""
    baselines = baselines or {}
    signals: list[dict] = []

    if not rows:
        return {
            "score": 0,
            "severity": "low",
            "signals": [],
            "request_count": 0,
            "distinct_routes": 0,
            "top_routes": [],
        }

    routes: dict[str, int] = {}
    not_found = 0
    auth_fails = 0
    injection_hits: dict[str, int] = {}
    shadow: set[str] = set()
    sensitive: set[str] = set()
    odd: set[str] = set()
    total_bytes = 0
    tamanhos: dict[tuple[str, str], list[int]] = {}
    ids_by_route: dict[str, set[int]] = {}

    for row in rows:
        method = (row.get("method") or "GET").upper()
        route = row.get("route") or "/"
        status = row.get("status_code") or 0
        path = row.get("path") or route

        routes[route] = routes.get(route, 0) + 1

        if status == 404:
            not_found += 1

        # 429 entra junto porque tentativa de login barrada pelo limitador de
        # taxa continua sendo tentativa de login que falhou. Contar so 401
        # deixaria a rajada mais agressiva pontuar menos que a mais lenta.
        if AUTH_ROUTE.search(route) and status in (401, 403, 429):
            auth_fails += 1

        for name in (row.get("flags") or {}).get("injection", []):
            injection_hits[name] = injection_hits.get(name, 0) + 1

        # Fantasma e rota que responde sem estar declarada. 404 aqui nao conta:
        # aquilo e varredura, e ja pontua no sinal de enumeracao.
        if status and status < 400 and (method, route) not in documented:
            shadow.add(f"{method} {route}")

        if is_sensitive(route):
            sensitive.add(f"{method} {route}")

        if method in FORBIDDEN_METHODS:
            odd.add(f"{method} {route}")
        elif status == 405:
            odd.add(f"{method} {route} (405)")

        size = row.get("response_bytes") or 0
        total_bytes += size
        if size:
            tamanhos.setdefault((method, route), []).append(size)

        found_ids = numeric_segments(path)
        if found_ids:
            ids_by_route.setdefault(route, set()).update(found_ids)

    if injection_hits:
        detail = ", ".join(f"{k} ({v}x)" for k, v in sorted(injection_hits.items()))
        signals.append(_signal("injection", f"padroes detectados: {detail}"))

    if auth_fails >= AUTH_FAIL_THRESHOLD:
        signals.append(_signal("auth_burst", f"{auth_fails} respostas 401/403 em rota de autenticacao"))

    distinct = len(routes)
    if distinct >= ENUM_ROUTE_THRESHOLD and not_found / len(rows) >= ENUM_NOTFOUND_RATIO:
        pct = round(not_found / len(rows) * 100)
        signals.append(_signal("enumeration", f"{distinct} rotas distintas, {pct}% respondendo 404"))

    if shadow:
        amostra = ", ".join(sorted(shadow)[:3])
        signals.append(_signal("shadow_api", f"{len(shadow)} rota(s) nao documentada(s) respondendo: {amostra}"))

    for route, found in ids_by_route.items():
        if len(found) < WALK_ID_THRESHOLD:
            continue
        span = max(found) - min(found) + 1
        if span <= len(found) * WALK_DENSITY:
            signals.append(
                _signal(
                    "object_walk",
                    f"{len(found)} ids distintos em {route} (de {min(found)} a {max(found)})",
                )
            )
            break

    spike = _detectar_pico(tamanhos, baselines)
    if spike is not None:
        signals.append(
            _signal(
                "volume_anomaly",
                f"{spike[0]} devolveu {spike[1]} bytes, {spike[1] // max(spike[2], 1)}x o normal da rota ({spike[2]})",
            )
        )
    elif total_bytes >= VOLUME_TOTAL_BYTES:
        signals.append(_signal("volume_anomaly", f"{total_bytes // 1024} KB puxados na janela"))

    if sensitive:
        amostra = ", ".join(sorted(sensitive)[:3])
        signals.append(_signal("sensitive_hit", f"acessou {len(sensitive)} endpoint(s) sensivel(is): {amostra}"))

    if odd:
        signals.append(_signal("odd_method", ", ".join(sorted(odd)[:3])))

    score = min(100, sum(s["weight"] for s in signals))
    top = sorted(routes.items(), key=lambda kv: kv[1], reverse=True)[:5]

    return {
        "score": score,
        "severity": severity_for(score),
        "signals": signals,
        "request_count": len(rows),
        "distinct_routes": distinct,
        "top_routes": [{"route": r, "count": c} for r, c in top],
    }


def window_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return now - timedelta(minutes=WINDOW_MINUTES)
