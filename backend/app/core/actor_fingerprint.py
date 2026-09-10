"""
Identidade de ator: quem esta atacando, quando o IP nao serve mais.

Bloqueio por IP tem um furo conhecido: o atacante troca de endereco e volta.
O comportamento, nao. A ordem em que a ferramenta monta os cabecalhos, o
ritmo entre as requisicoes e o perfil de erro sao propriedade do programa que
esta do outro lado, e sobrevivem a troca de IP.

Aqui mora so a matematica disso: entra o comportamento de um chamador, sai a
semelhanca dele com outro. Nao guarda estado nem toca no banco, pelo mesmo
motivo do motor de sinais: fica testavel sozinho e fica claro de onde veio
cada ponto.

Duas decisoes que valem ser ditas em voz alta:

1. Comparacao e por semelhanca, nao por hash exato. Hash exato quebra com um
   cabecalho a mais e a identidade se perde justo quando o atacante muda algo
   de leve, que e o caso que isso existe pra pegar.

2. So guardamos NOME de cabecalho, nunca valor. Valor carrega cookie, token e
   dado pessoal; nome nao carrega nada. A assinatura funciona igual e nao cria
   um problema de privacidade novo pra resolver depois.
"""

import re
import statistics
from difflib import SequenceMatcher

# --- Peso de cada traco na comparacao ---------------------------------------
#
# Somam 1.0. Cabecalho leva metade porque e o traco mais dificil de mudar sem
# querer: e o codigo da ferramenta que decide, nao o operador. User-Agent leva
# pouco porque e uma linha de texto que qualquer um troca.

PESO_CABECALHO = 0.50
PESO_AGENTE = 0.20
PESO_RITMO = 0.15
PESO_PERFIL = 0.15

# A partir daqui duas observacoes viram o mesmo ator.
LIMIAR_FUSAO = 0.75

# Abaixo disso a assinatura e comum demais pra sustentar identidade, e nao
# fundimos IPs mesmo com semelhanca alta. Ver distintividade() pra o porque.
MIN_DISTINTIVIDADE = 0.35

# Cabecalhos que variam dentro do mesmo cliente, por metodo ou por estado de
# login. Entrar na assinatura faria a mesma ferramenta parecer duas.
CABECALHOS_VOLATEIS = frozenset(
    {
        "content-length",
        "content-type",
        "cookie",
        "authorization",
        "if-none-match",
        "if-modified-since",
        "if-match",
        "range",
    }
)

# Cabecalhos que a NOSSA infraestrutura injeta: proxy, balanceador, CDN. Sao os
# mesmos pra todo mundo que passa pela mesma porta, entao deixariam qualquer
# par de chamadores parecido. Tem que sair antes da conta.
CABECALHOS_DE_PROXY = frozenset(
    {
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-real-ip",
        "forwarded",
        "via",
        "x-request-id",
        "x-amzn-trace-id",
        "cf-connecting-ip",
        "cf-ray",
        "cf-ipcountry",
        "true-client-ip",
    }
)

# Navegador de verdade manda esses. Ferramenta de ataque quase nunca.
MARCAS_DE_NAVEGADOR = frozenset(
    {
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-fetch-user",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
    }
)

# Agente que milhares de operadores diferentes mandam identico. Serve pra
# reconhecer ferramenta, nao pra reconhecer quem esta usando ela.
AGENTES_BANAIS = (
    "curl/",
    "wget/",
    "python-requests/",
    "python-urllib/",
    "go-http-client/",
    "java/",
    "libwww-perl/",
    "okhttp/",
    "axios/",
    "postmanruntime/",
    "httpie/",
)

# Numero de versao dentro do User-Agent. Chrome sobe de versao sozinho a cada
# poucas semanas; sem tirar isso o mesmo cliente vira um ator novo por mes.
_VERSAO = re.compile(r"\d+(\.\d+)+")


def assinatura_de_cabecalhos(nomes: list[str]) -> str:
    """Reduz os cabecalhos de uma requisicao a uma linha estavel.

    Guarda a ORDEM, que e o que distingue ferramenta de ferramenta: duas
    bibliotecas HTTP diferentes mandam quase o mesmo conjunto, em ordens
    diferentes."""
    limpos = []
    for nome in nomes:
        n = nome.strip().lower()
        if not n or n in CABECALHOS_VOLATEIS or n in CABECALHOS_DE_PROXY:
            continue
        if n in limpos:
            continue
        limpos.append(n)
    return ",".join(limpos)


def normalizar_agente(agente: str | None) -> str:
    """Tira numero de versao e espaco sobrando. O que resta e a familia."""
    if not agente:
        return ""
    return _VERSAO.sub("#", agente.strip().lower())[:200]


def _classe_de_ritmo(intervalos: list[float]) -> str:
    """Traduz os intervalos entre requisicoes numa classe legivel.

    Duas perguntas: quao rapido, e quao regular. Regularidade e o que separa
    gente de script; humano tem pausa pra ler, script nao tem."""
    if len(intervalos) < 3:
        return "indefinido"

    mediana = statistics.median(intervalos)
    media = statistics.fmean(intervalos)
    desvio = statistics.pstdev(intervalos)
    # Coeficiente de variacao: desvio relativo a media. Serve pra comparar
    # ritmos de velocidades diferentes na mesma escala.
    variacao = (desvio / media) if media > 0 else 0.0

    if variacao < 0.35:
        regularidade = "metronomico"
    elif variacao > 1.0:
        regularidade = "irregular"
    else:
        regularidade = "misto"

    if mediana < 0.5:
        velocidade = "rajada"
    elif mediana < 2:
        velocidade = "rapido"
    elif mediana < 10:
        velocidade = "normal"
    else:
        velocidade = "lento"

    return f"{velocidade}/{regularidade}"


def _mais_comum(valores: list[str]) -> str:
    if not valores:
        return ""
    return max(set(valores), key=valores.count)


def tracos(requisicoes: list[dict]) -> dict:
    """Resume o comportamento de um chamador numa janela.

    Cada requisicao precisa de ts, e pode trazer header_sig, user_agent,
    method e status_code. O que faltar simplesmente nao pontua depois."""
    if not requisicoes:
        return {
            "header_sig": "",
            "agente": "",
            "ritmo": "indefinido",
            "perfil": "",
            "amostras": 0,
        }

    ordenadas = sorted(requisicoes, key=lambda r: r["ts"])
    instantes = [r["ts"] for r in ordenadas]
    intervalos = [
        (b - a).total_seconds() for a, b in zip(instantes, instantes[1:]) if (b - a).total_seconds() >= 0
    ]

    assinaturas = [r.get("header_sig") or "" for r in ordenadas if r.get("header_sig")]
    agentes = [normalizar_agente(r.get("user_agent")) for r in ordenadas]

    metodos = sorted({(r.get("method") or "GET").upper() for r in ordenadas})
    erros = sum(1 for r in ordenadas if (r.get("status_code") or 0) >= 400)
    # Faixa de erro em vez de percentual cru: 41% e 43% sao o mesmo
    # comportamento, e comparar numero exato so adicionaria ruido.
    faixa_erro = min(int((erros / len(ordenadas)) * 5), 4)

    return {
        "header_sig": _mais_comum(assinaturas),
        "agente": _mais_comum([a for a in agentes if a]),
        "ritmo": _classe_de_ritmo(intervalos),
        "perfil": f"{'+'.join(metodos)}|e{faixa_erro}",
        "amostras": len(ordenadas),
    }


def _semelhanca_de_cabecalhos(a: str, b: str) -> float:
    """Conjunto e ordem, nessa proporcao.

    Conjunto sozinho acha parecido demais (todo mundo manda host e accept).
    Ordem sozinha e fragil demais (um cabecalho a mais desloca o resto). Dois
    tercos pra ordem porque e a parte que a ferramenta controla."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0

    la, lb = a.split(","), b.split(",")
    sa, sb = set(la), set(lb)
    uniao = sa | sb
    jaccard = len(sa & sb) / len(uniao) if uniao else 0.0
    ordem = SequenceMatcher(None, la, lb).ratio()
    return 0.35 * jaccard + 0.65 * ordem


def _agente_banal(agente: str) -> bool:
    """Agente que muita gente diferente manda igual: nao individualiza ninguem."""
    if not agente:
        return True
    return any(marca in agente for marca in AGENTES_BANAIS)


def _parece_navegador(agente: str) -> bool:
    return "mozilla/" in agente


def distintividade(t: dict) -> float:
    """Quanto essa assinatura pode sustentar uma afirmacao de identidade.

    Existe pra impedir a pior falha possivel desse recurso: juntar mil pessoas
    diferentes num 'ator' so porque todas usam Chrome, ou todas usam curl
    padrao. Assinatura comum nao prova nada, e produto de seguranca que afirma
    o que nao sabe perde o analista de vez.

    Quando isso devolve pouco, o resultado nao e um ator errado: e nenhum ator.
    Cada IP segue sozinho, que e a resposta honesta pra "nao da pra saber"."""
    sig = t.get("header_sig") or ""
    if not sig:
        return 0.0

    nomes = set(sig.split(","))
    agente = t.get("agente") or ""

    # Navegador de verdade: milhoes de pessoas mandam exatamente isso.
    if nomes & MARCAS_DE_NAVEGADOR:
        return 0.25

    # Diz ser navegador mas nao manda o que navegador manda. Nao e Chrome
    # nenhum: e ferramenta com User-Agent trocado. A propria mentira e um
    # traco, e um traco bem menos comum que a verdade.
    if _parece_navegador(agente):
        return 0.65

    if len(nomes) < 4:
        # Cliente pelado. Com agente banal junto (curl, wget, requests) sao
        # dois sinais comuns somados, e nao da pra dizer que dois IPs assim sao
        # o mesmo ator: fica abaixo do limiar de proposito.
        return 0.30 if _agente_banal(agente) else 0.50

    # Dai pra cima, mais cabecalho e mais chance de combinacao propria; header
    # fora do padrao (x-*) e o que mais individualiza.
    proprios = sum(1 for n in nomes if n.startswith("x-"))
    return min(1.0, 0.55 + 0.05 * (len(nomes) - 4) + 0.10 * proprios)


def semelhanca(a: dict, b: dict) -> dict:
    """Compara dois conjuntos de tracos. Devolve o total e a quebra por traco,
    porque o analista precisa poder discordar do numero."""
    cab = _semelhanca_de_cabecalhos(a.get("header_sig", ""), b.get("header_sig", ""))

    agente_a, agente_b = a.get("agente", ""), b.get("agente", "")
    if agente_a and agente_b:
        age = 1.0 if agente_a == agente_b else SequenceMatcher(None, agente_a, agente_b).ratio()
    else:
        age = 0.0

    ritmo_a, ritmo_b = a.get("ritmo", ""), b.get("ritmo", "")
    if ritmo_a in ("", "indefinido") or ritmo_b in ("", "indefinido"):
        rit = 0.0
    elif ritmo_a == ritmo_b:
        rit = 1.0
    else:
        # Mesma regularidade em velocidade diferente ainda diz alguma coisa:
        # a rede muda, o jeito do programa esperar nao.
        rit = 0.5 if ritmo_a.split("/")[-1] == ritmo_b.split("/")[-1] else 0.0

    perfil_a, perfil_b = a.get("perfil", ""), b.get("perfil", "")
    per = 1.0 if perfil_a and perfil_a == perfil_b else 0.0

    total = (
        PESO_CABECALHO * cab + PESO_AGENTE * age + PESO_RITMO * rit + PESO_PERFIL * per
    )

    return {
        "score": round(total, 4),
        "cabecalhos": round(cab, 4),
        "agente": round(age, 4),
        "ritmo": round(rit, 4),
        "perfil": round(per, 4),
    }


def pode_fundir(a: dict, b: dict) -> tuple[bool, dict]:
    """Decide se duas observacoes sao o mesmo ator.

    Dois portoes, nao um. Semelhanca alta com assinatura banal continua sendo
    coincidencia, e e por isso que a distintividade tem poder de veto aqui."""
    detalhe = semelhanca(a, b)
    dist = min(distintividade(a), distintividade(b))
    detalhe["distintividade"] = round(dist, 4)

    if dist < MIN_DISTINTIVIDADE:
        detalhe["motivo"] = "assinatura comum demais pra sustentar identidade"
        return False, detalhe

    if detalhe["score"] < LIMIAR_FUSAO:
        detalhe["motivo"] = "semelhanca abaixo do limiar"
        return False, detalhe

    detalhe["motivo"] = "semelhanca e assinatura suficientes"
    return True, detalhe


def confianca(score: float, dist: float, ips: int) -> str:
    """Traduz os numeros no que a tela tem permissao de afirmar.

    'high' nunca quer dizer "e a mesma pessoa" e sim "e a mesma ferramenta com
    o mesmo padrao". Dois operadores rodando sqlmap padrao sao indistinguiveis
    daqui, e a tela precisa dizer isso em vez de fingir certeza."""
    if score >= 0.90 and dist >= 0.60:
        return "high"
    if score >= LIMIAR_FUSAO and dist >= MIN_DISTINTIVIDADE:
        return "medium"
    return "low"
