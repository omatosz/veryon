"""
Adaptadores de webhook.

Cada plataforma aceita um corpo diferente no mesmo POST. Discord quer
"content", Slack quer "text", Teams quer um MessageCard. A diferenca acaba
aqui: o resto do caminho, fila, tentativa, teto por hora, e igual para todos.

Separado do notificador de proposito. Adicionar Telegram ou PagerDuty depois e
escrever uma funcao e uma linha no dicionario, sem tocar na logica de decisao.

Nenhum adaptador faz requisicao. Eles so montam o dicionario que vira JSON.
Isso deixa o formato testavel sem rede: passa um resumo, confere o corpo.
"""

from typing import Any, Callable

# Ordem de severidade. Usada para comparar o nivel do alerta com o minimo
# exigido pelo canal. Sigma usa esses cinco nomes.
NIVEIS = ["informational", "low", "medium", "high", "critical"]


def peso_do_nivel(nivel: str | None) -> int:
    """Posicao do nivel na escala. Nivel desconhecido vale 0, ou seja, o mais
    baixo: se uma regra nova trouxer um nome que nao conhecemos, ela nao passa
    por engano num canal configurado para 'high'."""
    try:
        return NIVEIS.index((nivel or "").lower())
    except ValueError:
        return 0


def _linha_resumo(resumo: dict[str, Any]) -> str:
    """A frase que descreve o evento, em pt-BR, igual para toda plataforma.

    Quem le isso no celular precisa decidir em dois segundos se levanta da
    cadeira. Entao: severidade, o que foi, de onde veio, e quantas vezes.
    """
    partes = [
        f"[{(resumo.get('level') or '?').upper()}]",
        resumo.get("title") or "Alerta",
    ]

    ip = resumo.get("source_ip")
    if ip:
        partes.append(f"de {ip}")

    # O ator entra depois do IP e nao no lugar dele: quem le de madrugada
    # precisa do endereco para agir, e do ator para entender o tamanho.
    ator = frase_do_ator(resumo)
    if ator:
        partes.append(f"[{ator}]")

    quantos = int(resumo.get("alert_count") or 1)
    if quantos > 1:
        partes.append(f"({quantos} ocorrencias agrupadas)")

    return " ".join(partes)


def frase_do_ator(resumo: dict[str, Any]) -> str | None:
    """Como o ator aparece na mensagem, ou None quando nao ha ator.

    Diz "mesmo padrao", nunca "mesma pessoa". O rastreamento afirma ferramenta
    e comportamento, e a mensagem que sai de madrugada nao pode afirmar mais
    do que o motor afirma. A confianca vai junto pelo mesmo motivo: um ator de
    confianca baixa e uma pista, nao uma conclusao.
    """
    ref = resumo.get("actor_ref")
    if not ref:
        return None

    frase = f"ator {ref}"
    ips = int(resumo.get("actor_ips") or 0)
    if ips > 1:
        frase += f", mesmo padrao visto de {ips} IPs"
    conf = resumo.get("actor_confidence")
    if conf:
        frase += f", confianca {CONFIANCA_EM_PORTUGUES.get(conf, conf)}"
    return frase


CONFIANCA_EM_PORTUGUES = {"high": "alta", "medium": "media", "low": "baixa"}


def _detalhes(resumo: dict[str, Any]) -> list[tuple[str, str]]:
    """Pares rotulo/valor que acompanham o resumo, ja sem os vazios."""
    itens = [
        ("Regra", resumo.get("rule_id")),
        ("Origem", resumo.get("source_ip")),
        ("Ator", frase_do_ator(resumo)),
        ("Severidade", resumo.get("level")),
        ("Ocorrencias", str(resumo.get("alert_count") or 1)),
        ("Tecnica MITRE", resumo.get("mitre_technique")),
    ]
    return [(rotulo, str(valor)) for rotulo, valor in itens if valor]


def corpo_discord(resumo: dict[str, Any]) -> dict[str, Any]:
    linhas = [_linha_resumo(resumo)]
    linhas += [f"**{rotulo}:** {valor}" for rotulo, valor in _detalhes(resumo)]
    return {"content": "\n".join(linhas)}


def corpo_slack(resumo: dict[str, Any]) -> dict[str, Any]:
    linhas = [_linha_resumo(resumo)]
    linhas += [f"*{rotulo}:* {valor}" for rotulo, valor in _detalhes(resumo)]
    return {"text": "\n".join(linhas)}


def corpo_teams(resumo: dict[str, Any]) -> dict[str, Any]:
    # MessageCard e o formato legado, mas e o unico que um webhook de canal
    # aceita sem app registrado no tenant. Adaptive Card exige Power Automate,
    # o que colocaria uma dependencia de licenca no caminho de um alerta.
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": _linha_resumo(resumo),
        "title": _linha_resumo(resumo),
        "sections": [
            {
                "facts": [{"name": rotulo, "value": valor} for rotulo, valor in _detalhes(resumo)],
            }
        ],
    }


def corpo_generic(resumo: dict[str, Any]) -> dict[str, Any]:
    """Sem formatacao: o resumo cru, para quem quer processar em vez de ler.
    E o formato que um gateway proprio ou um n8n da vida consome melhor."""
    return {
        "text": _linha_resumo(resumo),
        "alert": resumo,
    }


def corpo_email(resumo: dict[str, Any]) -> dict[str, Any]:
    """Assunto e corpo de texto puro.

    Nao devolve JSON como os outros porque e-mail nao e webhook. Quem consome
    isso e montar_email, nao montar_corpo.

    Texto puro, e nao HTML, de proposito: alerta precisa ser legivel no celular
    com a conexao ruim e no cliente de e-mail corporativo que bloqueia imagem e
    estilo. Ferramenta de plantao seria seria a ultima a apostar em renderizacao.

    O assunto carrega severidade e origem porque em muita caixa de entrada e a
    unica coisa que a pessoa le antes de decidir se abre.
    """
    nivel = (resumo.get("level") or "?").upper()
    titulo = resumo.get("title") or "Alerta"
    ip = resumo.get("source_ip")

    assunto = f"[VERYON][{nivel}] {titulo}"
    if ip:
        assunto += f" ({ip})"

    linhas = [_linha_resumo(resumo), ""]
    linhas += [f"{rotulo}: {valor}" for rotulo, valor in _detalhes(resumo)]

    quantos = int(resumo.get("alert_count") or 1)
    if quantos > 1:
        linhas += [
            "",
            f"Este e-mail representa {quantos} alertas do mesmo tipo e da mesma "
            "origem, agrupados para nao encher a caixa de entrada.",
        ]

    linhas += ["", "Detalhes completos na tela de Alertas do Veryon."]

    return {"subject": assunto, "body": "\n".join(linhas)}


def montar_email(resumo: dict[str, Any]) -> dict[str, Any]:
    """Assunto e corpo para canal de tipo 'email'."""
    return corpo_email(resumo)


def _linhas_digest(itens: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """Titulo e linhas de um resumo, do mais grave para o menos.

    A ordem importa mais aqui do que em qualquer outra mensagem: um resumo com
    vinte itens so e util se o pior estiver em cima. Quem le de relance vai ler
    as tres primeiras linhas e mais nada.
    """
    ordenados = sorted(
        itens,
        key=lambda i: (peso_do_nivel(i.get("level")), int(i.get("alert_count") or 1)),
        reverse=True,
    )

    total_alertas = sum(int(i.get("alert_count") or 1) for i in ordenados)
    pior = (ordenados[0].get("level") or "?").upper() if ordenados else "?"

    titulo = (
        f"Resumo do Veryon: {len(ordenados)} situacoes, "
        f"{total_alertas} alertas no periodo. Mais grave: {pior}"
    )

    linhas = []
    for item in ordenados:
        nivel = (item.get("level") or "?").upper()
        quantos = int(item.get("alert_count") or 1)
        parte = f"[{nivel}] {item.get('title') or 'Alerta'}"
        if item.get("source_ip"):
            parte += f" de {item['source_ip']}"
        if item.get("actor_ref"):
            ips = int(item.get("actor_ips") or 0)
            parte += f" (ator {item['actor_ref']}"
            parte += f", {ips} IPs)" if ips > 1 else ")"
        if quantos > 1:
            parte += f" x{quantos}"
        linhas.append(parte)

    return titulo, linhas


def montar_digest(kind: str, itens: list[dict[str, Any]]) -> dict[str, Any]:
    """Uma mensagem so, com tudo que acumulou para o canal no periodo.

    Devolve o mesmo formato que o transporte daquele tipo espera: corpo de
    webhook para os webhooks, assunto e corpo para e-mail.
    """
    titulo, linhas = _linhas_digest(itens)

    if kind == "email":
        corpo = [titulo, ""] + linhas
        corpo += ["", "Detalhes completos na tela de Alertas do Veryon."]
        return {"subject": f"[VERYON] {titulo}", "body": "\n".join(corpo)}

    texto = "\n".join([titulo, ""] + linhas)

    if kind == "slack":
        return {"text": texto}
    if kind == "teams":
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": titulo,
            "title": titulo,
            "text": "\n\n".join(linhas),
        }
    if kind == "generic":
        return {"text": titulo, "digest": itens}
    # discord e o padrao
    return {"content": texto}


ADAPTADORES: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "discord": corpo_discord,
    "slack": corpo_slack,
    "teams": corpo_teams,
    "generic": corpo_generic,
}


def montar_corpo(kind: str, resumo: dict[str, Any]) -> dict[str, Any]:
    """Corpo do POST para o tipo de canal. Tipo desconhecido cai no generic em
    vez de estourar: uma linha errada no banco nao pode derrubar o laco."""
    return ADAPTADORES.get(kind, corpo_generic)(resumo)
