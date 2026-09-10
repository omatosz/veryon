"""
Laco de rastreamento de ator.

A cada ciclo: pega os chamadores que o motor de sinais ja marcou como
suspeitos, resume o comportamento de cada um e decide se aquilo e um ator novo
ou alguem que ja passou por aqui com outro endereco.

O recorte importa e e proposital: SO entra quem ja tem achado aberto. Isso nao
e um sistema de identificar visitante, e um sistema de nao perder um atacante
conhecido quando ele troca de IP. Fingerprint de todo mundo que acessa seria
outra coisa, com outro nome e outro debate, e nao e o que esta sendo feito
aqui.

Regras de convivencia com o analista, na mesma linha dos trilhos da prevencao:

  - fusao so acontece com assinatura distintiva; parecido com Chrome nao basta;
  - toda juncao guarda a semelhanca e a quebra por traco, pra ser contestavel;
  - IP movido na mao fica marcado e o laco nao mexe mais nele.
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import bindparam, text

from app.core import actor_fingerprint
from app.db.session import async_session

log = logging.getLogger("veryon.actor_tracker")

TRACK_SECONDS = 30
# Quanto trafego passado entra no resumo de comportamento de um IP. Precisa ser
# maior que a janela do motor de sinais: ritmo so aparece com amostra.
JANELA_MINUTOS = 60
MAX_ROWS = 20_000
# Ator mais velho que isso nao entra mais na comparacao. Sem teto, cada ciclo
# compararia contra a historia inteira e o custo cresceria pra sempre.
JANELA_FUSAO_DIAS = 14
MAX_CANDIDATOS = 200
# Sem trafego novo por esse tempo, o ator vira dormente. Continua existindo:
# e exatamente pra reconhece-lo se ele voltar que isso tudo existe.
DORMENTE_HORAS = 24
# Abaixo disso nao da pra afirmar nada sobre ritmo nem sobre padrao.
MIN_AMOSTRAS = 4

FETCH_SUSPEITOS = text(
    """
    SELECT client_ip, score
      FROM api_findings
     WHERE status IN ('open', 'investigating', 'escalated')
       AND last_seen >= :cutoff
    """
)

FETCH_REQS = text(
    """
    SELECT client_ip, ts, header_sig, user_agent, method, status_code
      FROM api_requests
     WHERE ts >= :start
       AND client_ip IN :ips
     ORDER BY ts
     LIMIT :cap
    """
).bindparams(bindparam("ips", expanding=True))

FETCH_VINCULO = text(
    """
    -- LEFT JOIN por causa do vinculo orfao: quando o analista separa um IP do
    -- ator, a linha fica com manual ligado e sem dono. Com INNER JOIN ela
    -- sumiria da consulta, o laco trataria o IP como desconhecido e refaria a
    -- juncao que a pessoa acabou de desfazer.
    SELECT ai.id, ai.actor_id, ai.manual, a.ref
      FROM actor_ips ai
      LEFT JOIN actors a ON a.id = ai.actor_id
     WHERE ai.client_ip = :ip
    """
)

FETCH_CANDIDATOS = text(
    """
    SELECT id, ref, traits
      FROM actors
     WHERE last_seen >= :desde
     ORDER BY last_seen DESC
     LIMIT :cap
    """
)

INSERT_ATOR = text(
    """
    INSERT INTO actors
        (ref, traits, confidence, distinctiveness, ip_count, request_count,
         max_score, first_seen, last_seen, status)
    VALUES
        (:ref, CAST(:traits AS jsonb), :confidence, :dist, 1, :requests,
         :score, :now, :now, 'active')
    RETURNING id
    """
)

INSERT_VINCULO = text(
    """
    INSERT INTO actor_ips
        (actor_id, client_ip, first_seen, last_seen, request_count,
         similarity, match_detail)
    VALUES
        (:actor_id, :ip, :now, :now, :requests, :similarity,
         CAST(:detail AS jsonb))
    ON CONFLICT (client_ip) DO NOTHING
    """
)

TOCA_VINCULO = text(
    """
    UPDATE actor_ips
       SET last_seen = :now, request_count = :requests
     WHERE client_ip = :ip
    """
)

# Recalcula os agregados a partir dos vinculos em vez de somar incrementos. Sai
# mais caro e da o numero certo mesmo depois de o analista separar um IP na mao.
ATUALIZA_ATOR = text(
    """
    UPDATE actors a
       SET ip_count = v.ips,
           request_count = v.requests,
           first_seen = LEAST(a.first_seen, v.inicio),
           last_seen = GREATEST(a.last_seen, v.fim),
           max_score = GREATEST(a.max_score, :score),
           confidence = :confidence,
           distinctiveness = :dist,
           status = 'active'
      FROM (
            SELECT count(*) AS ips,
                   COALESCE(sum(request_count), 0) AS requests,
                   min(first_seen) AS inicio,
                   max(last_seen) AS fim
              FROM actor_ips WHERE actor_id = :actor_id
           ) v
     WHERE a.id = :actor_id
    """
)

ADORMECE = text(
    """
    UPDATE actors
       SET status = 'dormant'
     WHERE status = 'active'
       AND last_seen < :cutoff
    """
)


def _ref_de(traits: dict) -> str:
    """Identificador curto e estavel, do tipo que da pra falar em voz alta.

    Sai dos tracos e nao do id do banco pra que o mesmo comportamento reapareca
    com o mesmo nome se a linha for recriada."""
    base = f"{traits.get('header_sig', '')}|{traits.get('agente', '')}"
    return hashlib.blake2b(base.encode("utf-8", "replace"), digest_size=3).hexdigest()


async def _ref_livre(db, traits: dict) -> str:
    """Resolve colisao de ref. Tres bytes colidem eventualmente, e ref repetida
    seria pior que ref feia: duas historias diferentes com o mesmo nome."""
    base = _ref_de(traits)
    ref = base
    for sufixo in range(1, 10):
        existe = (
            await db.execute(text("SELECT 1 FROM actors WHERE ref = :r"), {"r": ref})
        ).first()
        if existe is None:
            return ref
        ref = f"{base}{sufixo}"
    return f"{base}{datetime.now(timezone.utc).strftime('%H%M%S')}"[:12]


async def _melhor_candidato(db, traits: dict, desde: datetime):
    """Procura, entre os atores recentes, o mais parecido que passe nos dois
    portoes de pode_fundir. Devolve (id, ref, detalhe) ou None."""
    linhas = (
        await db.execute(FETCH_CANDIDATOS, {"desde": desde, "cap": MAX_CANDIDATOS})
    ).all()

    melhor = None
    for ator_id, ref, guardados in linhas:
        ok, detalhe = actor_fingerprint.pode_fundir(traits, guardados or {})
        if not ok:
            continue
        if melhor is None or detalhe["score"] > melhor[2]["score"]:
            melhor = (ator_id, ref, detalhe)
    return melhor


async def track_once() -> dict:
    """Um ciclo completo. Devolve um resumo pro log e pros testes."""
    agora = datetime.now(timezone.utc)
    inicio = agora - timedelta(minutes=JANELA_MINUTOS)

    async with async_session() as db:
        suspeitos = {
            ip: score
            for ip, score in (
                await db.execute(FETCH_SUSPEITOS, {"cutoff": inicio})
            ).all()
            if ip
        }
        if not suspeitos:
            await db.execute(ADORMECE, {"cutoff": agora - timedelta(hours=DORMENTE_HORAS)})
            await db.commit()
            return {"suspeitos": 0, "novos": 0, "fundidos": 0, "ignorados": 0}

        linhas = (
            await db.execute(
                FETCH_REQS,
                {"start": inicio, "ips": list(suspeitos), "cap": MAX_ROWS},
            )
        ).mappings().all()

        por_ip: dict[str, list[dict]] = {}
        for linha in linhas:
            por_ip.setdefault(linha["client_ip"], []).append(dict(linha))

        novos = fundidos = ignorados = 0

        for ip, reqs in por_ip.items():
            if len(reqs) < MIN_AMOSTRAS:
                ignorados += 1
                continue

            traits = actor_fingerprint.tracos(reqs)
            dist = actor_fingerprint.distintividade(traits)
            score = suspeitos.get(ip, 0)

            if not traits["header_sig"]:
                # Origem que nao manda cabecalho (log de acesso simples) nao
                # sustenta identidade. Melhor nao ter ator do que ter um errado.
                ignorados += 1
                continue

            vinculo = (await db.execute(FETCH_VINCULO, {"ip": ip})).first()

            if vinculo is not None:
                _, ator_id, manual, _ref = vinculo
                await db.execute(
                    TOCA_VINCULO, {"ip": ip, "now": agora, "requests": len(reqs)}
                )
                if not manual:
                    await db.execute(
                        ATUALIZA_ATOR,
                        {
                            "actor_id": ator_id,
                            "score": score,
                            "confidence": actor_fingerprint.confianca(1.0, dist, 1),
                            "dist": dist,
                        },
                    )
                continue

            candidato = await _melhor_candidato(
                db, traits, agora - timedelta(days=JANELA_FUSAO_DIAS)
            )

            if candidato is None:
                ref = await _ref_livre(db, traits)
                ator_id = (
                    await db.execute(
                        INSERT_ATOR,
                        {
                            "ref": ref,
                            "traits": json.dumps(traits),
                            "confidence": actor_fingerprint.confianca(1.0, dist, 1),
                            "dist": dist,
                            "requests": len(reqs),
                            "score": score,
                            "now": agora,
                        },
                    )
                ).scalar()
                detalhe = {"motivo": "primeira aparicao desse comportamento"}
                similaridade = 1.0
                novos += 1
            else:
                ator_id, ref, detalhe = candidato
                similaridade = detalhe["score"]
                fundidos += 1
                log.info(
                    "ator %s: %s entrou por semelhanca %.2f (cabecalhos %.2f)",
                    ref,
                    ip,
                    similaridade,
                    detalhe["cabecalhos"],
                )

            await db.execute(
                INSERT_VINCULO,
                {
                    "actor_id": ator_id,
                    "ip": ip,
                    "now": agora,
                    "requests": len(reqs),
                    "similarity": similaridade,
                    "detail": json.dumps(detalhe),
                },
            )
            await db.execute(
                ATUALIZA_ATOR,
                {
                    "actor_id": ator_id,
                    "score": score,
                    "confidence": actor_fingerprint.confianca(similaridade, dist, 1),
                    "dist": dist,
                },
            )

        await db.execute(ADORMECE, {"cutoff": agora - timedelta(hours=DORMENTE_HORAS)})
        await db.commit()

    return {
        "suspeitos": len(suspeitos),
        "novos": novos,
        "fundidos": fundidos,
        "ignorados": ignorados,
    }


async def track_loop() -> None:
    log.info("rastreador de ator iniciado (janela de %d min)", JANELA_MINUTOS)
    while True:
        try:
            resumo = await track_once()
            if resumo["novos"] or resumo["fundidos"]:
                log.info("rastreamento de ator: %s", resumo)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("ciclo de rastreamento falhou: %s", exc)
        await asyncio.sleep(TRACK_SECONDS)
