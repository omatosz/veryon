"""
Laco de notificacao.

A cada ciclo faz duas coisas, nesta ordem:

1. Enfileira. Le os alertas que apareceram desde o checkpoint e decide, para
   cada canal ligado, se aquilo vira mensagem.
2. Entrega. Pega o que esta pendente e ja pode tentar, e faz o POST.

Os dois produtores de alerta (detection/, container proprio, e api_analyzer,
dentro do backend) nao sabem que este arquivo existe. Eles continuam so
escrevendo em alerts. Quem descobre o alerta novo e este laco, lendo a tabela
a partir de um checkpoint, do mesmo jeito que o detection le raw_events a
partir de detection_checkpoint.

OS SETE TRILHOS

Espelham a ideia dos trilhos da prevencao: limites que nao dependem de
configuracao de canal nenhum, porque existem para impedir que a propria
ferramenta vire o incidente.

1. Canal nasce desligado. Nada sai ate alguem preencher a URL e ligar na mao.
2. Severidade minima, global e por canal. Vence a mais exigente das duas.
3. Uma mensagem pendente por grupo, por canal. Repeticao vira contador, nao
   mensagem nova. Garantido por indice unico parcial, nao por logica: duas
   instancias do backend nao conseguem furar isso.
4. Silencio pos-envio. Grupo que ja saiu nao volta dentro da janela; o alerta
   novo incrementa o contador da mensagem que ja foi.
5. Teto por hora, por canal. Ao bater o teto o pendente espera o proximo
   ciclo. Nada e descartado, so adiado.
6. Backoff exponencial e teto de tentativas. Webhook que falhou cinco vezes
   nao passa na sexta; o que resolve e alguem olhar a URL.
7. Nada e invisivel. Tentativa, erro e horario de envio ficam na propria
   linha da fila.

O que nao e registrado, de proposito: alerta descartado por severidade baixa.
Isso e configuracao explicita, nao trilho de seguranca, e gravar uma linha por
alerta informativo encheria a tabela sem informar nada.
"""

import asyncio
import json
import logging
import smtplib
from email.message import EmailMessage
from typing import Any

import httpx
from sqlalchemy import text

from app.core import notify_adapters
from app.core.config import settings
from app.db.session import async_session

log = logging.getLogger("veryon.notifier")

# Teto de alertas lidos por ciclo. Uma rajada muito grande nao pode fazer o
# notificador puxar o historico inteiro pra memoria.
MAX_ALERTAS_POR_CICLO = 500
# Teto de mensagens entregues por ciclo. Segura o laco: com muitos pendentes,
# entrega aos poucos em vez de prender o ciclo por minutos.
MAX_ENTREGAS_POR_CICLO = 20
# Base do backoff, em minutos. Tentativa n espera BACKOFF_BASE * 2^(n-1).
BACKOFF_BASE_MINUTOS = 2

FETCH_CHECKPOINT = text("SELECT last_alert_id FROM notification_checkpoint WHERE id = 1")

SAVE_CHECKPOINT = text("UPDATE notification_checkpoint SET last_alert_id = :ultimo WHERE id = 1")

FETCH_CANAIS = text(
    # Sem o destino de proposito: enfileirar so decide se a mensagem existe e
    # para qual canal. Quem precisa saber o endereco e a entrega, que busca em
    # FETCH_PENDENTES no momento de mandar. Assim uma troca de destino vale
    # para o que ja esta na fila.
    "SELECT id, name, kind, min_level, immediate_level "
    "FROM notification_channels WHERE enabled"
)

FETCH_ALERTAS_NOVOS = text(
    """
    SELECT id, ts, rule_id, title, level, mitre_technique, source_ip
      FROM alerts
     WHERE id > :desde
     ORDER BY id
     LIMIT :cap
    """
)

# Enfileira. O ON CONFLICT usa o indice unico parcial de pendentes: se ja
# existe mensagem pendente para o mesmo grupo neste canal, o alerta novo vira
# incremento de contador em vez de mensagem nova.
#
# O nivel sobe mas nunca desce: se o grupo ja tinha um critical pendente e
# chega um high, a mensagem continua critical. O contrario esconderia a
# gravidade atras da ultima ocorrencia.
def _upsert(status: str):
    """Monta o INSERT de enfileiramento para 'pending' ou 'digest'.

    Os dois sao identicos menos por uma coisa: o predicado do ON CONFLICT. Cada
    status tem seu proprio indice unico parcial, e o Postgres so infere o
    indice certo se o predicado bater exatamente. Por isso a consulta e gerada
    em vez de escrita duas vezes: duplicar sessenta linhas de SQL para trocar
    uma palavra e como as duas versoes divergem sem ninguem perceber.

    O nivel sobe mas nunca desce: se o grupo ja tinha um critical acumulado e
    chega um high, a mensagem continua critical. O contrario esconderia a
    gravidade atras da ultima ocorrencia.
    """
    return text(
        f"""
        INSERT INTO alert_notifications
            (channel_id, group_key, status, level, level_weight, title, rule_id,
             source_ip, first_alert_id, last_alert_id, payload)
        VALUES
            (:canal, :grupo, '{status}', :level, :peso_novo, :title, :rule_id,
             :source_ip, :alerta, :alerta, CAST(:payload AS jsonb))
        ON CONFLICT (channel_id, group_key) WHERE status = '{status}'
        DO UPDATE SET
            alert_count = alert_notifications.alert_count + 1,
            last_alert_id = EXCLUDED.last_alert_id,
            level = CASE
                WHEN EXCLUDED.level_weight > alert_notifications.level_weight
                THEN EXCLUDED.level ELSE alert_notifications.level
            END,
            title = CASE
                WHEN EXCLUDED.level_weight > alert_notifications.level_weight
                THEN EXCLUDED.title ELSE alert_notifications.title
            END,
            level_weight = greatest(alert_notifications.level_weight, EXCLUDED.level_weight),
            updated_at = now()
        """
    )


UPSERT_PENDENTE = _upsert("pending")
UPSERT_DIGEST = _upsert("digest")

# Trilho 4: grupo entregue ha pouco. Em vez de criar mensagem nova, soma na
# que ja saiu, para nao perder a contagem.
ABSORVER_EM_ENVIADA = text(
    """
    UPDATE alert_notifications
       SET alert_count = alert_count + 1,
           last_alert_id = :alerta,
           updated_at = now()
     WHERE id = (
        SELECT id FROM alert_notifications
         WHERE channel_id = :canal
           AND group_key = :grupo
           AND status = 'sent'
           AND sent_as = 'single'
           AND sent_at > now() - make_interval(mins => :janela)
         ORDER BY sent_at DESC
         LIMIT 1
     )
    """
)

FETCH_PENDENTES = text(
    """
    SELECT n.id, n.channel_id, n.group_key, n.level, n.title, n.rule_id,
           n.source_ip, n.alert_count, n.attempts, n.payload,
           c.kind, c.target, c.name
      FROM alert_notifications n
      JOIN notification_channels c ON c.id = n.channel_id
     WHERE n.status = 'pending'
       AND n.next_attempt_at <= now()
       AND c.enabled
     ORDER BY n.created_at
     LIMIT :cap
    """
)

CONTAR_ENVIADAS_NA_HORA = text(
    """
    SELECT channel_id, count(*) AS n
      FROM alert_notifications
     WHERE status = 'sent'
       AND sent_as = 'single'
       AND sent_at > now() - interval '1 hour'
     GROUP BY channel_id
    """
)

MARCAR_ENVIADA = text(
    """
    UPDATE alert_notifications
       SET status = 'sent', sent_at = now(), updated_at = now(),
           attempts = attempts + 1, last_error = NULL
     WHERE id = :id
    """
)

MARCAR_FALHA = text(
    """
    UPDATE alert_notifications
       SET attempts = attempts + 1,
           last_error = :erro,
           updated_at = now(),
           status = CASE WHEN attempts + 1 >= :teto THEN 'failed' ELSE 'pending' END,
           next_attempt_at = now() + make_interval(mins => :espera)
     WHERE id = :id
    """
)


def chave_de_grupo(alerta: dict[str, Any]) -> str:
    """A unidade de agrupamento: hoje regra + IP de origem.

    Fica numa funcao sozinha de proposito. Se o rastreamento de ator for
    descongelado, esta funcao passa a devolver a identidade do ator e o
    agrupamento passa a valer entre IPs diferentes, sem que nada mais neste
    arquivo mude.
    """
    return f"{alerta.get('rule_id') or 'sem-regra'}|{alerta.get('source_ip') or 'sem-ip'}"


def nivel_minimo(canal_min: str | None) -> int:
    """Vence a exigencia mais alta entre o minimo global e o do canal."""
    return max(
        notify_adapters.peso_do_nivel(settings.notification_min_level),
        notify_adapters.peso_do_nivel(canal_min),
    )


def _resumo(linha: dict[str, Any]) -> dict[str, Any]:
    """O que o adaptador precisa para montar o corpo da mensagem."""
    carga = linha.get("payload") or {}
    if isinstance(carga, str):
        try:
            carga = json.loads(carga)
        except ValueError:
            carga = {}
    return {
        "level": linha.get("level"),
        "title": linha.get("title"),
        "rule_id": linha.get("rule_id"),
        "source_ip": linha.get("source_ip"),
        "alert_count": linha.get("alert_count") or 1,
        "mitre_technique": carga.get("mitre_technique"),
    }


def _enviar_email_sincrono(destinos: list[str], assunto: str, corpo: str) -> None:
    """Manda o e-mail de verdade. Sincrono de proposito, ver _enviar_email."""
    if not settings.smtp_host:
        raise RuntimeError(
            "canal de e-mail configurado, mas SMTP_HOST esta vazio. "
            "Preencha SMTP_HOST, SMTP_USER e SMTP_PASSWORD no .env"
        )

    msg = EmailMessage()
    msg["Subject"] = assunto
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = ", ".join(destinos)
    msg.set_content(corpo)

    tempo = settings.notification_timeout_seconds

    if settings.smtp_ssl:
        servidor = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=tempo)
    else:
        servidor = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=tempo)

    with servidor:
        if settings.smtp_starttls and not settings.smtp_ssl:
            servidor.starttls()
        # Servidor interno de relay costuma nao pedir autenticacao. Tentar
        # login sem usuario configurado daria erro onde nao ha problema.
        if settings.smtp_user:
            servidor.login(settings.smtp_user, settings.smtp_password)
        servidor.send_message(msg)


async def _enviar_email(destino: str, resumo: dict[str, Any]) -> None:
    """Envia por SMTP sem travar o laco.

    O smtplib e sincrono e bloqueia. Rodar direto aqui prenderia o event loop
    inteiro do backend durante o handshake de TLS e o envio, ou seja, a API
    inteira ficaria parada esperando um servidor de e-mail responder.

    asyncio.to_thread joga isso numa thread e devolve o controle. Escolhido em
    vez de trazer aiosmtplib porque o volume e minusculo, no maximo algumas
    dezenas por hora pelo teto do trilho 5, e uma dependencia a menos e uma
    dependencia a menos para atualizar depois.
    """
    montado = notify_adapters.montar_email(resumo)
    # Varios destinatarios separados por virgula no mesmo canal.
    destinos = [d.strip() for d in destino.split(",") if d.strip()]
    if not destinos:
        raise RuntimeError("canal de e-mail sem destinatario")

    await asyncio.to_thread(
        _enviar_email_sincrono, destinos, montado["subject"], montado["body"]
    )


async def entregar(cliente: httpx.AsyncClient, linha: dict[str, Any]) -> None:
    """Entrega uma mensagem pelo transporte do canal.

    Webhook e e-mail sao transportes diferentes e param aqui. Tudo o que vem
    antes, decidir, agrupar, contar e adiar, e igual para os dois, e tudo o que
    vem depois, marcar sucesso ou falha com backoff, tambem.
    """
    resumo = _resumo(linha)

    if linha["kind"] == "email":
        await _enviar_email(linha["target"], resumo)
        return

    corpo = notify_adapters.montar_corpo(linha["kind"], resumo)
    resposta = await cliente.post(linha["target"], json=corpo)
    resposta.raise_for_status()


async def enfileirar_novos() -> int:
    """Le os alertas desde o checkpoint e decide o que vira mensagem.

    Devolve quantas decisoes de enfileiramento foram tomadas. O checkpoint
    avanca mesmo quando nenhum alerta vira mensagem: o objetivo dele e nao
    reprocessar, nao registrar sucesso.
    """
    enfileirados = 0

    async with async_session() as sessao:
        desde = (await sessao.execute(FETCH_CHECKPOINT)).scalar_one()
        canais = [dict(l) for l in (await sessao.execute(FETCH_CANAIS)).mappings()]
        if not canais:
            # Sem canal ligado nao ha o que decidir, mas o checkpoint precisa
            # andar assim mesmo. Senao, o dia em que alguem ligar o primeiro
            # canal viraria uma avalanche de tudo que se acumulou.
            ultimo = (
                await sessao.execute(
                    text("SELECT COALESCE(max(id), :desde) FROM alerts WHERE id > :desde"),
                    {"desde": desde},
                )
            ).scalar_one()
            if ultimo != desde:
                await sessao.execute(SAVE_CHECKPOINT, {"ultimo": ultimo})
                await sessao.commit()
            return 0

        alertas = [
            dict(l)
            for l in (
                await sessao.execute(
                    FETCH_ALERTAS_NOVOS, {"desde": desde, "cap": MAX_ALERTAS_POR_CICLO}
                )
            ).mappings()
        ]
        if not alertas:
            return 0

        for alerta in alertas:
            peso = notify_adapters.peso_do_nivel(alerta.get("level"))
            grupo = chave_de_grupo(alerta)

            for canal in canais:

                # Trilho 2: severidade.
                if peso < nivel_minimo(canal.get("min_level")):
                    continue

                # O caminho: interrompe agora ou espera o resumo. Quem decide
                # e a severidade contra o immediate_level do canal.
                imediato = peso >= notify_adapters.peso_do_nivel(
                    canal.get("immediate_level")
                )

                # Trilho 4: grupo entregue ha pouco absorve o alerta novo.
                #
                # So vale no caminho imediato. Se valesse tambem no digest, um
                # alerta que chegasse logo depois de um resumo sair seria somado
                # a uma linha ja entregue, ou seja, sumiria: o resumo daquele
                # periodo ja foi, e o proximo nao teria por que inclui-lo. No
                # caminho do digest o alerta sempre entra no acumulador, que so
                # e zerado quando o resumo seguinte sai.
                if imediato:
                    absorvido = await sessao.execute(
                        ABSORVER_EM_ENVIADA,
                        {
                            "canal": canal["id"],
                            "grupo": grupo,
                            "alerta": alerta["id"],
                            "janela": settings.notification_group_minutes,
                        },
                    )
                    if absorvido.rowcount:
                        continue

                consulta = UPSERT_PENDENTE if imediato else UPSERT_DIGEST

                # Trilho 3: um acumulador por grupo, em cada caminho. O indice
                # parcial resolve o conflito virando incremento.
                await sessao.execute(
                    consulta,
                    {
                        "canal": canal["id"],
                        "grupo": grupo,
                        "level": alerta.get("level"),
                        "title": alerta.get("title"),
                        "rule_id": alerta.get("rule_id"),
                        "source_ip": alerta.get("source_ip"),
                        "alerta": alerta["id"],
                        "peso_novo": peso,
                        "payload": json.dumps(
                            {"mitre_technique": alerta.get("mitre_technique")}
                        ),
                    },
                )
                enfileirados += 1

        await sessao.execute(SAVE_CHECKPOINT, {"ultimo": alertas[-1]["id"]})
        await sessao.commit()

    return enfileirados


async def entregar_pendentes() -> dict[str, int]:
    """Faz o POST do que esta pendente, respeitando o teto por hora."""
    resultado = {"enviadas": 0, "falhas": 0, "adiadas_por_teto": 0}

    async with async_session() as sessao:
        pendentes = [
            dict(l)
            for l in (
                await sessao.execute(FETCH_PENDENTES, {"cap": MAX_ENTREGAS_POR_CICLO})
            ).mappings()
        ]
        if not pendentes:
            return resultado

        # Trilho 5: teto por hora, contado por canal.
        ja_enviadas = {
            l["channel_id"]: l["n"]
            for l in (await sessao.execute(CONTAR_ENVIADAS_NA_HORA)).mappings()
        }

        async with httpx.AsyncClient(timeout=settings.notification_timeout_seconds) as cliente:
            for linha in pendentes:
                canal_id = linha["channel_id"]
                if ja_enviadas.get(canal_id, 0) >= settings.notification_max_per_hour:
                    resultado["adiadas_por_teto"] += 1
                    continue

                try:
                    await entregar(cliente, linha)
                except Exception as exc:  # noqa: BLE001
                    tentativas = int(linha["attempts"]) + 1
                    espera = BACKOFF_BASE_MINUTOS * (2 ** (tentativas - 1))
                    await sessao.execute(
                        MARCAR_FALHA,
                        {
                            "id": linha["id"],
                            "erro": str(exc)[:500],
                            "teto": settings.notification_max_attempts,
                            "espera": espera,
                        },
                    )
                    resultado["falhas"] += 1
                    log.warning(
                        "entrega no canal %s (%s) falhou (tentativa %d): %s",
                        linha["name"],
                        linha["kind"],
                        tentativas,
                        exc,
                    )
                    continue

                await sessao.execute(MARCAR_ENVIADA, {"id": linha["id"]})
                ja_enviadas[canal_id] = ja_enviadas.get(canal_id, 0) + 1
                resultado["enviadas"] += 1

        await sessao.commit()

    return resultado


CANAIS_COM_DIGEST_VENCIDO = text(
    """
    SELECT c.id, c.name, c.kind, c.target
      FROM notification_channels c
     WHERE c.enabled
       AND (c.last_digest_at IS NULL
            OR c.last_digest_at <= now() - make_interval(mins => :periodo))
       AND EXISTS (SELECT 1 FROM alert_notifications n
                    WHERE n.channel_id = c.id AND n.status = 'digest')
    """
)

FETCH_ITENS_DIGEST = text(
    """
    SELECT id, level, title, rule_id, source_ip, alert_count, payload
      FROM alert_notifications
     WHERE channel_id = :canal AND status = 'digest'
     ORDER BY level_weight DESC, alert_count DESC
     LIMIT :cap
    """
)

FECHAR_DIGEST = text(
    """
    UPDATE alert_notifications
       SET status = 'sent', sent_as = 'digest', sent_at = now(), updated_at = now()
     WHERE id = ANY(:ids)
    """
)

MARCAR_DIGEST_ENVIADO = text(
    "UPDATE notification_channels SET last_digest_at = now() WHERE id = :canal"
)

# Teto de itens num resumo. Acima disso ninguem le, e a mensagem estoura o
# limite de tamanho de webhook. O que passar fica para o proximo periodo.
MAX_ITENS_DIGEST = 25


async def enviar_digests() -> int:
    """Junta o que acumulou em cada canal e manda uma mensagem so.

    Roda a cada ciclo, mas so age no canal cujo periodo venceu. Um canal sem
    nada acumulado nem entra na consulta.

    Falha aqui nao tem backoff nem tentativa: se o resumo nao sair agora, as
    linhas continuam com status 'digest' e o proximo ciclo tenta de novo, ja
    com o que chegou no meio tempo. Resumo atrasado por dez minutos e resumo;
    alerta urgente atrasado e outra coisa, e por isso aquele tem retry e este
    nao precisa.
    """
    enviados = 0

    async with async_session() as sessao:
        canais = [
            dict(l)
            for l in (
                await sessao.execute(
                    CANAIS_COM_DIGEST_VENCIDO,
                    {"periodo": settings.notification_digest_minutes},
                )
            ).mappings()
        ]
        if not canais:
            return 0

        async with httpx.AsyncClient(timeout=settings.notification_timeout_seconds) as cliente:
            for canal in canais:
                itens = [
                    dict(l)
                    for l in (
                        await sessao.execute(
                            FETCH_ITENS_DIGEST,
                            {"canal": canal["id"], "cap": MAX_ITENS_DIGEST},
                        )
                    ).mappings()
                ]
                if not itens:
                    continue

                montado = notify_adapters.montar_digest(canal["kind"], itens)

                try:
                    if canal["kind"] == "email":
                        destinos = [d.strip() for d in canal["target"].split(",") if d.strip()]
                        await asyncio.to_thread(
                            _enviar_email_sincrono,
                            destinos,
                            montado["subject"],
                            montado["body"],
                        )
                    else:
                        resposta = await cliente.post(canal["target"], json=montado)
                        resposta.raise_for_status()
                except Exception as exc:  # noqa: BLE001
                    log.warning("resumo do canal %s falhou: %s", canal["name"], exc)
                    continue

                await sessao.execute(FECHAR_DIGEST, {"ids": [i["id"] for i in itens]})
                await sessao.execute(MARCAR_DIGEST_ENVIADO, {"canal": canal["id"]})
                enviados += 1

        await sessao.commit()

    return enviados


async def notificar_once() -> dict[str, int]:
    enfileirados = await enfileirar_novos()
    entregas = await entregar_pendentes()
    resumos = await enviar_digests()
    return {"enfileirados": enfileirados, **entregas, "resumos": resumos}


async def sincronizar_checkpoint() -> int:
    """Leva o checkpoint para o ultimo alerta que existe, na subida do laco.

    Notificacao serve pra avisar que algo esta acontecendo agora. Um alerta de
    tres dias atras nao precisa de push; ele precisa da tela de Alertas, que
    ja existe. Sem isso, ligar o notificador num banco com historico mandaria
    a fila inteira de uma vez, o destinatario silenciaria o canal, e o
    proximo alerta de verdade morreria no mudo.
    """
    async with async_session() as sessao:
        ultimo = (
            await sessao.execute(text("SELECT COALESCE(max(id), 0) FROM alerts"))
        ).scalar_one()
        await sessao.execute(SAVE_CHECKPOINT, {"ultimo": ultimo})
        await sessao.commit()
    return ultimo


async def notify_loop() -> None:
    ultimo = await sincronizar_checkpoint()
    log.info(
        "notificador iniciado (ciclo de %ds, minimo global '%s', teto de %d/hora, "
        "comecando a partir do alerta %d)",
        settings.notification_poll_seconds,
        settings.notification_min_level,
        settings.notification_max_per_hour,
        ultimo,
    )
    while True:
        try:
            resumo = await notificar_once()
            if any(resumo.values()):
                log.info("notificacao: %s", resumo)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("ciclo de notificacao falhou: %s", exc)
        await asyncio.sleep(settings.notification_poll_seconds)
