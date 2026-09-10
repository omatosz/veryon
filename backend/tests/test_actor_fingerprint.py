"""
Testes do motor de identidade de ator.

O modulo e puro de proposito, entao da pra testar a decisao inteira sem banco,
sem container e sem rede. O que esta coberto aqui e o que decide se o recurso
serve ou atrapalha:

  - a assinatura tem que ignorar o que a nossa propria infraestrutura injeta;
  - a mesma ferramenta em IP novo tem que reencontrar o ator;
  - assinatura banal NAO pode fundir ninguem, mesmo com semelhanca alta.

O terceiro e o mais importante. Um falso positivo aqui nao e um alerta a mais:
e o produto afirmando que duas pessoas sao a mesma.
"""

from datetime import datetime, timedelta, timezone

from app.core import actor_fingerprint as af

AGORA = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)

# Ferramenta de varredura: poucos cabecalhos, ordem propria, agente proprio.
SCANNER = ["Host", "User-Agent", "Accept", "Accept-Encoding", "Connection"]
AGENTE_SCANNER = "sqlmap/1.7.2#stable (https://sqlmap.org)"

# Navegador de verdade, com as marcas que so navegador manda.
NAVEGADOR = [
    "Host",
    "Connection",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "Accept",
    "Sec-Fetch-Site",
    "Sec-Fetch-Mode",
    "Accept-Encoding",
    "Accept-Language",
]
AGENTE_NAVEGADOR = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def requisicoes(headers, agente, n=10, passo=1.0, metodo="GET", status=404):
    """Monta uma janela de trafego com ritmo constante."""
    sig = af.assinatura_de_cabecalhos(headers)
    return [
        {
            "ts": AGORA + timedelta(seconds=i * passo),
            "header_sig": sig,
            "user_agent": agente,
            "method": metodo,
            "status_code": status,
        }
        for i in range(n)
    ]


# --- Assinatura de cabecalhos ----------------------------------------------


def test_assinatura_ignora_cabecalhos_injetados_pelo_proxy():
    """O caso que quebraria tudo em silencio.

    Em producao o trafego chega pelo nginx, que carimba x-forwarded-for e
    companhia em TODA requisicao. Se isso entrasse na assinatura, todo mundo
    ficaria parecido com todo mundo e o rastreamento fundiria a internet
    inteira num ator so."""
    direto = af.assinatura_de_cabecalhos(SCANNER)
    via_proxy = af.assinatura_de_cabecalhos(
        ["X-Forwarded-For", "X-Real-IP", "CF-Ray"] + SCANNER
    )
    assert direto == via_proxy


def test_assinatura_preserva_a_ordem():
    """Mesmo conjunto em ordem diferente e ferramenta diferente."""
    a = af.assinatura_de_cabecalhos(["Host", "User-Agent", "Accept"])
    b = af.assinatura_de_cabecalhos(["Accept", "Host", "User-Agent"])
    assert a != b


def test_assinatura_ignora_cabecalho_que_varia_por_requisicao():
    """content-length muda entre GET e POST do mesmo cliente."""
    sem = af.assinatura_de_cabecalhos(["Host", "User-Agent", "Accept"])
    com = af.assinatura_de_cabecalhos(
        ["Host", "Content-Length", "User-Agent", "Content-Type", "Accept"]
    )
    assert sem == com


def test_agente_perde_a_versao():
    """Chrome sobe de versao sozinho. Sem normalizar, o mesmo cliente viraria
    um ator novo a cada atualizacao do navegador."""
    a = af.normalizar_agente("Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36")
    b = af.normalizar_agente("Mozilla/5.0 Chrome/121.0.6167.85 Safari/537.36")
    assert a == b


# --- Ritmo ------------------------------------------------------------------


def test_ritmo_separa_script_de_gente():
    script = af.tracos(requisicoes(SCANNER, AGENTE_SCANNER, n=12, passo=1.0))

    instantes = [0, 3, 18, 20, 60, 67, 110]
    humano = af.tracos(
        [
            {
                "ts": AGORA + timedelta(seconds=s),
                "header_sig": af.assinatura_de_cabecalhos(NAVEGADOR),
                "user_agent": AGENTE_NAVEGADOR,
                "method": "GET",
                "status_code": 200,
            }
            for s in instantes
        ]
    )

    # O que precisa valer nao e o rotulo exato do lado humano (navegacao de
    # gente varia demais pra caber sempre no mesmo balde), e sim que os dois
    # nunca caiam na mesma classe: e por ela que a semelhanca compara.
    assert script["ritmo"].endswith("metronomico")
    assert not humano["ritmo"].endswith("metronomico")
    assert script["ritmo"] != humano["ritmo"]


def test_amostra_pequena_nao_afirma_ritmo():
    poucas = af.tracos(requisicoes(SCANNER, AGENTE_SCANNER, n=2))
    assert poucas["ritmo"] == "indefinido"


# --- Fusao ------------------------------------------------------------------


def test_mesma_ferramenta_em_ip_novo_reencontra_o_ator():
    """O motivo de tudo isso existir: o atacante troca de IP, o comportamento
    nao troca junto."""
    terca = af.tracos(requisicoes(SCANNER, AGENTE_SCANNER))
    quinta = af.tracos(requisicoes(SCANNER, AGENTE_SCANNER))

    funde, detalhe = af.pode_fundir(terca, quinta)
    assert funde
    assert detalhe["score"] >= af.LIMIAR_FUSAO


def test_ferramentas_diferentes_nao_fundem():
    scanner = af.tracos(requisicoes(SCANNER, AGENTE_SCANNER))
    outro = af.tracos(
        requisicoes(
            ["Host", "Accept", "Accept-Language", "User-Agent", "X-Requested-With"],
            "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        )
    )
    funde, _ = af.pode_fundir(scanner, outro)
    assert not funde


def test_cabecalho_a_mais_nao_quebra_a_identidade():
    """Hash exato quebraria aqui, e e por isso que a comparacao e por
    semelhanca: a ferramenta ganhou um cabecalho entre uma campanha e outra."""
    antes = af.tracos(requisicoes(SCANNER, AGENTE_SCANNER))
    depois = af.tracos(requisicoes(SCANNER + ["Cache-Control"], AGENTE_SCANNER))

    funde, detalhe = af.pode_fundir(antes, depois)
    assert funde, detalhe


# --- Os trilhos de seguranca ------------------------------------------------


def test_navegador_comum_nunca_sustenta_identidade():
    """Dois visitantes de Chrome tem tracos praticamente identicos. Se isso
    fundisse, o Veryon estaria dizendo que duas pessoas sao a mesma com base em
    nada. Tem que recusar mesmo com semelhanca alta."""
    visitante_a = af.tracos(requisicoes(NAVEGADOR, AGENTE_NAVEGADOR, status=200))
    visitante_b = af.tracos(requisicoes(NAVEGADOR, AGENTE_NAVEGADOR, status=200))

    semelhanca = af.semelhanca(visitante_a, visitante_b)
    funde, detalhe = af.pode_fundir(visitante_a, visitante_b)

    assert semelhanca["score"] > 0.9, "os tracos sao mesmo quase iguais"
    assert not funde, "e exatamente por isso que a distintividade tem veto"
    assert "comum" in detalhe["motivo"]


def test_curl_padrao_nao_funde_com_outro_curl_padrao():
    """Cliente pelado com agente banal e o denominador comum da internet."""
    a = af.tracos(requisicoes(["Host", "User-Agent", "Accept"], "curl/8.1.2"))
    b = af.tracos(requisicoes(["Host", "User-Agent", "Accept"], "curl/8.4.0"))

    funde, detalhe = af.pode_fundir(a, b)
    assert not funde
    assert detalhe["distintividade"] < af.MIN_DISTINTIVIDADE


def test_agente_de_navegador_sem_cabecalho_de_navegador_e_distintivo():
    """Ferramenta com User-Agent trocado pra parecer Chrome. A mentira nao
    passa despercebida: navegador de verdade manda sec-fetch e sec-ch-ua, e
    quem so copia a string do agente nao manda."""
    disfarcado = af.tracos(requisicoes(SCANNER, AGENTE_NAVEGADOR))
    assert af.distintividade(disfarcado) > af.MIN_DISTINTIVIDADE

    outro_igual = af.tracos(requisicoes(SCANNER, AGENTE_NAVEGADOR))
    funde, _ = af.pode_fundir(disfarcado, outro_igual)
    assert funde


def test_sem_assinatura_nao_ha_identidade():
    """Log de acesso simples nao traz cabecalho. Melhor nenhum ator do que um
    ator inventado."""
    vazio = af.tracos(requisicoes([], None))
    assert af.distintividade(vazio) == 0.0
    funde, _ = af.pode_fundir(vazio, vazio)
    assert not funde


# --- Confianca --------------------------------------------------------------


def test_confianca_nunca_e_alta_com_assinatura_banal():
    assert af.confianca(1.0, 0.25, 3) == "low"


def test_confianca_alta_exige_semelhanca_e_distintividade():
    assert af.confianca(0.95, 0.70, 2) == "high"
    assert af.confianca(0.80, 0.70, 2) == "medium"
