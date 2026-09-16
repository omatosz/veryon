from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    redis_url: str

    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    admin_username: str
    admin_password: str

    # Origens que podem chamar a API do navegador, separadas por vírgula. O
    # padrão cobre só o Vite local. Em produção, com o painel servido de outro
    # endereço (nginx, domínio próprio), este valor precisa listar esse
    # endereço, senão o navegador bloqueia a resposta antes de o JS ver ela.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Liga a rota que dispara todas as simulacoes de ataque de uma vez. Fica
    # desligada por padrao de proposito: um cliente de verdade nao tem
    # honeypot nem alvo vulneravel no proprio ambiente (ver deploy/), entao um
    # botao "ataque a mim mesmo" no painel dele nao serve pra nada. A rota
    # devolve 404 com isto desligado, pra nem revelar que existe.
    demo_mode_enabled: bool = False

    # De quanto em quanto tempo o backend recarrega a blocklist do banco.
    # Mesmo intervalo dos dois scripts de enforcement, entao o pior caso de
    # atraso continua sendo o mesmo nos dois atuadores.
    blocklist_refresh_seconds: int = 5
    # So ligar atras de um proxy de confianca. Com isso ligado, quem chama a
    # API pode forjar X-Forwarded-For e escapar do bloqueio.
    trust_proxy_headers: bool = False

    # Chave que o gateway do cliente usa pra mandar log de acesso pro
    # /ingest/api-logs. Vazia desliga a ingestao: sem chave configurada o
    # endpoint recusa tudo, em vez de aceitar de qualquer um.
    ingest_api_key: str = ""
    # Ligar a observacao do proprio trafego da API. Desligar so faz sentido se
    # o volume incomodar; a analise passa a depender so do que for ingerido.
    api_traffic_capture: bool = True

    # --- Notificacoes ---
    # Chave geral. Desligado o laco nem sobe, e o checkpoint fica parado. Ao
    # religar, o notificador retoma do ponto em que estava e nao dispara o
    # atrasado: o proprio checkpoint e avancado a cada ciclo.
    notifications_enabled: bool = False
    # De quanto em quanto tempo o laco olha alertas novos e tenta entregar o
    # que esta pendente. Nao adianta ser menor que o ciclo de quem produz
    # alerta, que hoje e 10s.
    notification_poll_seconds: int = 15
    # Alerta abaixo desta severidade nao vira notificacao em canal nenhum.
    # O canal ainda pode exigir mais que isso no proprio min_level.
    notification_min_level: str = "high"
    # Janela de agrupamento. Dentro dela, o mesmo grupo (regra + ip) nao gera
    # mensagem nova depois de ja ter saido uma. Sem isso, um scan de dez
    # minutos vira centenas de mensagens iguais e a pessoa silencia o canal,
    # que e o pior desfecho possivel.
    notification_group_minutes: int = 10
    # Teto de mensagens por canal por hora, somando todos os grupos. E o
    # trilho que impede erro sistematico de virar incidente de ruido. Conta so
    # o que sai sozinho: um resumo e uma mensagem por periodo e nao disputa
    # este limite com o alerta urgente.
    notification_max_per_hour: int = 20
    # De quanto em quanto tempo o resumo sai. Tudo o que ficou abaixo do
    # immediate_level do canal se acumula e vira uma mensagem so a cada
    # periodo destes. Uma hora e o intervalo que mantem o resumo curto o
    # bastante pra alguem ler de verdade.
    notification_digest_minutes: int = 60
    # Depois disso a mensagem vira 'failed' e para de tentar. Webhook que
    # falhou cinco vezes com backoff nao vai passar na sexta; o que resolve e
    # alguem olhar a URL.
    notification_max_attempts: int = 5
    # Tempo limite de cada entrega, webhook ou e-mail. Curto de proposito: o
    # laco de notificacao nao pode ficar preso num destino lento.
    notification_timeout_seconds: float = 10.0

    # --- SMTP, usado pelos canais de tipo 'email' ---
    # Segredo de infraestrutura, entao mora aqui e nao no banco: o banco guarda
    # so para quem mandar. Com smtp_host vazio, canal de e-mail falha com erro
    # claro em vez de estourar no meio do laco.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    # Remetente. Vazio usa o smtp_user, que e o caso comum em Gmail e afins.
    smtp_from: str = ""
    # STARTTLS na porta 587, o padrao hoje. Desligar so faz sentido contra
    # servidor interno sem TLS, tipo um relay na propria rede.
    smtp_starttls: bool = True
    # TLS implicito na porta 465. Quando ligado, o starttls e ignorado.
    smtp_ssl: bool = False

    # --- Retencao e compressao no Timescale ---
    # As politicas moram no banco, mas quem manda nelas e este bloco: a cada
    # boot o backend compara o que esta configurado aqui com o que existe no
    # banco e corrige a diferenca. Trocar um prazo e editar o .env e reiniciar,
    # nao escrever migration.
    #
    # Em qualquer um dos campos abaixo, 0 desliga aquela politica.
    #
    # Desligado, nada e comprimido nem apagado automaticamente, e o backend
    # remove as politicas que existirem. E a posicao segura: politica de
    # retencao apaga dado de verdade, entao desligar tem que parar de apagar.
    retention_enabled: bool = True

    # Evento cru do honeypot e dos coletores. Comprime cedo porque a deteccao
    # so olha o que acabou de chegar. Noventa dias cobre investigacao para tras
    # e e o prazo que a maioria dos clientes pede em contrato.
    raw_events_compress_after_days: int = 7
    raw_events_drop_after_days: int = 90

    # Alerta e a memoria do produto. Padrao e nunca apagar: comprimido ele
    # ocupa pouco, e um SOC que esquece o que ja viu perde a parte que
    # interessa. Trinta dias antes de comprimir porque tria de alerta antigo
    # ainda acontece, e UPDATE em chunk comprimido e caro.
    alerts_compress_after_days: int = 30
    alerts_drop_after_days: int = 0

    # Trafego de API e o maior volume do sistema e o mais descartavel. Dois
    # dias antes de comprimir, e nao um, porque o analisador calcula a linha de
    # base olhando 24h para tras: comprimir com um dia colocaria a janela de
    # analise em cima do chunk comprimido a cada volta.
    api_requests_compress_after_days: int = 2
    api_requests_drop_after_days: int = 7

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
