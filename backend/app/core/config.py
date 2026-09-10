from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    redis_url: str

    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    admin_username: str
    admin_password: str

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

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
