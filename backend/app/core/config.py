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

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
