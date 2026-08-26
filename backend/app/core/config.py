from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    redis_url: str

    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    admin_username: str
    admin_password: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
