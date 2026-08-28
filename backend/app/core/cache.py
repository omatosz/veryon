import redis.asyncio as redis

from app.core.config import settings

# Cliente unico do processo. redis-py ja faz pool por baixo, entao dividir o
# mesmo cliente entre o health check e a blocklist e o certo.
redis_client = redis.from_url(settings.redis_url)
