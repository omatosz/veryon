from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_password
from app.db.models import User
from app.db.session import async_session


async def seed_admin_user():
    async with async_session() as session:
        result = await session.execute(select(User).where(User.username == settings.admin_username))
        if result.scalar_one_or_none() is not None:
            return

        session.add(User(username=settings.admin_username, password_hash=hash_password(settings.admin_password)))
        await session.commit()
        print(f"usuario admin '{settings.admin_username}' criado", flush=True)
