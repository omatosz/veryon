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

        # role explicito: o server_default da coluna e 'analyst', e o usuario
        # do .env e justamente o que precisa poder tudo no primeiro boot.
        session.add(
            User(
                username=settings.admin_username,
                password_hash=hash_password(settings.admin_password),
                role="admin",
            )
        )
        await session.commit()
        print(f"usuario admin '{settings.admin_username}' criado", flush=True)
