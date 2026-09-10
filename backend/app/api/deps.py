import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.models import User
from app.db.session import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Quem esta chamando, lido do banco a cada requisicao.

    O papel poderia viajar dentro do token e evitar esta consulta, mas ai ele
    so mudaria de verdade quando o token expirasse. Tirar o admin de alguem
    levaria ate uma hora para valer, e o mesmo vale para desligar a conta de
    quem saiu da empresa. Num produto de seguranca isso nao se sustenta, e uma
    busca por indice unico e barata perto do custo de errar aqui.
    """
    try:
        username = decode_access_token(token)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()

    # Mesma resposta para usuario apagado e para conta desligada: 401 com a
    # mesma mensagem. Distinguir os dois casos entregaria de graca a
    # informacao de quais nomes existem no sistema.
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def current_username(user: User = Depends(get_current_user)) -> str:
    """So o nome, para os campos de auditoria.

    Existe para os endpoints que gravam quem fez a acao (`blocked_by`,
    `updated_by`, `requested_by`) e nao precisam do resto do usuario. O
    FastAPI reaproveita o resultado de get_current_user dentro da mesma
    requisicao, entao isto nao gera consulta a mais.
    """
    return user.username


async def require_admin(user: User = Depends(get_current_user)) -> User:
    """Barra quem nao e admin.

    403 e nao 404: quem chegou aqui esta autenticado, o recurso existe, e o
    problema e permissao. Esconder isso atras de 404 confundiria o analista
    honesto sem atrapalhar ninguem mal-intencionado, que ja sabe que a rota
    existe pela documentacao da propria API.
    """
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta ação é restrita a administradores",
        )
    return user
