from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.limiter import limiter
from app.core.security import create_access_token, verify_password
from app.db.models import User
from app.db.session import get_db
from app.schemas import Token, UserOut

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    website: str = Form(default=""),
    db: AsyncSession = Depends(get_db),
):
    # honeypot: campo escondido no formulario que só um bot preencheria
    # automaticamente; usuario real nunca ve nem toca nesse campo
    if website:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais invalidas")

    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais invalidas")

    # Conta desligada nao recebe token. A mensagem e a mesma de senha errada
    # de proposito: dizer "sua conta foi desativada" confirma para quem esta
    # tentando que aquele nome existe.
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais invalidas")

    return Token(access_token=create_access_token(user.username))


@router.get("/auth/me", response_model=UserOut)
async def quem_sou_eu(user: User = Depends(get_current_user)):
    """Quem esta logado e com que papel.

    A tela precisa disto para nao oferecer botao que a API vai recusar. O
    papel viaja aqui, e nao dentro do token, porque o token dura uma hora e
    tirar o admin de alguem tem que valer na hora seguinte, nao na proxima.
    """
    return user
