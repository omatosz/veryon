"""Gestao de usuarios e papeis.

Sem isto, o unico usuario do Veryon e o que o `.env` cria no boot, e entregar
acesso a alguem significa entregar a conta do dono. Este router e o que
transforma "o sistema tem login" em "o sistema tem contas".

Tudo aqui e restrito a admin, inclusive a listagem: quem sao os usuarios e com
que poder cada um entra e informacao de administracao, nao de operacao.

## As tres travas

Existe uma forma classica de se trancar para fora de um painel: rebaixar a si
mesmo. As tres travas abaixo existem para isso, e as duas primeiras valem
mesmo para quem e admin, porque a intencao nao muda o estrago.

1. Ninguem muda o proprio papel.
2. Ninguem desliga a propria conta.
3. O ultimo admin ativo nao pode ser rebaixado nem desligado por ninguem.

Sem a terceira, dois admins poderiam se rebaixar em sequencia, cada um deles
respeitando as duas primeiras, e o sistema ficaria sem nenhum administrador.
A saida seria mexer no banco na mao.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.security import hash_password
from app.db.models import User
from app.db.session import get_db
from app.schemas import UserCreate, UserOut, UserUpdate

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_admin)],
)


async def _admins_ativos(db: AsyncSession) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(User)
            .where(User.role == "admin", User.is_active.is_(True))
        )
    ).scalar_one()


@router.get("", response_model=list[UserOut])
async def listar(db: AsyncSession = Depends(get_db)):
    return list(
        (await db.execute(select(User).order_by(User.username))).scalars().all()
    )


@router.post("", response_model=UserOut, status_code=201)
async def criar(body: UserCreate, db: AsyncSession = Depends(get_db)):
    existe = (
        await db.execute(select(User).where(User.username == body.username))
    ).scalar_one_or_none()
    # 409 e nao 422: o dado esta bem formado, o conflito e com o que ja existe.
    if existe is not None:
        raise HTTPException(status_code=409, detail="Ja existe usuario com esse nome")

    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
async def atualizar(
    user_id: int,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    eu: User = Depends(get_current_user),
):
    alvo = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if alvo is None:
        raise HTTPException(status_code=404, detail="Usuario nao encontrado")

    campos = body.model_dump(exclude_unset=True)
    if not campos:
        return alvo

    # Trocar a propria senha e legitimo e continua permitido. O que as duas
    # travas abaixo barram e mudar o proprio poder de acesso.
    if alvo.id == eu.id:
        if "role" in campos and campos["role"] != alvo.role:
            raise HTTPException(
                status_code=422,
                detail="Voce nao pode mudar o proprio papel. Peca a outro administrador",
            )
        if campos.get("is_active") is False:
            raise HTTPException(
                status_code=422, detail="Voce nao pode desligar a propria conta"
            )

    # Vale para qualquer alvo, inclusive outra pessoa: se este e o ultimo
    # admin de pe, rebaixar ou desligar deixa o Veryon sem administrador.
    perdendo_admin = (
        alvo.role == "admin"
        and alvo.is_active
        and (campos.get("role") == "analyst" or campos.get("is_active") is False)
    )
    if perdendo_admin and await _admins_ativos(db) <= 1:
        raise HTTPException(
            status_code=422,
            detail="Este e o ultimo administrador ativo. Promova outro antes",
        )

    if "password" in campos and campos["password"]:
        alvo.password_hash = hash_password(campos.pop("password"))
    campos.pop("password", None)

    for campo, valor in campos.items():
        setattr(alvo, campo, valor)

    await db.commit()
    await db.refresh(alvo)
    return alvo
