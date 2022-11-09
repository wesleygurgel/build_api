from pytz import timezone
from typing import Optional, List
from datetime import datetime, timedelta
from pydantic import EmailStr

from fastapi.security import OAuth2PasswordBearer
from jose import jwt

from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.configs import settings
from core.security import verify_password

from models.usuario_model import UsuarioModel


# CRIAÇÃO DE UM ENDPOINT PARA O NOSSO OAUTH2
oauth2_schema = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/usuarios/login"
)


# ONDE FAREMOS AUTENTICACAO DO USUARIO
async def authenticate(email: EmailStr, password: str, db: AsyncSession) -> Optional[UsuarioModel]:
    async with db as session:
        query = select(UsuarioModel).filter(UsuarioModel.email == email)
        result = await session.execute(query)
        user: UsuarioModel = result.scalars().unique().one_or_none()

        if not user:
            return None

        if not verify_password(password=password, hash_password=user.senha):
            return None

        return user


async def _create_token(token_type: str, life_time: timedelta, subject: str) -> str:
    # https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3 - Especificações
    payload = {}

    sp = timezone('America/Sao_Paulo')
    expire = datetime.now(tz=sp) + life_time

    payload["type"] = token_type
    payload["exp"] = expire
    payload["iat"] = datetime.now(tz=sp)  # GERADO EM
    payload["sub"] = str(subject)

    return jwt.encode(claims=payload, key=settings.JWT_SECRET, algorithm=settings.ALGORITHM)


async def _create_token_access(subject: str) -> str:
    """
    https://jwt.io
    """
    return _create_token(
        token_type='access_token',
        life_time=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        subject=subject
    )
