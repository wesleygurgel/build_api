from typing import List
from pydantic import BaseSettings
from sqlalchemy.ext.declarative import declarative_base


class Settings(BaseSettings):
    API_V1_STR: str = '/api/v1'
    DB_URL: str = 'postgresql+asyncpg://postgres:root@localhost:5432/resale_test'
    DBBaseModel = declarative_base()

    JWT_SECRET: str = 'HbEWvY-kYZzdZQqN1cbLVZ_e28ebHC-VMPguNbI-50I'
    """
    import secrets

    token: str = secrets.token_urlsafe(32)
    """
    ALGORITHM: str = 'HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7 # 1 SEMANA

    class Config:
        case_sensitive = True


settings: Settings = Settings()