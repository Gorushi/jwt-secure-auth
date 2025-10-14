import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # DB 설정
    SQLALCHEMY_DATABASE_URL: str = os.getenv("SQLALCHEMY_DATABASE_URL", "sqlite:///./test.db")

    # JWT 설정
    SECRET_KEY: str = os.getenv("SECRET_KEY", "default_secret_key")
    
    # 알고리즘 및 키 경로 추가
    TOKEN_ALGORITHM: str = os.getenv("TOKEN_ALGORITHM", "HS256")
    PRIVATE_KEY_PATH: str = os.getenv("PRIVATE_KEY_PATH", "./keys/private_key.pem")
    PUBLIC_KEY_PATH: str = os.getenv("PUBLIC_KEY_PATH", "./keys/public_key.pem")
    
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

    class Config:
        case_sensitive = True

settings = Settings()
