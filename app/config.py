import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# .env 파일에서 환경 변수를 로드.
load_dotenv()

class Settings(BaseSettings):
    """애플리케이션의 모든 설정을 관리하는 클래스"""

    # --- 데이터베이스 설정 ---
    SQLALCHEMY_DATABASE_URL: str = os.getenv("SQLALCHEMY_DATABASE_URL", "sqlite:///./test.db")

    # --- JWT 인증 설정 ---
    # HS256 알고리즘을 위한 비밀키 (터미널에서 'openssl rand -hex 32'로 생성 권장)
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your_default_secret_key")

    # 사용할 토큰 서명 알고리즘 (HS256 또는 RS256)
    TOKEN_ALGORITHM: str = os.getenv("TOKEN_ALGORITHM", "HS256")

    # RS256 키 파일 경로
    PRIVATE_KEY_PATH: str = os.getenv("PRIVATE_KEY_PATH", "./private_key.pem")
    PUBLIC_KEY_PATH: str = os.getenv("PUBLIC_KEY_PATH", "./public_key.pem")

    # 토큰 만료 시간 설정
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

    class Config:
        # 환경 변수 이름의 대소문자를 구분하도록 설정
        case_sensitive = True

# 설정 객체를 생성하여 다른 파일에서 임포트하여 사용할 수 있도록 함
settings = Settings()
