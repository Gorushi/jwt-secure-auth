from fastapi import FastAPI
from . import models
from .db import engine
from .api.endpoints import auth
# from .routes import auth
from .routes import users 

# 애플리케이션 시작 시 DB 테이블 생성
models.Base.metadata.create_all(bind=engine)

# FastAPI 앱 인스턴스 생성
app = FastAPI(
    title="JWT Secure Auth API",
    description="JWT 기반 인증 시스템 보안 강화 및 공격/방어 실습용 API",
    version="1.0.0"
)

# 라우터 포함 (Prefix 설정 추가)
# - 로그인: http://127.0.0.1:8000/api/auth/login
# - MFA인증: http://127.0.0.1:8000/api/auth/mfa/verify
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])

# - 사용자정보: http://127.0.0.1:8000/api/users/me
app.include_router(users.router, prefix="/api/users", tags=["Users"])

# 루트 경로
@app.get("/", tags=["Root"])
def read_root():
    """
    API 서버의 루트 경로입니다. 서버가 정상적으로 실행 중인지 확인합니다.
    """
    return {"message": "Welcome to the JWT Secure Auth API!"}
