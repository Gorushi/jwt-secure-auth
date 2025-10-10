from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from . import models, auth, schemas
from .db import SessionLocal

# --- Security Schemes ---

# 사용자 이름/비밀번호 form으로 로그인을 처리하는 Swagger UI를 위함
# tokenUrl은 실제 로그인(토큰 발급) 경로와 일치해야 함
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Authorization: Bearer <token> 헤더에서 직접 토큰을 추출하기 위함
# (주로 Refresh Token을 전달받을 때 사용)
bearer_scheme = HTTPBearer()


# --- Database Dependency ---

def get_db():
    """
    각 API 요청에 대한 데이터베이스 세션을 생성, 요청 완료 후 세션을 닫음
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Authentication Dependencies ---

def get_current_user_from_token(token: str, db: Session) -> models.User:
    """
    JWT 토큰을 디코딩, 검증하여 해당 사용자를 반환하는 핵심 함수.
    Access Token과 Refresh Token 검증에 모두 재사용됩니다.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


def get_current_user_from_access_token(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> models.User:
    """
    Access Token을 사용하여 현재 로그인된 사용자를 가져오는 의존성.
    일반적으로 보호된 API 엔드포인트에서 사용됨
    """
    return get_current_user_from_token(token, db)


def get_current_user_from_refresh_token(
    token_credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db)
) -> models.User:
    """
    Refresh Token을 사용하여 현재 사용자를 가져오는 의존성.
    - 토큰 유효성 검증과 함께 DB에 저장된 토큰과 일치하는지 확인
    - 주로 로그아웃, 토큰 재발급과 같은 작업에 사용됨
    """
    token = token_credentials.credentials
    user = get_current_user_from_token(token, db)
    
    # DB에 저장된 Refresh Token과 일치하는지 확인
    stored_token = db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id == user.id,
        models.RefreshToken.token == token
    ).first()

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    return user


def get_new_access_token_from_refresh_token(
    current_user: models.User = Depends(get_current_user_from_refresh_token)
) -> str:
    """
    유효한 Refresh Token을 기반으로 새로운 Access Token을 생성하여 반환하는 의존성.
    토큰 재발급 엔드포인트에서 사용됨
    """
    new_access_token = auth.create_access_token(data={"sub": current_user.email})
    return new_access_token
