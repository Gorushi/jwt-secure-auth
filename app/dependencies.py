from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from . import models, auth, schemas
from .db import SessionLocal
from .config import settings 

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# JTI가 블랙리스트에 있는지 확인하는 함수
def is_jti_blacklisted(jti: str, db: Session) -> bool:
    """JTI가 블랙리스트에 등록되었는지 확인."""
    return db.query(models.TokenBlacklist).filter(models.TokenBlacklist.jti == jti).first() is not None

def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> models.User:
    """
    Access Token을 검증하고 현재 사용자를 반환하는 의존성.
    - 토큰 디코딩 및 유효성 검사
    - JTI 블랙리스트 확인
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if settings.TOKEN_ALGORITHM == "RS256":
            payload = jwt.decode(token, auth.PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        else:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        
        email: str = payload.get("sub")
        jti: str = payload.get("jti") # JTI 추출

        if email is None or jti is None:
            raise credentials_exception
        
        # 블랙리스트 확인 로직 추가
        if is_jti_blacklisted(jti, db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Token has been revoked"
            )

    except JWTError:
        raise credentials_exception
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# 쿠키에서 Refresh Token을 가져오는 의존성
def get_refresh_token_from_cookie(request: Request) -> str:
    """요청 쿠키에서 refresh_token을 추출."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found in cookies"
        )
    return refresh_token
