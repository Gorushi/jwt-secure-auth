from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from . import models, schemas, auth
from .db import SessionLocal

# 기존 로그인 흐름을 위한 스키마
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# 수동 토큰 입력을 위한 새로운 스키마
bearer_scheme = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user_from_token(token: str, db: Session):
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

# access_token을 사용하는 함수
def get_current_user_from_access_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    return get_current_user_from_token(token, db)

# refresh_token을 사용하는 함수
def get_current_user_from_refresh_token(
    token: HTTPAuthorizationCredentials = Depends(bearer_scheme), # 1. oauth2_scheme -> bearer_scheme으로 변경
    db: Session = Depends(get_db)
):
    # 2. token -> token.credentials로 변경 (HTTPBearer는 객체로 토큰을 전달)
    user = get_current_user_from_token(token.credentials, db)
    
    # DB에 저장된 Refresh Token과 일치하는지 확인
    stored_token = db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id == user.id,
        models.RefreshToken.token == token.credentials # 3. token -> token.credentials로 변경
    ).first()

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    return user
