import os
import uuid
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from . import models
from .config import settings

# --- 비밀번호 해싱 ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- RS256 키 로딩 ---
PRIVATE_KEY = None
PUBLIC_KEY = None

if settings.TOKEN_ALGORITHM == "RS256":
    try:
        with open(settings.PRIVATE_KEY_PATH, "r") as f:
            PRIVATE_KEY = f.read()
        with open(settings.PUBLIC_KEY_PATH, "r") as f:
            PUBLIC_KEY = f.read()
    except FileNotFoundError:
        raise RuntimeError("RS256 algorithm is set, but key files are not found.")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# JTI(JWT ID) 클레임을 추가하여 각 토큰에 고유 식별자를 부여.
# 설정에 따라 HS256 또는 RS256 알고리즘을 동적으로 사용하여 토큰을 생성.
def _create_token(data: dict, expires_delta: timedelta) -> str:
    """JWT 토큰을 생성하는 내부 함수"""
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()) # JTI 추가
    })
    
    if settings.TOKEN_ALGORITHM == "RS256":
        encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=settings.TOKEN_ALGORITHM)
    else: # HS256
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.TOKEN_ALGORITHM)
        
    return encoded_jwt

def create_access_token(data: dict) -> str:
    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return _create_token(data, expires_delta)

def create_refresh_token(data: dict) -> str:
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return _create_token(data, expires_delta)

def authenticate_user(db: Session, email: str, password: str) -> Optional[models.User]:
    """이메일과 비밀번호로 사용자를 인증."""
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user
