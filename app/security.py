from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import uuid

from app.config import settings
from app.dependencies import get_db
from app import schemas
from app.schemas import TokenData

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# --- RS256 키 로딩 ---
try:
    with open(settings.PRIVATE_KEY_PATH, "r") as f:
        PRIVATE_KEY = f.read()
    with open(settings.PUBLIC_KEY_PATH, "r") as f:
        PUBLIC_KEY = f.read()
except FileNotFoundError:
    if settings.TOKEN_ALGORITHM == "RS256":
        raise RuntimeError("RS256 is configured, but key files are missing.")
    PRIVATE_KEY = None
    PUBLIC_KEY = None

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# --- OTP 유틸 ---
import random
import string
def create_otp(length: int = 6) -> str:
    """간단한 숫자 6자리 OTP 생성"""
    return "".join(random.choices(string.digits, k=length))

def _create_token(data: dict, expires_delta: timedelta, token_type: str):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()), 
        "typ": token_type 
    })
    
    if settings.TOKEN_ALGORITHM == "RS256":
        encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=settings.TOKEN_ALGORITHM)
    else: # HS256
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.TOKEN_ALGORITHM)
        
    return encoded_jwt

def create_access_token(data: dict):
    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return _create_token(data, expires_delta, "access")

def create_refresh_token(data: dict):
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return _create_token(data, expires_delta, "refresh")

# --- MFA 토큰 로직 ---
def create_mfa_token(data: dict):
    """MFA 인증 단계에서 사용할 임시 토큰"""
    expires_delta = timedelta(minutes=5)
    return _create_token(data, expires_delta, "mfa")

def verify_mfa_token_payload(token: str) -> Optional[str]:
    try:
        if settings.TOKEN_ALGORITHM == "RS256":
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        else:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])
            
        username: str = payload.get("sub")
        token_type: str = payload.get("typ") # typ or type
        
        # 토큰 타입이 mfa인지 확인
        if username is None or (token_type != "mfa" and payload.get("typ") != "mfa"):
            return None
        return username
    except JWTError:
        return None

# --- CRUD 순환 참조 방지를 위한 늦은 임포트 및 의존성 주입 ---
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if settings.TOKEN_ALGORITHM == "RS256":
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        else: 
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])

        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        token_type: str = payload.get("typ")

        if username is None or jti is None or token_type != "access":
            raise credentials_exception
        
        # Blacklist 검증을 위해 crud_token 임포트 (순환 참조 방지)
        from app.crud import crud_token
        if crud_token.is_jti_in_blacklist(db, jti=jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )

        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    # User 조회 (순환 참조 방지 위해 여기서 models 사용)
    from app import models
    user = db.query(models.User).filter(models.User.email == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user
