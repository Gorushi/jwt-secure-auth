from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import uuid

from app.core.config import settings
from app.db.session import get_db
from app.crud import crud_user, crud_token
from app.schemas.token import TokenData

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

def _create_token(data: dict, expires_delta: timedelta, token_type: str):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()), # JTI 클레임 추가
        "typ": token_type # 토큰 타입 명시 (access/refresh)
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

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if settings.TOKEN_ALGORITHM == "RS256":
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        else: # HS256
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])

        username: str = payload.get("sub")
        jti: str = payload.get("jti") # JTI 추출
        token_type: str = payload.get("typ")

        if username is None or jti is None or token_type != "access":
            raise credentials_exception
        
        # Blacklist 검증
        if crud_token.is_jti_in_blacklist(db, jti=jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )

        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
        
    user = crud_user.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user
