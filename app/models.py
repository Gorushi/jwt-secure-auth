from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.sql import func
from .db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    # --- MFA 관련 필드 ---
    # OTP를 해시해서 저장 (보안)
    mfa_otp_secret = Column(String, nullable=True)
    # OTP 만료 시간
    mfa_otp_expires_at = Column(DateTime, nullable=True)

# RefreshToken 모델을 제거하고, JTI 기반의 TokenBlacklist 모델을 추가.
# JTI(JWT ID)를 저장하여 특정 토큰을 무효화하는 데 사용됨
class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
