from pydantic import BaseModel, EmailStr
from typing import Optional

# --- User Schemas ---
class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

    class Config:
        from_attributes = True

# --- Token Schemas ---
class TokenData(BaseModel):
    # JWT 표준에 맞춰 'email' 대신 'sub'(subject)를 사용
    sub: Optional[str] = None

class AccessToken(BaseModel):
    access_token: str
    token_type: str = "bearer"

class Token(AccessToken):
    # Refresh Token은 HttpOnly 쿠키로 전달되므로 응답 본문에서 제거
    pass

# 로그아웃 등 간단한 메시지 응답을 위한 스키마
class Msg(BaseModel):
    msg: str

# --- MFA Schemas ---
class MFARequired(BaseModel):
    """1단계 로그인 성공 시 (MFA 필요) 응답"""
    message: str = "MFA authentication required"
    mfa_token: str

class MFAVerify(BaseModel):
    """2단계 MFA 인증 요청"""
    mfa_token: str
    otp: str
