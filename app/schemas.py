from pydantic import BaseModel, EmailStr
from typing import Optional

# --- User Schemas ---

class UserBase(BaseModel):
    """사용자 정보의 기본이 되는 스키마"""
    email: EmailStr

class UserCreate(UserBase):
    """사용자 생성을 위한 스키마 (비밀번호 포함)"""
    password: str

class User(UserBase):
    """DB에서 조회한 사용자 정보를 반환하기 위한 스키마"""
    id: int
    is_active: bool = True

    class Config:
        # SQLAlchemy 모델과 Pydantic 모델을 매핑하기 위한 설정
        from_attributes = True

# --- Token Schemas ---

class TokenData(BaseModel):
    """JWT 토큰의 payload에 담기는 데이터를 위한 스키마"""
    email: Optional[str] = None

class AccessToken(BaseModel):
    """Access Token 재발급 시 사용되는 응답 스키마"""
    access_token: str
    token_type: str = "bearer"

class Token(AccessToken):
    """로그인 시 발급되는 전체 토큰(Access + Refresh)을 위한 스키마"""
    refresh_token: str
