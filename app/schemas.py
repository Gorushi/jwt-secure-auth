from pydantic import BaseModel
from typing import Optional

class Signup(BaseModel):
    username: str
    password: str

# 토큰 응답 모델
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

# 토큰 페이로드(내용) 모델
class TokenData(BaseModel):
    username: Optional[str] = None

# 사용자 정보 응답 모델
class User(BaseModel):
    id: int
    username: str
    is_active: bool

    class Config:
        from_attributes = True
