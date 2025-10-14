from sqlalchemy.orm import Session
from app.models.token import RefreshToken, TokenBlacklist
from datetime import datetime, timedelta

# ... 기존 RefreshToken 관련 CRUD 함수들 ...
def create_refresh_token(db: Session, user_id: int, token: str, expires_delta: timedelta):
    expires_at = datetime.utcnow() + expires_delta
    db_refresh_token = RefreshToken(
        user_id=user_id,
        token=token,
        expires_at=expires_at
    )
    db.add(db_refresh_token)
    db.commit()
    db.refresh(db_refresh_token)
    return db_refresh_token

def get_refresh_token(db: Session, token: str):
    return db.query(RefreshToken).filter(RefreshToken.token == token).first()

def revoke_refresh_token(db: Session, token: str):
    db_token = get_refresh_token(db, token)
    if db_token:
        db_token.is_revoked = True
        db.commit()
    return db_token

#  Blacklist 관련 CRUD 함수 추가
def add_jti_to_blacklist(db: Session, jti: str):
    """
    토큰의 JTI를 블랙리스트에 추가.
    """
    db_jti = TokenBlacklist(jti=jti)
    db.add(db_jti)
    db.commit()
    db.refresh(db_jti)
    return db_jti

def is_jti_in_blacklist(db: Session, jti: str) -> bool:
    """
    JTI가 블랙리스트에 있는지 확인.
    """
    return db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first() is not None
