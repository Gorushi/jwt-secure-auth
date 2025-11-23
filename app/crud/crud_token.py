from sqlalchemy.orm import Session
from app.models import TokenBlacklist

def add_jti_to_blacklist(db: Session, jti: str):
    """
    JTI(JWT ID)를 블랙리스트에 추가하여 토큰을 무효화
    """
    db_token = TokenBlacklist(jti=jti)
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return db_token

def is_jti_in_blacklist(db: Session, jti: str) -> bool:
    """
    해당 JTI가 블랙리스트에 있는지 확인
    """
    return db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first() is not None
