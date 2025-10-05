from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .. import models, schemas, auth
from ..db import get_db

router = APIRouter(tags=["auth"], prefix="/auth")

@router.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(payload: schemas.Signup, db: Session = Depends(get_db)):
    # 중복 확인
    existing = db.query(models.User).filter(models.User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="username already exists")

    user = models.User(
        username=payload.username,
        hashed_password=auth.hash_password(payload.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"msg": "user created", "username": user.username}

@router.post("/login")
def login(payload: schemas.Login, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    if not auth.verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    # 1주차는 토큰 대신 간단 응답. 이후 JWT 발급으로 확장 예정.
    return {"msg": "login success", "username": user.username}

