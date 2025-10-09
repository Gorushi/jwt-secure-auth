from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from .. import models, schemas, auth
from ..db import get_db

router = APIRouter(tags=["auth"], prefix="/auth")

@router.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(payload: schemas.Signup, db: Session = Depends(get_db)):
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

@router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """사용자 인증 후 Access/Refresh 토큰을 발급합니다."""
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token_data = {"sub": user.username}
    access_token = auth.create_access_token(data=token_data)
    refresh_token = auth.create_refresh_token(data=token_data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }
