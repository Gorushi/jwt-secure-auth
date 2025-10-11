from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Annotated

from .. import schemas, models, auth, dependencies

# 라우터에 직접 prefix와 tags를 설정
router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

@router.post("/signup", response_model=schemas.User, status_code=status.HTTP_201_CREATED)
def signup(user: schemas.UserCreate, db: Session = Depends(dependencies.get_db)):
    """
    **[추가된 기능]** 새로운 사용자를 생성
    - 이메일(username) 중복을 확인
    - 비밀번호를 안전하게 해싱하여 저장
    """
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    hashed_password = auth.get_password_hash(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed_password)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user


@router.post("/login", response_model=schemas.Token)
def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(dependencies.get_db)
):
    """
    사용자 로그인 후 Access Token과 Refresh Token을 발급
    - Refresh Token은 DB에 저장하여 관리
    """
    # form_data.username이 실제 이메일 주소
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth.create_access_token(data={"sub": user.email})
    refresh_token = auth.create_refresh_token(data={"sub": user.email})

    # 기존 리프레시 토큰이 있으면 업데이트, 없으면 새로 생성
    db_token = db.query(models.RefreshToken).filter(models.RefreshToken.user_id == user.id).first()
    if db_token:
        db_token.token = refresh_token
    else:
        db_token = models.RefreshToken(user_id=user.id, token=refresh_token)
        db.add(db_token)
    db.commit()

    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer"
    }


@router.post("/refresh", response_model=schemas.AccessToken)
def refresh_access_token(
    new_access_token: str = Depends(dependencies.get_new_access_token_from_refresh_token)
):
    """
    유효한 Refresh Token을 사용하여 새로운 Access Token을 발급받음
    """
    return {"access_token": new_access_token, "token_type": "bearer"}


@router.post("/logout")
def logout(
    db: Session = Depends(dependencies.get_db),
    # `get_current_user...` 의존성은 토큰 유효성 검사 역할도 수행
    current_user: models.User = Depends(dependencies.get_current_user_from_refresh_token)
):
    """
    로그아웃 처리. DB에 저장된 사용자의 Refresh Token을 삭제
    """
    db_token = db.query(models.RefreshToken).filter(models.RefreshToken.user_id == current_user.id).first()
    if db_token:
        db.delete(db_token)
        db.commit()
    return {"msg": "Successfully logged out"}
