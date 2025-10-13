from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Annotated
from jose import jwt, JWTError

from .. import schemas, models, auth, dependencies
from ..config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/signup", response_model=schemas.User, status_code=status.HTTP_201_CREATED)
def signup(user: schemas.UserCreate, db: Session = Depends(dependencies.get_db)):
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
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(dependencies.get_db)
):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth.create_access_token(data={"sub": user.email})
    refresh_token = auth.create_refresh_token(data={"sub": user.email})

    # Refresh Token을 HttpOnly 쿠키에 설정하여 보안 강화
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="strict", # CSRF 방어
        secure=False, # TODO: 배포 시 True로 변경 (HTTPS 환경)
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# Token Rotation 구현
@router.post("/refresh", response_model=schemas.AccessToken)
def refresh_access_token(
    response: Response,
    refresh_token: str = Depends(dependencies.get_refresh_token_from_cookie),
    db: Session = Depends(dependencies.get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token"
    )
    try:
        # Refresh Token 검증
        if settings.TOKEN_ALGORITHM == "RS256":
            payload = jwt.decode(refresh_token, auth.PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        else:
            payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        
        email: str = payload.get("sub")
        jti: str = payload.get("jti")
        if email is None or jti is None:
            raise credentials_exception

        # 사용된 Refresh Token을 블랙리스트에 추가
        if dependencies.is_jti_blacklisted(jti, db):
            raise HTTPException(status_code=403, detail="Refresh token has been revoked")
        
        db.add(models.TokenBlacklist(jti=jti))
        db.commit()

        # 새로운 토큰 쌍 발급
        new_access_token = auth.create_access_token(data={"sub": email})
        new_refresh_token = auth.create_refresh_token(data={"sub": email})

        # 새로운 Refresh Token을 쿠키에 설정
        response.set_cookie(
            key="refresh_token", value=new_refresh_token, httponly=True, samesite="strict"
        )
        return {"access_token": new_access_token, "token_type": "bearer"}
    except JWTError:
        raise credentials_exception

# JTI를 블랙리스트에 추가하는 방식으로 로그아웃 구현
@router.post("/logout", response_model=schemas.Msg)
def logout(
    response: Response,
    access_token: str = Depends(dependencies.oauth2_scheme),
    refresh_token: str = Depends(dependencies.get_refresh_token_from_cookie),
    db: Session = Depends(dependencies.get_db)
):
    try:
        # Access Token의 JTI를 블랙리스트에 추가
        if settings.TOKEN_ALGORITHM == "RS256":
            access_payload = jwt.decode(access_token, auth.PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        else:
            access_payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        db.add(models.TokenBlacklist(jti=access_payload.get("jti")))
        
        # Refresh Token의 JTI를 블랙리스트에 추가
        if settings.TOKEN_ALGORITHM == "RS256":
            refresh_payload = jwt.decode(refresh_token, auth.PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        else:
            refresh_payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        db.add(models.TokenBlacklist(jti=refresh_payload.get("jti")))
        
        db.commit()
    except JWTError:
        # 토큰이 유효하지 않더라도 로그아웃은 성공 처리
        pass
    
    response.delete_cookie(key="refresh_token")
    return {"msg": "Successfully logged out"}
