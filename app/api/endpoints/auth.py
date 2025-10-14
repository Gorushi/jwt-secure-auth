from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from app.db.session import get_db
from app import schemas, crud, security
from app.models import user as user_model
from app.core.config import settings

router = APIRouter()

# ... /signup 엔드포인트는 동일 ...

@router.post("/login", response_model=schemas.token.Token)
def login_for_access_token(response: Response, db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    user = crud.crud_user.authenticate_user(db, username=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = security.create_access_token(data={"sub": user.username})
    refresh_token = security.create_refresh_token(data={"sub": user.username})
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/refresh", response_model=schemas.token.Token)
def refresh_access_token(response: Response, db: Session = Depends(get_db), refresh_token: schemas.token.RefreshToken = Depends()):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Refresh Token 검증
        if settings.TOKEN_ALGORITHM == "RS256":
            payload = jwt.decode(refresh_token.refresh_token, security.PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        else:
            payload = jwt.decode(refresh_token.refresh_token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        token_type: str = payload.get("typ")

        if username is None or jti is None or token_type != "refresh":
            raise credentials_exception

        # 사용된 Refresh Token을 Blacklist에 추가 (Token Rotation)
        if crud.crud_token.is_jti_in_blacklist(db, jti=jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked"
            )
        crud.crud_token.add_jti_to_blacklist(db, jti=jti)

        user = crud.crud_user.get_user_by_username(db, username=username)
        if user is None:
            raise credentials_exception

        # 새로운 토큰 쌍 발급
        new_access_token = security.create_access_token(data={"sub": user.username})
        new_refresh_token = security.create_refresh_token(data={"sub": user.username})
        
        response.set_cookie(key="refresh_token", value=new_refresh_token, httponly=True, samesite="strict")

        return {"access_token": new_access_token, "token_type": "bearer"}
    except JWTError:
        raise credentials_exception

@router.post("/logout")
def logout(
    response: Response,
    db: Session = Depends(get_db),
    access_token: str = Depends(security.oauth2_scheme),
    refresh_token: schemas.token.RefreshToken = Depends()
):
    # Access Token과 Refresh Token 모두 Blacklist 처리
    try:
        # Access Token의 JTI를 Blacklist에 추가
        if settings.TOKEN_ALGORITHM == "RS256":
            access_payload = jwt.decode(access_token, security.PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        else:
            access_payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])
        access_jti = access_payload.get("jti")
        if access_jti:
            crud.crud_token.add_jti_to_blacklist(db, jti=access_jti)

        # Refresh Token의 JTI를 Blacklist에 추가
        if refresh_token and refresh_token.refresh_token:
            if settings.TOKEN_ALGORITHM == "RS256":
                refresh_payload = jwt.decode(refresh_token.refresh_token, security.PUBLIC_KEY, algorithms=[settings.TOKEN_ALGORITHM])
            else:
                refresh_payload = jwt.decode(refresh_token.refresh_token, settings.SECRET_KEY, algorithms=[settings.TOKEN_ALGORITHM])
            refresh_jti = refresh_payload.get("jti")
            if refresh_jti:
                crud.crud_token.add_jti_to_blacklist(db, jti=refresh_jti)

    except JWTError:
        # 토큰이 유효하지 않더라도 로그아웃은 성공 처리
        pass
    
    response.delete_cookie(key="refresh_token")
    return {"message": "Successfully logged out"}

@router.get("/protected", response_model=schemas.user.User)
def read_protected_route(current_user: user_model.User = Depends(security.get_current_user)):
    return current_user
