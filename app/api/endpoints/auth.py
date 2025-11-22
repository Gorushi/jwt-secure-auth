from fastapi import APIRouter, Depends, HTTPException, status, Response, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional
import uuid

from app.dependencies import get_db
from app.config import settings
from app import schemas, auth, models, security
from app.crud import crud_token

router = APIRouter()

# --- 1. 회원가입 ---
@router.post("/signup", response_model=schemas.User, status_code=status.HTTP_201_CREATED)
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
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

# --- 2. 로그인 (MFA 1단계) ---
@router.post("/login", response_model=schemas.MFARequired)
def login_for_access_token(
    response: Response, 
    db: Session = Depends(get_db), 
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    MFA 1단계: 아이디/비번 확인 -> OTP 생성 -> 콘솔 출력 -> MFA 토큰 반환
    """
    user = auth.authenticate_user(db, email=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # OTP 생성
    if hasattr(security, 'create_otp'):
        otp = security.create_otp()
    else:
        import random, string
        otp = "".join(random.choices(string.digits, k=6))
    
    # DB에 OTP 저장 (해싱)
    user.mfa_otp_secret = auth.get_password_hash(otp)
    user.mfa_otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.commit()

    # [Dev Mode] 콘솔에 OTP 출력
    print(f"\n====== [DEV-MODE] OTP for user '{user.email}': {otp} ======\n")

    # MFA 토큰 생성
    # security 모듈 사용, 키 선택 로직 포함
    if hasattr(security, 'create_mfa_token'):
        mfa_token = security.create_mfa_token(data={"sub": user.email})
    else:
        # Fallback
        expires_delta = timedelta(minutes=5)
        to_encode = {
            "sub": user.email, 
            "type": "mfa", 
            "exp": datetime.utcnow() + expires_delta, 
            "iat": datetime.utcnow(),
            "jti": str(uuid.uuid4())
        }
        
        # RS256일 경우 Private Key 사용
        if settings.TOKEN_ALGORITHM == "RS256":
            if hasattr(security, 'PRIVATE_KEY') and security.PRIVATE_KEY:
                encode_key = security.PRIVATE_KEY
            elif hasattr(auth, 'PRIVATE_KEY') and auth.PRIVATE_KEY:
                encode_key = auth.PRIVATE_KEY
            else:
                # 키가 로드되지 않았을 경우 대비
                raise HTTPException(status_code=500, detail="Server Error: Private Key not loaded")
        else:
            encode_key = settings.SECRET_KEY
            
        mfa_token = jwt.encode(to_encode, encode_key, algorithm=settings.TOKEN_ALGORITHM)
    
    return {"message": "MFA authentication required", "mfa_token": mfa_token}

# --- 3. MFA 인증 (MFA 2단계) ---
@router.post("/mfa/verify", response_model=schemas.Token)
def verify_mfa_and_issue_token(
    response: Response,
    mfa_data: schemas.MFAVerify,
    db: Session = Depends(get_db)
):
    # MFA 토큰 검증
    try:
        # 검증 키 선택
        verify_key = settings.SECRET_KEY
        if settings.TOKEN_ALGORITHM == "RS256":
             if hasattr(security, 'PUBLIC_KEY') and security.PUBLIC_KEY:
                verify_key = security.PUBLIC_KEY
             elif hasattr(auth, 'PUBLIC_KEY') and auth.PUBLIC_KEY:
                verify_key = auth.PUBLIC_KEY
        
        payload = jwt.decode(mfa_data.mfa_token, verify_key, algorithms=[settings.TOKEN_ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type") or payload.get("typ")
        
        if username is None or token_type != "mfa":
            raise HTTPException(status_code=400, detail="Invalid MFA token type")
            
    except JWTError:
         raise HTTPException(status_code=400, detail="Invalid or expired MFA token")

    user = db.query(models.User).filter(models.User.email == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # OTP 검증
    if not user.mfa_otp_secret or not user.mfa_otp_expires_at:
        raise HTTPException(status_code=400, detail="No OTP requested")
    
    if datetime.utcnow() > user.mfa_otp_expires_at:
        raise HTTPException(status_code=400, detail="OTP expired")
        
    if not auth.verify_password(mfa_data.otp, user.mfa_otp_secret):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # 인증 성공 -> OTP 정보 초기화
    user.mfa_otp_secret = None
    user.mfa_otp_expires_at = None
    db.commit()

    # 최종 Access/Refresh 토큰 발급
    if hasattr(security, 'create_access_token'):
        access_token = security.create_access_token(data={"sub": user.email})
        refresh_token = security.create_refresh_token(data={"sub": user.email})
    else:
        raise HTTPException(status_code=500, detail="Security module error")
    
    # Refresh Token 쿠키 설정
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="strict",
        secure=False,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# --- 4. 토큰 갱신 (Refresh) ---
@router.post("/refresh", response_model=schemas.AccessToken)
def refresh_access_token(
    response: Response, 
    db: Session = Depends(get_db),
    refresh_token_in: schemas.Token = Body(...)
):
    # 토큰 문자열 추출
    token_str = getattr(refresh_token_in, 'access_token', None) or getattr(refresh_token_in, 'refresh_token', None)
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token_str:
        raise credentials_exception

    try:
        # 검증 키 선택
        verify_key = settings.SECRET_KEY
        if settings.TOKEN_ALGORITHM == "RS256":
             if hasattr(security, 'PUBLIC_KEY') and security.PUBLIC_KEY:
                verify_key = security.PUBLIC_KEY
             elif hasattr(auth, 'PUBLIC_KEY') and auth.PUBLIC_KEY:
                verify_key = auth.PUBLIC_KEY
        
        payload = jwt.decode(token_str, verify_key, algorithms=[settings.TOKEN_ALGORITHM])
        
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        token_type: str = payload.get("type") or payload.get("typ")

        if username is None or jti is None or token_type != "refresh":
            raise credentials_exception

        # Token Rotation: 블랙리스트 확인
        if crud_token.is_jti_in_blacklist(db, jti=jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked (Reuse detected)"
            )
        
        # 현재 토큰 블랙리스트 추가
        crud_token.add_jti_to_blacklist(db, jti=jti)

        user = db.query(models.User).filter(models.User.email == username).first()
        if user is None:
            raise credentials_exception

        # 새로운 토큰 쌍 발급
        new_access_token = security.create_access_token(data={"sub": user.email})
        new_refresh_token = security.create_refresh_token(data={"sub": user.email})
        
        response.set_cookie(key="refresh_token", value=new_refresh_token, httponly=True, samesite="strict")

        return {"access_token": new_access_token, "token_type": "bearer"}
        
    except JWTError:
        raise credentials_exception

# --- 5. 로그아웃 ---
@router.post("/logout")
def logout(
    response: Response,
    db: Session = Depends(get_db),
    access_token: str = Depends(security.oauth2_scheme),
    # [수정] 로그아웃도 Body에서 받도록 통일
    refresh_token_in: schemas.Token = Body(...)
):
    try:
        # 검증 키 선택
        verify_key = settings.SECRET_KEY
        if settings.TOKEN_ALGORITHM == "RS256":
             if hasattr(security, 'PUBLIC_KEY') and security.PUBLIC_KEY:
                verify_key = security.PUBLIC_KEY
             elif hasattr(auth, 'PUBLIC_KEY') and auth.PUBLIC_KEY:
                verify_key = auth.PUBLIC_KEY
        
        # 1. Access Token 블랙리스트
        access_payload = jwt.decode(access_token, verify_key, algorithms=[settings.TOKEN_ALGORITHM])
        access_jti = access_payload.get("jti")
        if access_jti:
            crud_token.add_jti_to_blacklist(db, jti=access_jti)

        # 2. Refresh Token 블랙리스트
        refresh_token_str = getattr(refresh_token_in, 'access_token', None) or getattr(refresh_token_in, 'refresh_token', None)
        if refresh_token_str:
            refresh_payload = jwt.decode(refresh_token_str, verify_key, algorithms=[settings.TOKEN_ALGORITHM])
            refresh_jti = refresh_payload.get("jti")
            if refresh_jti:
                crud_token.add_jti_to_blacklist(db, jti=refresh_jti)

    except JWTError:
        pass
    
    response.delete_cookie(key="refresh_token")
    return {"message": "Successfully logged out"}

@router.get("/protected", response_model=schemas.User)
def read_protected_route(current_user: models.User = Depends(security.get_current_user)):
    return current_user
