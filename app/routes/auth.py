from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta

from .. import schemas, models, auth, dependencies

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

@router.post("/token", response_model=schemas.Token)
def login_for_access_token(
    db: Session = Depends(dependencies.get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = auth.create_refresh_token(
        data={"sub": user.email}, expires_delta=timedelta(days=auth.REFRESH_TOKEN_EXPIRE_DAYS)
    )

    db_token = db.query(models.RefreshToken).filter(models.RefreshToken.user_id == user.id).first()
    if db_token:
        db_token.token = refresh_token
    else:
        db_token = models.RefreshToken(user_id=user.id, token=refresh_token)
        db.add(db_token)
    db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@router.post(
    "/token/refresh", 
    response_model=schemas.Token,
    dependencies=[Depends(dependencies.get_current_user_from_refresh_token)]
)
def refresh_access_token(
    current_user: models.User = Depends(dependencies.get_current_user_from_refresh_token),
):
    new_access_token = auth.create_access_token(
        data={"sub": current_user.email},
        expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": new_access_token, "token_type": "bearer"}

@router.post(
    "/logout",
    dependencies=[Depends(dependencies.get_current_user_from_refresh_token)]
)
def logout(
    db: Session = Depends(dependencies.get_db),
    current_user: models.User = Depends(dependencies.get_current_user_from_refresh_token)
):
    db_token = db.query(models.RefreshToken).filter(models.RefreshToken.user_id == current_user.id).first()
    if db_token:
        db.delete(db_token)
        db.commit()
    return {"msg": "Successfully logged out"}
