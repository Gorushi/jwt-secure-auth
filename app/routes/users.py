from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas, dependencies

router = APIRouter(
    prefix="/users",
    tags=["Users"] 
)

@router.get("/me", response_model=schemas.User)
def read_users_me(current_user: models.User = Depends(dependencies.get_current_user_from_access_token)):
    """
    현재 로그인된 사용자의 정보를 반환
    - 요청 헤더의 Access Token을 검증하여 사용자를 식별
    """
    return current_user
