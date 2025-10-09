from fastapi import APIRouter, Depends
from .. import models, schemas
from ..dependencies import get_current_user

router = APIRouter(tags=["users"], prefix="/users")

@router.get("/me", response_model=schemas.User)
def read_current_user(current_user: models.User = Depends(get_current_user)):
    """
    보호된 엔드포인트.
    유효한 Access Token을 제공해야만 현재 로그인된 사용자 정보를 반환합니다.
    """
    return current_user
