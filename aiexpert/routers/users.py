from fastapi import APIRouter, Depends
import logging

from aiexpert.diam.group_utils import GroupChecker
from aiexpert.utils.configurations import SYSTEM_GROUP_ID
from ..auth.base import get_authenticated_user, User

from ..user.base import get_user_details

log = logging.getLogger(__name__)

router = APIRouter(
    prefix=f"/{__name__.replace(__package__ + '.', '')}", tags=["User Profile"], dependencies=[Depends(GroupChecker(allowed_groups=[SYSTEM_GROUP_ID]))]
)


@router.get("")
async def user(user: User = Depends(get_authenticated_user)):
    """
    Get user profile
    """
    return await get_user_details(user)

