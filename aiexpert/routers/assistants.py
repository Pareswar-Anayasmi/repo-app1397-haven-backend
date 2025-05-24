from fastapi import APIRouter, Depends, Query, Header
import logging

from aiexpert.diam.group_utils import GroupChecker
from aiexpert.utils.configurations import SYSTEM_GROUP_ID
from ..auth.base import get_authenticated_user, User
from pydantic import BaseModel
from typing import Optional

from ..assistants.base import(get_assistants as get_assistants_by_group,
                              generate_assistant_code,
                              search_assistants_by_filter,
                              get_user_groups,
                              register_new_assistant,
                              get_owner)

log = logging.getLogger(__name__)

router = APIRouter(
    prefix=f"/{__name__.replace(__package__ + '.', '')}", tags=["AI Assistants"], dependencies=[Depends(GroupChecker(allowed_groups=[SYSTEM_GROUP_ID]))]
)

class RegisterAssistantRequest(BaseModel):
    assistant_name: str
    assistant_owner: str
    description: str
    endpoint: str


@router.get("/owner")
async def get_assistant_owner(
    assistant_code: Optional[str] = Header(None),
    user: User = Depends(get_authenticated_user)):
    """
    Get assistant owner which is the owner of the user group
    """
   
    return await get_owner(assistant_code, user)


@router.get("")
async def get_assistants(
    page: int = Query(1, ge=1, description="Page number to fetch"),
    per_page: int = Query(10, ge=10, description="Number of records per page"),
    user: User = Depends(get_authenticated_user),
):
    """
    Get all assistants with pagination
    """
    user_groups = await get_user_groups(user)
    log.debug(f"Getting assistants for groups: {user_groups}")
    return await get_assistants_by_group(user_groups, page, per_page)


@router.post("/code")
async def generate_code():
    return {
        "code": await generate_assistant_code()
    }


@router.get("/search")
async def search_assistants(
    filter: str = Query(None, alias="$filter", description="assistant_name"),
    user: User = Depends(get_authenticated_user),
):
    """
    Supports filtering by name using contains operator.
    :param user: Authenticated user object
    :return: JSON response containing the filtered list of assistants
    """
    user_groups = await get_user_groups(user)
    return await search_assistants_by_filter(user_groups, filter)

@router.post("/register")
async def register_assistant(
    assistant_details: RegisterAssistantRequest,
    user: User = Depends(get_authenticated_user)
):
    """
    API endpoint to register an assistant
    """
    
    return await register_new_assistant(assistant_details, user)
