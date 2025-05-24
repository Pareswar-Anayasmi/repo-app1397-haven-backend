from fastapi import APIRouter, Depends, HTTPException
import logging

from pydantic import BaseModel

from ..utils.configurations import IT_ADMIN_GROUP_NAME

from ..auth.base import get_authenticated_user, User
from ..groups.base import (
    get_assistant_group_details,
    get_user_groups,
    get_user_group_details,
    assign_user_to_user_group,
    delete_user_from_user_group,
    update_user_role_in_user_group,
    update_user_group)

from ..diam.group_utils import get_assistant_groups

log = logging.getLogger(__name__)

router = APIRouter(
    prefix=f"/{__name__.replace(__package__ + '.', '')}", tags=["Groups Related APIs"]
)

class AssignUserToGroupRequest(BaseModel):
    assistant_group_name: str
    email: str
    role_name: str

class DeleteUserFromGroupRequest(BaseModel):
    assistant_group_name: str
    email: str

class UpdateGroupRequest(BaseModel):
    group_title: str
    group_description: str

@router.get("")
async def get_all_groups(user: User = Depends(get_authenticated_user)):
    """
    API endpoint to list all groups that user has access to.
    """
    
    return await get_user_groups(user)



@router.get("/it_admin_group")
async def get_it_admin_group(user: User = Depends(get_authenticated_user)):
    return await get_assistant_group_details(get_assistant_groups([IT_ADMIN_GROUP_NAME])[0])


@router.get("/{assistant_group_name}")
async def get_group_details(
    assistant_group_name: str,
    user: User = Depends(get_authenticated_user)
):
    """
    API endpoint to get details of a group
    """
    
    return await get_user_group_details(assistant_group_name, user)

@router.post("/users")
async def assign_user_to_group(
    group_user_details: AssignUserToGroupRequest,
    user: User = Depends(get_authenticated_user)
):
    """
    API endpoint to assign a user to a group
    """
    
    return await assign_user_to_user_group(group_user_details, user)

@router.delete("/users")
async def delete_user_from_group(
    group_user_details: DeleteUserFromGroupRequest,
    user: User = Depends(get_authenticated_user)
):
    """
    API endpoint to delete a user from a group
    """
    
    if not await delete_user_from_user_group(group_user_details, user):
        raise HTTPException(404, "Cannot find user to delete.")

@router.post("/users/role/")
async def update_user_role_in_group(
    group_user_details: AssignUserToGroupRequest,
    user: User = Depends(get_authenticated_user)
):
    """
    API endpoint to assign a user to a group
    """
    
    return await update_user_role_in_user_group(group_user_details, user)

@router.post("/{assistant_group_name}")
async def update_group(
    assistant_group_name: str,
    group_details: UpdateGroupRequest,
    user: User = Depends(get_authenticated_user)
):
    """
    API endpoint to update a user group
    """
    
    return await update_user_group(assistant_group_name, group_details, user)
