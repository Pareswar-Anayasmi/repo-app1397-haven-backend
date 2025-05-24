import httpx

from ..diam.service_account import get_token

from ..utils.configurations import DIAM_API_ENDPOINT_BASE_URL

from ..auth.base import get_authenticated_user, User

from typing import List

from fastapi import HTTPException, Depends

import logging

log = logging.getLogger(__name__)

def get_assistant_groups(group_names):
    # Split each group into the following format: "system_group:assistant_group:role"
    # and return the assistant groups

    assistant_groups = []
    for group in group_names:
        group_parts = group.split(":")
        if len(group_parts) > 1 and group_parts[1] not in assistant_groups:
            assistant_groups.append(group_parts[1])

    return assistant_groups


async def get_groups():
    """
    Since DIAM provides the Organization group UUID in JWT token, we need to map the UUID to the group name.
    """
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {await get_token()}",
    }
                
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{DIAM_API_ENDPOINT_BASE_URL}/groups", headers=headers)
        response.raise_for_status()
        groups = response.json()

    log.debug("Get groups from DIAM: %s", groups)
    
    return {
        "records": [
            {
                "id": group["id"],
                "name": group["attributes"]["name"],
                "type": group["attributes"]["group_type"],
            }
            for group in groups["data"]
        ]
    }
    
class GroupChecker():
    def __init__(self, allowed_groups: List[str] = [], blocked_groups: List[str] = []):  
        self.allowed_groups = allowed_groups 
        self.blocked_groups = blocked_groups

    def __call__(self, user: User = Depends(get_authenticated_user)):
        
        log.debug("Allowed groups: %s, blocked groups: %s, user groups: %s", self.allowed_groups, self.blocked_groups, (user.groups if user else None))
        
        if (not user or not user.groups) or (
            self.blocked_groups and any(group in user.groups for group in self.blocked_groups)
        ):
            raise HTTPException(status_code=403, detail="unauthorized")
            
        if not self.allowed_groups or any(group in user.groups for group in self.allowed_groups):
            return user

        raise HTTPException(status_code=403, detail="unauthorized")
    
async def add_user_to_group(diam_user_id: str, group_id: str):
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {await get_token()}",
    }
                
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{DIAM_API_ENDPOINT_BASE_URL}/users/{diam_user_id}/groups/{group_id}", headers=headers)
        
        log.debug("Response from DIAM: %s:", response.text)
        
        response.raise_for_status()
        return response.json()
    
async def delete_user_from_group(diam_user_id: str, group_id: str):
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {await get_token()}",
    }
    
    log.debug("Deleting user %s from group %s", diam_user_id, group_id)
                
    async with httpx.AsyncClient() as client:
        response = await client.delete(f"{DIAM_API_ENDPOINT_BASE_URL}/users/{diam_user_id}/groups/{group_id}", headers=headers)
        
        log.debug("Response from DIAM: %s:", response.text)
        
        response.raise_for_status()
        return response.json()


async def create_organization_group(org_group_name: str):
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {await get_token()}",
    }

    request_body={
        "data": {
            "type": "groups",
            "attributes": {
                "name": org_group_name,
                "group_type": "ORGANIZATION",
            },
        }
    }
                
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{DIAM_API_ENDPOINT_BASE_URL}/groups",
                                     headers=headers,
                                     json=request_body)
        
        log.debug("Response from DIAM: %s:", response.text)
        
        response.raise_for_status()
        return response.json()