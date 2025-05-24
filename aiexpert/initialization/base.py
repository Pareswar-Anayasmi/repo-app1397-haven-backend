from ..utils.configurations import SYSTEM_GROUP_ID

from sqlalchemy import select
from ..sql.connection import async_session_maker
from ..sql.schema import Assistants, AssistantPermissions, OrganizationGroups, GroupUsers
from ..diam.group_utils import get_groups, create_organization_group
from ..utils.configurations import ROLE_ADMIN, ROLE_USER, SYSTEM_GROUP_ID, PENDING_USER_STATUS, IT_ADMIN_GROUP_NAME
from ..auth.base import AuthError
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

log = logging.getLogger(__name__)

async def run(request):
    
    async with async_session_maker() as session:
        async with session.begin():
            it_admin_group_result = await session.execute(select(OrganizationGroups).where(OrganizationGroups.group_name == IT_ADMIN_GROUP_NAME))
        
            it_admin_group = it_admin_group_result.scalars().one_or_none()
            
            log.info("IT Admin group: %s", it_admin_group.group_id if it_admin_group else None)
            
            if it_admin_group:
                raise AuthError("IT Admin group has been created. No initialization is allowed.", 403)
            
            
            it_admin_org_group_diam = await create_organization_group(
                org_group_name=IT_ADMIN_GROUP_NAME
            )
            
            log.debug("IT Admin group created in DIAM: %s", it_admin_org_group_diam)
            
            it_admin_org_group_diam_id = it_admin_org_group_diam['data']['id']
            
            assistant_group_name = IT_ADMIN_GROUP_NAME.split(":")[1]
            role_name = IT_ADMIN_GROUP_NAME.split(":")[2]
            
            organization_groups = OrganizationGroups(
                group_id=it_admin_org_group_diam_id,
                group_name=IT_ADMIN_GROUP_NAME,
                group_title="IT Admin",
                group_description="IT Admin",
                assistant_group_name=assistant_group_name,
                role_name=role_name,
                created_by=request.owner_email,
                updated_by=request.owner_email
            )
            
            session.add(organization_groups)
            
            await session.flush()

            # Create Group Users in DB
            first_it_admin = GroupUsers(
                group_id=it_admin_org_group_diam_id,
                email=request.owner_email,
                status=PENDING_USER_STATUS,
            )
            
            session.add(first_it_admin)