from sqlalchemy import select
from ..sql.connection import async_session_maker
from ..sql.schema import OrganizationGroups, AssistantPermissions
from ..create_container_client import get_container_client
import logging
 
from ..utils.configurations import IT_ADMIN_GROUP_NAME
 
log = logging.getLogger(__name__)
 
async def get_user_details1(user):
    async with async_session_maker() as session:
       
        try:
            query = (
                select(AssistantPermissions.assistant_id, OrganizationGroups.role_name, OrganizationGroups.created_by)
                .join(OrganizationGroups, AssistantPermissions.group_id == OrganizationGroups.group_id)
                .where(OrganizationGroups.group_id.in_(user.groups))
            )
 
            results = await session.execute(query)
 
            rows = results.fetchall()
 
            assistant_permissions = []
            for row in rows:
                assistant_permissions.append({
                    "assistant_id": row.assistant_id,
                    "role_name": row.role_name,
                    "is_group_owner": True if row.created_by == user.id else False
                })
 
            it_admin_group_result = await session.execute(select(OrganizationGroups).where(OrganizationGroups.group_name == IT_ADMIN_GROUP_NAME))
           
            it_admin_group = it_admin_group_result.scalars().one()
 
            super_admin = it_admin_group.group_id in user.groups
 
            return {
                "email": user.email,
                "name": user.name,
                "given_name": user.given_name,
                "family_name": user.family_name,
                "assistant_permissions": assistant_permissions,
                "super_admin_user": super_admin
            }
        except Exception as e:
            log.exception("Error while fetching user permissions")
            return {
                "email": user.email,
                "name": user.name,
                "given_name": user.given_name,
                "family_name": user.family_name,
                "assistant_permissions": [],
                "super_admin_user": False
            }
 
async def get_user_details(user):
    try:
       
        # Query assistant permissions
        assistant_permissions_container = get_container_client("assistant_permissions")
        groups_container = get_container_client("organization_groups")
       
        # Get all groups the user belongs to
        user_group_ids = user.groups
       
        # Query for assistant permissions - Cosmos DB doesn't support joins like PostgreSQL,
        # so we need to do this in two steps or use a subquery
        assistant_permissions = []
       
        # First get all relevant OrganizationGroups
        group_query = f"SELECT g.group_id, g.role_name, g.created_by FROM g WHERE g.group_id IN ({','.join([f'\"{g}\"' for g in user_group_ids])})"
        group_items = groups_container.query_items(
            query=group_query,
            enable_cross_partition_query=True
        )
       
        group_info = {item['group_id']: item for item in group_items}
       
        if group_info:
            # Now get AssistantPermissions for these groups
            permission_query = f"SELECT p.assistant_id, p.group_id FROM p WHERE p.group_id IN ({','.join([f'\"{g}\"' for g in group_info.keys()])})"
            permission_items = assistant_permissions_container.query_items(
                query=permission_query,
                enable_cross_partition_query=True
            )
           
            for item in permission_items:
                group_data = group_info[item['group_id']]
                assistant_permissions.append({
                    "assistant_id": item['assistant_id'],
                    "role_name": group_data['role_name'],
                    "is_group_owner": group_data['created_by'] == user.id
                })
       
        # Check for IT admin group membership
        it_admin_group_query = f"SELECT TOP 1 g.group_id FROM g WHERE g.group_name = '{IT_ADMIN_GROUP_NAME}'"
        it_admin_group_items = groups_container.query_items(
            query=it_admin_group_query,
            enable_cross_partition_query=True
        )
       
        it_admin_group = next(it_admin_group_items, None)
        super_admin = it_admin_group and it_admin_group['group_id'] in user.groups
       
        return {
            "email": user.email,
            "name": user.name,
            "given_name": user.given_name,
            "family_name": user.family_name,
            "assistant_permissions": assistant_permissions,
            "super_admin_user": super_admin
        }
       
    except Exception as e:
        log.exception("Error while fetching user permissions from Cosmos DB")
        return {
            "email": user.email,
            "name": user.name,
            "given_name": user.given_name,
            "family_name": user.family_name,
            "assistant_permissions": [],
            "super_admin_user": False
        }