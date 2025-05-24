from sqlalchemy import func, select, delete, update, and_, or_, not_, exists
from sqlalchemy.orm import aliased
from ..sql.connection import async_session_maker
from ..sql.schema import OrganizationGroups, GroupUsers, Users
from ..auth.base import AuthError
from ..diam.group_utils import delete_user_from_group, add_user_to_group
from ..create_container_client import get_container_client
from ..sql import connection1
from sqlalchemy.ext.asyncio import AsyncSession
from ..utils.configurations import ROLE_ADMIN, PENDING_USER_STATUS, CONFIRMED_USER_STATUS
from fastapi import HTTPException
from datetime import datetime
import uuid
import logging
import re
 
log = logging.getLogger(__name__)
 
async def get_assistant_group_details1(assistant_group_name: str):
    async with async_session_maker() as session:
        query = (
            select(OrganizationGroups)
            .filter(OrganizationGroups.assistant_group_name == assistant_group_name)
        )
 
        results = await session.execute(query)
 
        return results.scalars().all()
async def get_assistant_group_details(assistant_group_name: str):
    assistant_details_container = await get_container_client("organization_groups")
 
    query = "SELECT * FROM c WHERE c.assistant_group_name = @group_name"
    parameters = [{"name": "@group_name", "value": assistant_group_name}]
 
    # Ensure you pass options correctly via keyword arguments
    items_iterable = assistant_details_container.query_items(
        query=query,
        parameters=parameters,
       # enable_cross_partition_query=True  # <- Correct usage for async client
    )
 
    results = []
    async for item in items_iterable:
        results.append(item)
 
    return results
async def get_user_groups(user):
    async with async_session_maker() as session:
        try:
            og = aliased(OrganizationGroups)
 
            subquery = (
                select(
                    og.assistant_group_name,
                    func.min(og.id).label("min_id"),
                )
                .filter(og.group_id.in_(user.groups))
                .group_by(og.assistant_group_name)
                .subquery()
            )
            query = select(OrganizationGroups).where(
                and_(
                    OrganizationGroups.assistant_group_name == subquery.c.assistant_group_name,
                    OrganizationGroups.id == subquery.c.min_id,
                )
            )
            results = await session.execute(query)
 
            return {
                "records": [
                    {
                        "group_id": record.group_id,
                        "group_name": record.assistant_group_name,
                        "group_title": record.group_title,
                        "group_description": record.group_description,
                        "created_at": record.created_at,
                        "updated_at": record.updated_at,
                    }
                    for record in results.scalars().all()
                ]
            }
        except Exception as e:
            log.exception("Error while fetching groups")
            return {"records": []}
 
 
async def get_user_group_details1(assistant_group_name, user):
    async with async_session_maker() as session:
        try:
            # Fetch group details first
            og = aliased(OrganizationGroups)
            gu = aliased(GroupUsers)
 
            subquery = (
                select(
                    og.assistant_group_name,
                    func.min(og.id).label("min_id"),
                )
                .filter(og.group_id.in_(user.groups))
                .filter(og.assistant_group_name == assistant_group_name)
                .group_by(og.assistant_group_name)
                .subquery()
            )
            group_query = select(OrganizationGroups).where(
                and_(
                    OrganizationGroups.assistant_group_name
                    == subquery.c.assistant_group_name,
                    OrganizationGroups.id == subquery.c.min_id,
                )
            )
 
            group_result = await session.execute(group_query)
            group_record = group_result.scalars().one_or_none()
 
            # Fetch group members next
            og_sub = aliased(OrganizationGroups)
            gu_sub = aliased(GroupUsers)
 
            admin_email_subquery = (
                select(gu_sub.email)
                .join(og_sub, og_sub.group_id == gu_sub.group_id)
                .where(og_sub.role_name == ROLE_ADMIN)
            )
 
            member_query = (
                select(
                    OrganizationGroups.assistant_group_name,
                    GroupUsers.email,
                    GroupUsers.status,
                    OrganizationGroups.role_name,
                    GroupUsers.joined_at,
                    GroupUsers.created_at,
                )
                .join(GroupUsers, OrganizationGroups.group_id == GroupUsers.group_id)
                .where(OrganizationGroups.assistant_group_name == assistant_group_name)
            )
 
            member_results = await session.execute(member_query)
            member_rows = member_results.fetchall()
 
            members = {}
            admin_user = False
            for member_row in member_rows:
                key = member_row.email + "_" + member_row.status
                member_record = {
                        "email": member_row.email,
                        "role_name": member_row.role_name,
                        "status": member_row.status,
                        "joined_at": (
                            member_row.joined_at if member_row.joined_at else ""
                        ),
                        "invited_at": member_row.created_at,
                    }
                if member_row.status == PENDING_USER_STATUS or key not in members or member_row.role_name == ROLE_ADMIN:
                    # add user to members if
                    # 1. always add pending records
                    # 2. add user if not already in members
                    # 3. if the role is admin, add user to members to override the previous record if any
                    members[key] = member_record
 
                if user.email == member_row.email and member_row.role_name == ROLE_ADMIN and member_row.status == CONFIRMED_USER_STATUS:
                    group_checker = await _check_group_permission(
                        assistant_group_name,
                        user,
                        session
                    )
                    admin_user = bool(group_checker)
                       
               
            members = list(members.values())
 
            return {
                "record": {
                    "group_name": group_record.assistant_group_name,
                    "group_description": group_record.group_description,
                    "group_title": group_record.group_title,
                    "created_at": group_record.created_at,
                    "updated_at": group_record.updated_at,
                    "created_by": group_record.created_by,
                    "admin_user": admin_user,
                    "members": members,
                }
            }
 
        except Exception as e:
            log.exception("Error while fetching group details")
            return {"record": []}
 
async def get_user_group_details(assistant_group_name, user):
    try:
        groups_container = get_container_client("organization_groups")
        group_users_container = get_container_client("group_users")
 
        # Fetch group details - using query_iterable to check for empty results
        group_query = f"""
        SELECT TOP 1 * FROM g
        WHERE g.assistant_group_name = @assistant_group_name
        AND ARRAY_CONTAINS(@user_groups, g.group_id)
        ORDER BY g.id
        """
       
        group_result = groups_container.query_items(
            query=group_query,
            parameters=[
                {"name": "@assistant_group_name", "value": assistant_group_name},
                {"name": "@user_groups", "value": user.groups}
            ],
            enable_cross_partition_query=True
        )
       
        # Convert to list to check if empty
        group_records = list(group_result)
        if not group_records:
            return {"record": []}
 
        group_record = group_records[0]
 
        # Fetch group members
        member_query = f"""
        SELECT
            g.assistant_group_name,
            u.email,
            u.status,
            g.role_name,
            u.joined_at,
            u.created_at
        FROM g JOIN u IN g.members
        WHERE g.assistant_group_name = @assistant_group_name
        """
       
        member_results = groups_container.query_items(
            query=member_query,
            parameters=[
                {"name": "@assistant_group_name", "value": assistant_group_name}
            ],
            enable_cross_partition_query=True
        )
 
        members = {}
        admin_user = False
       
        # Check if there are any members at all
        has_members = False
        async for member_row in member_results:
            has_members = True
            key = f"{member_row['email']}_{member_row['status']}"
            member_record = {
                "email": member_row["email"],
                "role_name": member_row["role_name"],
                "status": member_row["status"],
                "joined_at": member_row.get("joined_at", ""),
                "invited_at": member_row["created_at"],
            }
           
            if (member_row["status"] == PENDING_USER_STATUS or
                key not in members or
                member_row["role_name"] == ROLE_ADMIN):
                members[key] = member_record
 
            if (user.email == member_row["email"] and
                member_row["role_name"] == ROLE_ADMIN and
                member_row["status"] == CONFIRMED_USER_STATUS):
                group_checker = await _check_group_permission(
                    assistant_group_name,
                    user,
                    groups_container
                )
                admin_user = bool(group_checker)
 
        if not has_members:
            return {
                "record": {
                    "group_name": group_record["assistant_group_name"],
                    "group_description": group_record.get("group_description", ""),
                    "group_title": group_record.get("group_title", ""),
                    "created_at": group_record["created_at"],
                    "updated_at": group_record.get("updated_at", ""),
                    "created_by": group_record["created_by"],
                    "admin_user": admin_user,
                    "members": [],
                }
            }
 
        return {
            "record": {
                "group_name": group_record["assistant_group_name"],
                "group_description": group_record.get("group_description", ""),
                "group_title": group_record.get("group_title", ""),
                "created_at": group_record["created_at"],
                "updated_at": group_record.get("updated_at", ""),
                "created_by": group_record["created_by"],
                "admin_user": admin_user,
                "members": list(members.values()),
            }
        }
 
    except Exception as e:
        log.exception("Error while fetching group details from Cosmos DB")
        return {"record": []}
   
 
async def get_org_group_by_name_role(
    assistant_group_name, role_name, session: AsyncSession = None
):
    async def _run_query(session: AsyncSession):
        results = await session.execute(
            select(OrganizationGroups)
            .filter(OrganizationGroups.assistant_group_name == assistant_group_name)
            .filter(OrganizationGroups.role_name == role_name)
            .distinct()
        )
        return results.scalars().one_or_none()
 
    if session:
        return await _run_query(session)
    else:
        async with async_session_maker() as new_session:
            return await _run_query(new_session)
 
 
async def get_org_group_by_name_email1(
    assistant_group_name, email, session: AsyncSession = None
):
    async def _run_query(session: AsyncSession):
        results = await session.execute(
            select(OrganizationGroups)
            .join(
                GroupUsers, OrganizationGroups.group_id == GroupUsers.group_id
            )
            .filter(OrganizationGroups.assistant_group_name == assistant_group_name)
            .filter(GroupUsers.email == email)
            .distinct()
        )
        return results.scalars().one_or_none()
 
    if session:
        return await _run_query(session)
    else:
        async with async_session_maker() as new_session:
            return await _run_query(new_session)
 
async def get_org_group_by_name_email(
    assistant_group_name, email, container=None
):
    """
    Fetch the organization group document from Cosmos DB by group name and user email.
    """
    if container is None:
        # fallback to SQL version if container is not provided
        async def _run_query(session: AsyncSession):
            results = await session.execute(
                select(OrganizationGroups)
                .join(
                    GroupUsers, OrganizationGroups.group_id == GroupUsers.group_id
                )
                .filter(OrganizationGroups.assistant_group_name == assistant_group_name)
                .filter(GroupUsers.email == email)
                .distinct()
            )
            return results.scalars().one_or_none()
 
        async with async_session_maker() as new_session:
            return await _run_query(new_session)
 
    # Cosmos DB version
    query = """
    SELECT * FROM c
    WHERE c.assistant_group_name = @group_name
    AND EXISTS (
        SELECT VALUE m FROM m IN c.members WHERE m.email = @user_email
    )
    """
    params = [
        {"name": "@group_name", "value": assistant_group_name},
        {"name": "@user_email", "value": email}
    ]
    items = container.query_items(
        query=query,
        parameters=params,
        enable_cross_partition_query=True
    )
    async for item in items:
        return item  # Return the first matching group
    return None
 
async def _check_group_permission1(
    assistant_group_name, user, session: AsyncSession = None
):
    """
    Fetch the group user data for a specific assistant_group_name, email and admin role.
    """
 
    query = (
        select(OrganizationGroups.group_id)
        .where(
            OrganizationGroups.assistant_group_name == assistant_group_name,
            OrganizationGroups.role_name == ROLE_ADMIN
        )
    )
 
    result = await session.execute(query)
 
    try:
        org_group_id = result.fetchall()[0].group_id
    except Exception as e:
        log.exception("Error fetching organization groups for admin role")
        return None
 
    if org_group_id in user.groups:
        return org_group_id
    else:
        return None
 
async def _check_group_permission(
    assistant_group_name, user, session_or_container=None
):
    """
    Check if the user has admin permission for the given assistant_group_name.
    Supports Cosmos DB container only.
    """
    if session_or_container and hasattr(session_or_container, "query_items"):
        container = session_or_container
        query = """
        SELECT c.group_id FROM c
        WHERE c.assistant_group_name = @group_name
        AND c.role_name = @role_admin
        """
        params = [
            {"name": "@group_name", "value": assistant_group_name},
            {"name": "@role_admin", "value": ROLE_ADMIN}
        ]
        items = container.query_items(
            query=query,
            parameters=params,
            enable_cross_partition_query=True
        )
        async for item in items:
            org_group_id = item.get("group_id")
            if org_group_id and org_group_id in user.groups:
                return org_group_id
        return None
 
    # If not a Cosmos container, do not support SQLAlchemy fallback
    raise ValueError("A Cosmos DB container is required for permission checking.")
 
 
# async def _get_group_user_record(group_id, email, session: AsyncSession):
#     """
#     Fetch the group user data for a specific group_id and email.
#     """
 
#     result = await session.execute(
#         select(GroupUsers)
#         .filter(GroupUsers.group_id == group_id)
#         .filter(GroupUsers.email == email)
#     )
#     record = result.scalars().one_or_none()
#     return record
 
def validate_email(email):
    email_re = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(email_re, email))
 
async def assign_user_to_user_group1(group_user_details, user):
    if not group_user_details.assistant_group_name:
        raise ValueError("Group name is required.")
 
    if not group_user_details.email:
        raise ValueError("Email is required.")
 
    if not group_user_details.role_name:
        raise ValueError("Role is required.")
   
    if not validate_email(group_user_details.email):
        raise ValueError("Email is not valid.", "user_management#invalid_email")
 
 
    email = group_user_details.email.lower()
    async with async_session_maker() as session:
        async with session.begin():
 
            org_group: OrganizationGroups = await get_org_group_by_name_role(
                group_user_details.assistant_group_name,
                group_user_details.role_name.lower(),
                session,
            )
 
            # Check user permission to add user to group
            group_checker = await _check_group_permission(
                group_user_details.assistant_group_name,
                user,
                session
            )
 
            if not group_checker:
                raise AuthError("Unauthorized to add user to group.", 403)
 
            # Check already existing record
            group_user_exists = await get_org_group_by_name_email(
                group_user_details.assistant_group_name, email, session
            )
 
            if group_user_exists:
                raise ValueError("User already exists for this group.", "user_management#user_add_duplicated")
 
            group_user = GroupUsers(
                group_id=org_group.group_id,
                email=email,
                status=PENDING_USER_STATUS,
            )
 
            session.add(group_user)
 
            await session.flush()
 
            return group_user.to_dict()
 
async def assign_user_to_user_group(group_user_details, user):
    if not group_user_details.assistant_group_name:
        raise ValueError("Group name is required.")
    if not group_user_details.email:
        raise ValueError("Email is required.")
    if not group_user_details.role_name:
        raise ValueError("Role is required.")
    if not validate_email(group_user_details.email):
        raise ValueError("Email is not valid.", "user_management#invalid_email")
 
    email = group_user_details.email.lower()
    groups_container = get_container_client("organization_groups")
    users_container = get_container_client("group_users")
 
    try:
        # 1. Get the organization group by name and role
        group_query = """
        SELECT * FROM c WHERE c.assistant_group_name = @group_name AND c.role_name = @role_name
        """
        group_params = [
            {"name": "@group_name", "value": group_user_details.assistant_group_name},
            {"name": "@role_name", "value": group_user_details.role_name.lower()}
        ]
        group_items = groups_container.query_items(
            query=group_query,
            parameters=group_params,
            enable_cross_partition_query=True
        )
        org_group = None
        async for item in group_items:
            org_group = item
            break
        if not org_group:
            raise ValueError("Group not found.")
 
        # 2. Check user permission to add user to group
        group_checker = await _check_group_permission(
            group_user_details.assistant_group_name,
            user,
            groups_container
        )
        if not group_checker:
            raise AuthError("Unauthorized to add user to group.", 403)
 
        # 3. Check if user already exists in group
        existing = await get_org_group_by_name_email(
            group_user_details.assistant_group_name, email, groups_container
        )
        if existing:
            raise ValueError("User already exists for this group.", "user_management#user_add_duplicated")
 
        # 4. Add user to group_users container
        import uuid
        user_doc = {
            "id": str(uuid.uuid4()),
            "group_id": org_group["group_id"],
            "email": email,
            "status": PENDING_USER_STATUS,
            "created_at": datetime.utcnow().isoformat(),
            "joined_at": None,
            "role_name": group_user_details.role_name.lower()
        }
        await users_container.create_item(body=user_doc, partition_key=org_group["group_id"])
 
        # 5. Optionally, add user to group's members array
        try:
            members = org_group.get("members", [])
            members.append({
                "email": email,
                "role_name": group_user_details.role_name.lower(),
                "status": PENDING_USER_STATUS,
                "created_at": user_doc["created_at"],
                "joined_at": None
            })
            patch_operation = [
                {
                    "op": "replace",
                    "path": "/members",
                    "value": members
                }
            ]
            await groups_container.patch_item(
                item=org_group["id"],
                partition_key=org_group["group_id"],
                patch_operations=patch_operation
            )
        except Exception as e:
            log.warning(f"Could not update group members list: {str(e)}")
 
        return user_doc
 
    finally:
        await connection1.get_cosmos_client.close()
 
async def delete_user_from_user_group1(group_user_details, user):
    if not group_user_details.assistant_group_name:
        raise ValueError("Group name is required.")
 
    if not group_user_details.email:
        raise ValueError("Email is required.")
 
    email = group_user_details.email.lower()
    async with async_session_maker() as session:
        async with session.begin():
 
            org_group: OrganizationGroups = await get_org_group_by_name_email(
                group_user_details.assistant_group_name,
                email,
                session,
            )
 
            # Check user permission to delete user from group
            group_checker = await _check_group_permission(
                group_user_details.assistant_group_name,
                user,
                session
            )
            if not group_checker:
                raise AuthError("Unauthorized to delete user from group.", 403)
           
            if org_group.created_by == email:
                raise ValueError("Group creator cannot be deleted.")
           
            user_group_results = await session.execute(
                select(GroupUsers)
                .where(GroupUsers.group_id == org_group.group_id)
                .where(GroupUsers.email == email)
            )
            user_group_record = user_group_results.scalars().one_or_none()
 
            if user_group_record:
               
                if user_group_record.status != PENDING_USER_STATUS:
           
                    # Get DIAM id of the user to be deleted
                    user_results = await session.execute(
                        select(Users)
                        .filter(Users.email == email)
                        .distinct()
                    )
                    user_record = user_results.scalars().one_or_none()
                   
                    # Delete user from DIAM group first
                    await delete_user_from_group(
                        diam_user_id=user_record.diam_user_id,
                        group_id=org_group.group_id
                    )
 
                # Delete user from database next
                await session.delete(user_group_record)
       
                return True
           
            return False
 
async def delete_user_from_user_group(group_user_details, user):
    if not group_user_details.assistant_group_name:
        raise ValueError("Group name is required.")
    if not group_user_details.email:
        raise ValueError("Email is required.")
 
    email = group_user_details.email.lower()
    groups_container = get_container_client("organization_groups")
    users_container = get_container_client("group_users")
 
    try:
        # 1. Get the organization group by name and email
        org_group = await get_org_group_by_name_email(
            group_user_details.assistant_group_name,
            email,
            groups_container
        )
        if not org_group:
            return False
 
        # 2. Check user permission to delete user from group
        group_checker = await _check_group_permission(
            group_user_details.assistant_group_name,
            user,
            groups_container
        )
        if not group_checker:
            raise AuthError("Unauthorized to delete user from group.", 403)
 
        if org_group.get("created_by", "").lower() == email:
            raise ValueError("Group creator cannot be deleted.")
 
        # 3. Find the group_user record in group_users container
        query = """
        SELECT * FROM c WHERE c.group_id = @group_id AND c.email = @user_email
        """
        params = [
            {"name": "@group_id", "value": org_group["group_id"]},
            {"name": "@user_email", "value": email}
        ]
        user_items = users_container.query_items(
            query=query,
            parameters=params,
            enable_cross_partition_query=True
        )
        user_record = None
        async for item in user_items:
            user_record = item
            break
 
        if user_record:
            # If user is not pending, remove from DIAM group
            if user_record.get("status") != PENDING_USER_STATUS:
                # Get DIAM id from user record if available
                diam_user_id = user_record.get("diam_user_id")
                if diam_user_id:
                    await delete_user_from_group(
                        diam_user_id=diam_user_id,
                        group_id=org_group["group_id"]
                    )
 
            # Delete user from group_users container
            await users_container.delete_item(
                item=user_record["id"],
                partition_key=user_record["group_id"]
            )
 
            # Remove user from group's members array (if denormalized)
            try:
                members = org_group.get("members", [])
                new_members = [
                    m for m in members if m.get("email", "").lower() != email
                ]
                if len(new_members) != len(members):
                    patch_operation = [
                        {
                            "op": "replace",
                            "path": "/members",
                            "value": new_members
                        }
                    ]
                    await groups_container.patch_item(
                        item=org_group["id"],
                        partition_key=org_group["group_id"],
                        patch_operations=patch_operation
                    )
            except Exception as e:
                log.warning(f"Could not update group members list: {str(e)}")
 
            return True
 
        return False
 
    finally:
        await connection1.get_cosmos_client.close()
 
async def update_user_role_in_user_group1(group_user_details, user):
    if not group_user_details.assistant_group_name:
        raise ValueError("Group name is required.")
 
    if not group_user_details.email:
        raise ValueError("Email is required.")
 
    if not group_user_details.role_name:
        raise ValueError("Role is required.")
 
    email = group_user_details.email.lower()
    async with async_session_maker() as session:
        async with session.begin():
 
            role_to_check = 'user' if group_user_details.role_name.lower() == 'admin' else 'admin'
 
            org_group_old: OrganizationGroups = await get_org_group_by_name_role(
                group_user_details.assistant_group_name,
                role_to_check,
                session,
            )
 
            org_group_new: OrganizationGroups = await get_org_group_by_name_role(
                group_user_details.assistant_group_name,
                group_user_details.role_name.lower(),
                session,
            )
 
            # Check user permission to update user in group
            group_checker = await _check_group_permission(
                group_user_details.assistant_group_name,
                user,
                session
            )
 
            if not group_checker:
                raise AuthError("Unauthorized to update user in group.", 403)
 
            if org_group_old.created_by == email:
                raise ValueError("Group creator role cannot be changed.")
 
            # Get DIAM id of the user to be deleted
            user_results = await session.execute(
                select(Users)
                .filter(Users.email == email)
                .distinct()
            )
            user_record = user_results.scalars().one_or_none()
 
            # Delete user from old DIAM group
            await delete_user_from_group(
                diam_user_id=user_record.diam_user_id,
                group_id=org_group_old.group_id
            )
 
            # Add user to new DIAM group
            await add_user_to_group(
                diam_user_id=user_record.diam_user_id,
                group_id=org_group_new.group_id
            )
 
            # Update user in database. Update instead of insert and delete to preserve the created_at
            await session.execute(
                update(GroupUsers)
                .where(
                    and_(
                        GroupUsers.group_id == org_group_old.group_id,
                        GroupUsers.email == email,
                    )
                )
                .values(group_id=org_group_new.group_id, updated_at=datetime.now())
            )
            return True
 
async def update_user_role_in_user_group(group_user_details, user):
    if not group_user_details.assistant_group_name:
        raise ValueError("Group name is required.")
 
    if not group_user_details.email:
        raise ValueError("Email is required.")
 
    if not group_user_details.role_name:
        raise ValueError("Role is required.")
 
    email = group_user_details.email.lower()
    groups_container = get_container_client("organization_groups")
    users_container = get_container_client("group_users")
 
    # 1. Get the old and new group records by role
    role_to_check = 'user' if group_user_details.role_name.lower() == 'admin' else 'admin'
 
    # Old group (current role)
    old_group_query = """
    SELECT * FROM c WHERE c.assistant_group_name = @group_name AND c.role_name = @role_to_check
    """
    old_group_params = [
        {"name": "@group_name", "value": group_user_details.assistant_group_name},
        {"name": "@role_to_check", "value": role_to_check}
    ]
    old_group_items = groups_container.query_items(
        query=old_group_query,
        parameters=old_group_params,
        enable_cross_partition_query=True
    )
    org_group_old = None
    async for item in old_group_items:
        org_group_old = item
        break
 
    # New group (target role)
    new_group_query = """
    SELECT * FROM c WHERE c.assistant_group_name = @group_name AND c.role_name = @role_name
    """
    new_group_params = [
        {"name": "@group_name", "value": group_user_details.assistant_group_name},
        {"name": "@role_name", "value": group_user_details.role_name.lower()}
    ]
    new_group_items = groups_container.query_items(
        query=new_group_query,
        parameters=new_group_params,
        enable_cross_partition_query=True
    )
    org_group_new = None
    async for item in new_group_items:
        org_group_new = item
        break
 
    if not org_group_old or not org_group_new:
        raise ValueError("Group not found.")
 
    # 2. Check user permission to update user in group
    group_checker = await _check_group_permission(
        group_user_details.assistant_group_name,
        user,
        groups_container
    )
    if not group_checker:
        raise AuthError("Unauthorized to update user in group.", 403)
 
    if org_group_old.get("created_by", "").lower() == email:
        raise ValueError("Group creator role cannot be changed.")
 
    # 3. Find the user record in group_users container
    user_query = """
    SELECT * FROM c WHERE c.group_id = @group_id AND c.email = @user_email
    """
    user_params = [
        {"name": "@group_id", "value": org_group_old["group_id"]},
        {"name": "@user_email", "value": email}
    ]
    user_items = users_container.query_items(
        query=user_query,
        parameters=user_params,
        enable_cross_partition_query=True
    )
    user_record = None
    async for item in user_items:
        user_record = item
        break
 
    if not user_record:
        raise ValueError("User not found in group.")
 
    # 4. Update user record to new group_id and role
    # Remove from old group_users
    await users_container.delete_item(
        item=user_record["id"],
        partition_key=user_record["group_id"]
    )
 
    # Add to new group_users
    import uuid
    from datetime import datetime
    new_user_doc = {
        "id": str(uuid.uuid4()),
        "group_id": org_group_new["group_id"],
        "email": email,
        "status": user_record.get("status"),
        "created_at": user_record.get("created_at"),
        "joined_at": user_record.get("joined_at"),
        "role_name": group_user_details.role_name.lower(),
        "updated_at": datetime.utcnow().isoformat()
    }
    await users_container.create_item(body=new_user_doc, partition_key=org_group_new["group_id"])
 
    # 5. Update members array in both old and new group docs
    try:
        # Remove from old group members
        old_members = org_group_old.get("members", [])
        old_members = [m for m in old_members if m.get("email", "").lower() != email]
        await groups_container.patch_item(
            item=org_group_old["id"],
            partition_key=org_group_old["group_id"],
            patch_operations=[
                {
                    "op": "replace",
                    "path": "/members",
                    "value": old_members
                }
            ]
        )
        # Add to new group members
        new_members = org_group_new.get("members", [])
        new_members.append({
            "email": email,
            "role_name": group_user_details.role_name.lower(),
            "status": user_record.get("status"),
            "created_at": user_record.get("created_at"),
            "joined_at": user_record.get("joined_at")
        })
        await groups_container.patch_item(
            item=org_group_new["id"],
            partition_key=org_group_new["group_id"],
            patch_operations=[
                {
                    "op": "replace",
                    "path": "/members",
                    "value": new_members
                }
            ]
        )
    except Exception as e:
        log.warning(f"Could not update group members list: {str(e)}")
 
    return True
 
async def update_user_group(assistant_group_name, group_details, user):
    if not assistant_group_name.strip():
        raise ValueError("Assistant Group Name is required.")
 
    if not group_details.group_title.strip():
        raise ValueError("Group Name is required.")
 
    if not group_details.group_description.strip():
        raise ValueError("Group Description is required.")
 
    async with async_session_maker() as session:
        async with session.begin():
 
            # Check user permission to update user in group
            group_checker = await _check_group_permission(
                assistant_group_name,
                user,
                session
            )
 
            if not group_checker:
                raise AuthError("Unauthorized to update group.", 403)
           
            try:
                await session.execute(
                    update(OrganizationGroups)
                        .where(
                            and_(
                                OrganizationGroups.assistant_group_name == assistant_group_name
                            )
                        )
                        .values(
                            group_title = group_details.group_title,
                            group_description = group_details.group_description,
                            updated_at = datetime.now(),
                            updated_by = user.email
                        )
                )
 
                await session.commit()
                return {"message": f"Group updated successfully"}
            except:
                return {"message": f"Unable to update group"}