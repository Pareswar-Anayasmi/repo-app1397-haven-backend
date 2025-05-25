from sqlalchemy import func, select, delete, update, and_, or_, not_, exists
from sqlalchemy.orm import aliased
from ..sql.connection import async_session_maker
from ..sql.schema import OrganizationGroups, GroupUsers, Users
from ..auth.base import AuthError
from ..diam.group_utils import delete_user_from_group, add_user_to_group
from sqlalchemy.ext.asyncio import AsyncSession
from ..utils.configurations import ROLE_ADMIN, PENDING_USER_STATUS, CONFIRMED_USER_STATUS
from fastapi import HTTPException
from datetime import datetime
from ..create_container_client import get_container_client
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


async def get_user_group_details(assistant_group_name, user):
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


async def get_org_group_by_name_email(
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


async def _check_group_permission(
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


async def delete_user_from_user_group(group_user_details, user):
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

async def update_user_role_in_user_group(group_user_details, user):
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
