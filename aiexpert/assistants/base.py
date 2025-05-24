from sqlalchemy import func, select, or_
from ..sql.connection import async_session_maker
from ..sql.schema import Assistants, AssistantPermissions, OrganizationGroups, GroupUsers
from ..diam.group_utils import get_groups, create_organization_group
from ..utils.configurations import ROLE_ADMIN, ROLE_USER, SYSTEM_GROUP_ID, PENDING_USER_STATUS, IT_ADMIN_GROUP_NAME
from ..auth.base import AuthError
import logging
from sqlalchemy.ext.asyncio import AsyncSession
import secrets
import re
from datetime import datetime
from ..create_container_client import get_container_client
log = logging.getLogger(__name__)

ASSISTANT_CODE_LENGTH = 32


async def get_assistant_by_code(groups, assistant_code, session: AsyncSession = None):
    async def _run_query(session: AsyncSession):
        results = await session.execute(
            select(Assistants)
            .join(
                AssistantPermissions, Assistants.id == AssistantPermissions.assistant_id
            )
            .filter(Assistants.assistant_code == assistant_code)
            .filter(AssistantPermissions.group_id.in_(groups))
            .distinct()
        )
        
        return results.scalars().one_or_none()

    if session:
        return await _run_query(session)
    else:
        async with async_session_maker() as new_session:
            return await _run_query(new_session)
        

# async def get_assistant_by_code(groups, assistant_code, session: AsyncSession = None,c1=None,c2=None,c3=None):
#     async def _run_query(c1,c2):
#         query1="SELECT DISTINCT p.assistant_id FROM p WHERE ARRAY_CONTAINS(@groups, p.group_id)"
#         params1 = [
#             {"name": "@groups", "value": groups}
#         ]

#         assistant_ids = []
#         try:
#             async for item in c1.query_items(query=query1,parameters=params1):
#                 assistant_ids.append(item['assistant_id'])

#         except Exception as e:
#             logging.error(f"Error querying AssistantPermissions: {e}")
#             return []
        
#         logging.info(f"assistantsss{assistant_ids}")

#         query2 = "SELECT * FROM a WHERE a.assistant_code = @assistant_code AND ARRAY_CONTAINS(@assistant_ids, a.id)"
        
#         params2 = [
#             {"name": "@assistant_code", "value": assistant_code},
#             {"name": "@assistant_ids", "value": assistant_ids}
#         ]

#         assistants = []
#         try:
#             async for assistant in c2.query_items(query=query2,parameters=params2):
#                 assistants.append(assistant)

#         except Exception as e:
#             logging.exception(f"Error querying Assistants: {e}")
#             return []

#         return assistants

#     if c1 and c2 :
#         return await _run_query(c1,c2)
#     else:
#         c1= await get_container_client("assistant_permissions")
#         c2= await get_container_client("assistants")
#         return await _run_query(c1,c2)


async def get_assistants1(groups, page, per_page):
    async with async_session_maker() as session:
        try:
                                    
            total_query = (
                select(func.count())
                .select_from(Assistants)
                .join(
                    AssistantPermissions, Assistants.id == AssistantPermissions.assistant_id
                )
                .filter(AssistantPermissions.group_id.in_(groups))
                .distinct()
            )
            total_result = await session.execute(total_query)
            total_count = total_result.scalar()

            results = await session.execute(
                select(Assistants)
                .join(
                    AssistantPermissions, Assistants.id == AssistantPermissions.assistant_id
                )
                .filter(AssistantPermissions.group_id.in_(groups))
                .distinct()
                .offset((page - 1) * per_page)
                .limit(per_page)
                .order_by(Assistants.assistant_name)
            )

            return {
                "total": total_count,
                "records": [
                    {
                        "id": record.id,
                        "assistant_name": record.assistant_name,
                        "description": record.description,
                        "endpoint": record.endpoint  
                    } for record in results.scalars().all()
                ]
            }
        except Exception as e:
            log.exception("Error while fetching assistants")
            return {"total": 0, "records": []}


async def get_assistants(groups, page, per_page):
    try:
        assistants_container = await get_container_client("assistants")
        permissions_container = await get_container_client("assistant_permissions")

        group_ids_set = set(groups)

        # Step 1: Fetch assistant_ids where group_id is in the input groups
        allowed_assistant_ids = set()
        async for permission in permissions_container.read_all_items():
            if permission.get("group_id") in group_ids_set:
                allowed_assistant_ids.add(permission["assistant_id"])

        # Step 2: Fetch assistants with matching IDs
        assistants = []
        async for assistant in assistants_container.read_all_items():
            if assistant["id"] in allowed_assistant_ids:
                assistants.append(assistant)

        # Step 3: Sort by assistant_name (case-insensitive)
        assistants.sort(key=lambda x: x.get("assistant_name", "").lower())

        # Step 4: Paginate
        total = len(assistants)
        start = (page - 1) * per_page
        end = start + per_page
        paginated = assistants[start:end]

        # Step 5: Return formatted response
        return {
            "total": total,
            "records": [
                {
                    "id": item["id"],
                    "assistant_name": item.get("assistant_name"),
                    "description": item.get("description"),
                    "endpoint": item.get("endpoint")
                } for item in paginated
            ]
        }

    except Exception as e:
        log.exception("Error while fetching assistants")
        return {"total": 0, "records": []}
    
async def generate_assistant_code():
    return secrets.token_hex(ASSISTANT_CODE_LENGTH)

async def get_user_groups(user):
    if hasattr(user, 'groups'):
        user_groups = user.groups
    else:
        user_groups = [str(user)]
    return user_groups

async def search_assistants_by_filter1(groups, filter_query=None):
    async with async_session_maker() as session:
        try:
            query = (
                select(Assistants)
                .outerjoin(AssistantPermissions)
                .filter(
                    or_(
                        AssistantPermissions.group_id.in_(groups),
                        AssistantPermissions.id == None
                    )
                )
                .distinct()
            )
            if filter_query:
                field, operator, value = "name", "contains", filter_query.strip()
                if "contains" in filter_query:
                    value = filter_query.split("contains")[1].strip().strip("' ")
                elif "eq" in filter_query:
                    operator = "eq"
                    value = filter_query.split("eq")[1].strip().strip("' ")
                
                if field == "name":
                    if operator == "contains":
                        query = query.filter(Assistants.assistant_name.ilike(f"%{value}%"))
                    else:
                        query = query.filter(Assistants.assistant_name.ilike(value))
            results = await session.execute(query.order_by(Assistants.assistant_name))
            records = [
                {
                    "id": record.id,
                    "assistant_name": record.assistant_name,
                    "description": record.description,
                    "endpoint": record.endpoint
                } for record in results.scalars().all()
            ]
            return {
                "records": records
            }
        except Exception as e:
            log.exception("Error searching assistants")
            return {"total": 0, "records": []}


async def search_assistants_by_filter(groups, filter_query=None):
    try:
        # Connect to the containers
        assistants_container = await get_container_client("assistants")
        permissions_container = await get_container_client("assistant_permissions")

        # Get assistant IDs that are either in provided groups or have no permission
        group_ids_set = set(groups)

        assistant_ids = set()
        async for permission in permissions_container.read_all_items():
            if permission.get("group_id") in group_ids_set:
                assistant_ids.add(permission["assistant_id"])

        # Also include assistants with no permissions (unrestricted)
        assistants_with_permissions = set()
        async for permission in permissions_container.read_all_items():
            assistants_with_permissions.add(permission["assistant_id"])

        unrestricted_assistants = set()
        async for assistant in assistants_container.read_all_items():
            if assistant["id"] not in assistants_with_permissions:
                unrestricted_assistants.add(assistant["id"])

        final_ids = assistant_ids.union(unrestricted_assistants)

        # Apply filter on name if needed
        results = []
        async for assistant in assistants_container.read_all_items():
            if assistant["id"] not in final_ids:
                continue

            name = assistant.get("assistant_name", "").lower()
            if filter_query:
                if "contains" in filter_query:
                    value = filter_query.split("contains")[1].strip().strip("' ").lower()
                    if value not in name:
                        continue
                elif "eq" in filter_query:
                    value = filter_query.split("eq")[1].strip().strip("' ").lower()
                    if name != value:
                        continue

            results.append({
                "id": assistant["id"],
                "assistant_name": assistant.get("assistant_name"),
                "description": assistant.get("description"),
                "endpoint": assistant.get("endpoint")
            })

        # Sort results by assistant_name
        results.sort(key=lambda x: x["assistant_name"].lower())
        return {"records": results}

    except Exception as e:
        log.exception("Error searching assistants")
        return {"total": 0, "records": []}

def validate_email(email):
    email_re = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(email_re, email))

async def register_new_assistant(assistant_details, user):
    if not assistant_details.assistant_name:
        raise ValueError("Assistant name is required.")

    if not assistant_details.assistant_owner:
        raise ValueError("Assistant administrator is required.")

    if not validate_email(assistant_details.assistant_owner):
        raise ValueError("Assistant administrator email is not valid.")

    if not assistant_details.description:
        raise ValueError("Assistant description is required.")

    if not assistant_details.endpoint:
        raise ValueError("Assistant endpoint is required.")
    
    user_groups = await get_user_groups(user)
    
    assistant_owner_email = assistant_details.assistant_owner.lower()
    
    async with async_session_maker() as session:
        
        it_admin_group_result = await session.execute(select(OrganizationGroups).where(OrganizationGroups.group_name == IT_ADMIN_GROUP_NAME))
        
        it_admin_group = it_admin_group_result.scalars().one()

        if it_admin_group.group_id not in user_groups:
            raise AuthError("Unauthorized to register assistant.", 403)
    
        # Get existing groups
        groups_list = await get_groups()

        group_name = assistant_details.assistant_name.lower().replace(':','').replace(' ','-')

        # Check existing organization groups in DIAM
        admin_org_group_name = SYSTEM_GROUP_ID+":"+group_name+":"+ROLE_ADMIN
        user_org_group_name = SYSTEM_GROUP_ID+":"+group_name+":"+ROLE_USER

        if any(group["name"] in {admin_org_group_name, user_org_group_name} for group in groups_list["records"]):
            raise ValueError("Group already exists in DIAM.")
        
        try:
            # Create organization groups in DIAM
            admin_org_group_diam = await create_organization_group(
                org_group_name=admin_org_group_name
            )
            log.debug("admin_org_group_diam: %s:", admin_org_group_diam)        
            admin_org_group_id = admin_org_group_diam['data']['id']

            user_org_group_diam = await create_organization_group(
                org_group_name=user_org_group_name
            )
            log.debug("user_org_group_diam: %s:", user_org_group_diam)
            user_org_group_id = user_org_group_diam['data']['id']

            group_desc = 'Group for '+assistant_details.assistant_name
            # Create Organization Groups in DB
            admin_org_group = OrganizationGroups(
                group_id=admin_org_group_id,
                group_name=admin_org_group_name,
                group_title=assistant_details.assistant_name,
                group_description=group_desc,
                assistant_group_name=group_name,
                role_name=ROLE_ADMIN,
                created_by=assistant_owner_email,
                updated_by=assistant_owner_email,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            session.add(admin_org_group)
            log.debug("admin_org_group created with group_id: %s:", admin_org_group_id)

            user_org_group = OrganizationGroups(
                group_id=user_org_group_id,
                group_name=user_org_group_name,
                group_title=assistant_details.assistant_name,
                group_description=group_desc,
                assistant_group_name=group_name,
                role_name=ROLE_USER,
                created_by=assistant_owner_email,
                updated_by=assistant_owner_email,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            session.add(user_org_group)
            log.debug("user_org_group created with group_id: %s:", user_org_group_id)

            await session.flush()

            # Create Group Users in DB
            group_user_super_admin = GroupUsers(
                group_id=admin_org_group_id,
                email=user.email,
                status=PENDING_USER_STATUS,
                joined_at=datetime.now(),
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            session.add(group_user_super_admin)
            log.debug("group_user_super_admin created with group_id: %s and email: %s", admin_org_group_id, user.email)

            group_user_assistant_owner = GroupUsers(
                group_id=admin_org_group_id,
                email=assistant_owner_email,
                status=PENDING_USER_STATUS,
                joined_at=datetime.now(),
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            session.add(group_user_assistant_owner)
            log.debug("group_user_assistant_owner created with group_id: %s and email: %s", admin_org_group_id, assistant_owner_email)

            await session.flush()

            # Create assistant in DB
            assistant_code = await generate_assistant_code()

            assistant = Assistants(
                assistant_name=assistant_details.assistant_name,
                description=assistant_details.description,
                endpoint=assistant_details.endpoint,
                assistant_code=assistant_code
            )
            session.add(assistant)

            await session.flush()

            assistant_results = await session.execute(
                select(Assistants)
                .filter(Assistants.assistant_name == assistant_details.assistant_name)
                .distinct()
            )
            assistant_record = assistant_results.scalars().one_or_none()
            log.debug("Id of new assistant: %s:", assistant_record.id)

            # Create assistant permissions in DB
            admin_assistant_permission = AssistantPermissions(
                assistant_id=assistant_record.id,
                group_id=admin_org_group_id
            )
            session.add(admin_assistant_permission)

            user_assistant_permission = AssistantPermissions(
                assistant_id=assistant_record.id,
                group_id=user_org_group_id
            )
            session.add(user_assistant_permission)

            await session.commit()
            
            return {
                "assistant_name": assistant_details.assistant_name,
                "assistant_code": assistant_code,
                "group_name": group_name,
                "group_description": group_desc,
                "admin_group_id": admin_org_group_id,
                "user_group_id": user_org_group_id
            }
        except:
            raise ValueError("Assistant registration failed")
        

async def get_owner(assistant_code, user):
    async with async_session_maker() as session:
        assistants: Assistants = await get_assistant_by_code(
            user.groups, assistant_code, session
        )

        if assistants is None:
            raise ValueError("Invalid assistant_code provided")
        
        query = (
            select(AssistantPermissions.assistant_id, OrganizationGroups.created_by)
            .join(OrganizationGroups, AssistantPermissions.group_id == OrganizationGroups.group_id)
            .where(AssistantPermissions.assistant_id == assistants.id)
        )

        results = await session.execute(query)

        rows = results.first()
        
        if rows is None:
            raise ValueError("Assistant not found")

        return {
            "assistant_id": rows.assistant_id,
            "owner": rows.created_by
        }
      