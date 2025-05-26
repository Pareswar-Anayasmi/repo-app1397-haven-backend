import uuid
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


async def get_assistant_by_code1(groups, assistant_code, session: AsyncSession = None):
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
        


async def get_assistant_by_code(groups, assistant_code, session=None):
    async def _run_query(session):
        assistants_container = await get_container_client("assistants")
        permissions_container = await get_container_client("assistant_permissions")

        # Step 1: Find assistant by assistant_code
        query_assistants = "SELECT * FROM c WHERE c.assistant_code = @code"
        params_assistants = [{"name": "@code", "value": assistant_code}]

        assistants = assistants_container.query_items(
            query=query_assistants,
            parameters=params_assistants
        )

        assistant = None
        async for item in assistants:
            assistant = item
            break

        if not assistant:
            return None

        assistant_id = assistant["id"]  # Note dict access here

        # Step 2: Check permissions for this assistant_id in any of the groups
        # Build OR conditions for group_id filter
        group_conditions = " OR ".join([f"c.group_id = '{group_id}'" for group_id in groups])
        permission_query = f"""
            SELECT * FROM c
            WHERE c.assistant_id = @assistant_id AND ({group_conditions})
        """
        permission_params = [{"name": "@assistant_id", "value": assistant_id}]

        permissions = permissions_container.query_items(
            query=permission_query,
            parameters=permission_params
        )

        async for _ in permissions:
            # Permission found, return the assistant dict as is
            return assistant

        # No permissions found
        return None

    if session:
        return await _run_query(session)
    else:
        async with async_session_maker() as new_session:
            return await _run_query(new_session)

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

async def register_new_assistant1(assistant_details, user):
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
    
async def get_owner1(assistant_code, user):
    # Get Cosmos containers
    permissions_container = await get_container_client("assistant_permissions")
    organization_container = await get_container_client("organization_groups")

    # Get assistant object by code from Cosmos (you must ensure this function exists and works)
    assistants = await get_assistant_by_code(user.groups, assistant_code)

    if assistants is None:
        raise ValueError("Invalid assistant_code provided")

    # Query assistant_permissions container
    query_permissions = "SELECT * FROM c WHERE c.assistant_id = @assistant_id"
    params_permissions = [{"name": "@assistant_id", "value": assistants["id"]}]

    permission_items = permissions_container.query_items(
        query=query_permissions,
        parameters=params_permissions
        # enable_cross_partition_query=True,
    )
    permissions = [item async for item in permission_items]

    if not permissions:
        raise ValueError("Assistant not found")

    permission = permissions[0]

    # Query organization_groups container
    query_org = "SELECT c.created_by FROM c WHERE c.group_id = @group_id"
    params_org = [{"name": "@group_id", "value": permission["group_id"]}]

    org_items = organization_container.query_items(
        query=query_org,
        parameters=params_org
        # enable_cross_partition_query=True,
    )
    org_results = [item async for item in org_items]

    if not org_results:
        raise ValueError("Owner not found")

    owner = org_results[0]["created_by"]

    return {
        "assistant_id": permission["assistant_id"],
        "owner": owner,
    }

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

    assistant_owner_email = assistant_details.assistant_owner.lower()
    group_name = assistant_details.assistant_name.lower().replace(':', '').replace(' ', '-')

    # Fetch user groups from Cosmos DB
    user_groups = await get_user_groups(user)

    organizationGroups = await get_container_client("organization_groups")
    groupUsers = await get_container_client("group_users")
    assistants = await get_container_client("assistants")

    query = f"SELECT * FROM c WHERE c.group_name = '{IT_ADMIN_GROUP_NAME}'"

    it_admin_group_result = []

    async for item in organizationGroups.query_items(
        query=query
    ):
        it_admin_group_result.append(item)

    # Validate result
    if not it_admin_group_result:
        raise ValueError(f"No group found with name: {IT_ADMIN_GROUP_NAME}")

    it_admin_group = it_admin_group_result[0]

    if it_admin_group.get("group_id") not in user_groups:
        raise AuthError("Unauthorized to register assistant.", 403)



    # Get existing DIAM groups
    groups_list = await get_groups()

    admin_org_group_name = f"{SYSTEM_GROUP_ID}:{group_name}:{ROLE_ADMIN}"
    user_org_group_name = f"{SYSTEM_GROUP_ID}:{group_name}:{ROLE_USER}"

    if any(group["name"] in {admin_org_group_name, user_org_group_name} for group in groups_list["records"]):
        raise ValueError("Group already exists in DIAM.")

    try:
        # Create DIAM groups
        admin_org_group_diam = await create_organization_group(org_group_name=admin_org_group_name)
        user_org_group_diam = await create_organization_group(org_group_name=user_org_group_name)

        admin_org_group_id = admin_org_group_diam["data"]["id"]
        user_org_group_id = user_org_group_diam["data"]["id"]

        group_desc = f"Group for {assistant_details.assistant_name}"
        now = datetime.utcnow().isoformat()

        # Create org groups in Cosmos DB
        await organizationGroups.create_item({
            "id": str(uuid.uuid4()),
            "group_id": admin_org_group_id,
            "group_name": admin_org_group_name,
            "group_title": assistant_details.assistant_name,
            "group_description": group_desc,
            "assistant_group_name": group_name,
            "role_name": ROLE_ADMIN,
            "created_by": assistant_owner_email,
            "updated_by": assistant_owner_email,
            "created_at": now,
            "updated_at": now
        })

        await organizationGroups.create_item({
            "id": str(uuid.uuid4()),
            "group_id": user_org_group_id,
            "group_name": user_org_group_name,
            "group_title": assistant_details.assistant_name,
            "group_description": group_desc,
            "assistant_group_name": group_name,
            "role_name": ROLE_USER,
            "created_by": assistant_owner_email,
            "updated_by": assistant_owner_email,
            "created_at": now,
            "updated_at": now
        })

        # Create group users
        await groupUsers.create_item({
            "id": str(uuid.uuid4()),
            "group_id": admin_org_group_id,
            "email": user.email,
            "status": PENDING_USER_STATUS,
            "joined_at": now,
            "created_at": now,
            "updated_at": now
        })

        await groupUsers.create_item({
            "id": str(uuid.uuid4()),
            "group_id": admin_org_group_id,
            "email": assistant_owner_email,
            "status": PENDING_USER_STATUS,
            "joined_at": now,
            "created_at": now,
            "updated_at": now
        })

        # Create assistant
        assistant_code = await generate_assistant_code()
        assistant_id = str(uuid.uuid4())

        await assistants.create_item({
            "id": assistant_id,
            "assistant_name": assistant_details.assistant_name,
            "description": assistant_details.description,
            "endpoint": assistant_details.endpoint,
            "assistant_code": assistant_code,
            "created_at": now,
            "updated_at": now
        })

        # Add permissions
        await assistants.upsert_item({
            "id": assistant_id,
            "permissions": [
                {"group_id": admin_org_group_id},
                {"group_id": user_org_group_id}
            ]
        })

        return {
            "assistant_name": assistant_details.assistant_name,
            "assistant_code": assistant_code,
            "group_name": group_name,
            "group_description": group_desc,
            "admin_group_id": admin_org_group_id,
            "user_group_id": user_org_group_id
        }

    except Exception as e:
        raise ValueError(f"Assistant registration failed: {str(e)}")