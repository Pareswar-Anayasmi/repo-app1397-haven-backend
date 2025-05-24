from datetime import datetime
from ..sql.connection import async_session_maker
from sqlalchemy import func, select, delete
from sqlalchemy.future import select
from ..sql.schema import ConversationSummary, Assistants

from ..assistants.base import get_assistant_by_code

from ..auth.base import User

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from ..sql.connection import async_session_maker
from ..create_container_client import get_container_client
import uuid
log = logging.getLogger(__name__)


def _validate_summary_title(title: str):

    if not title:
        raise ValueError("Title is required.")
    
    if not title.strip():
        raise ValueError("Title cannot be empty.")
    
    if len(title) > 100:
        raise ValueError("Title cannot exceed 100 characters.")
    
async def create_summary_record(user: User, summary):

    if not summary.thread_id:
        raise ValueError("thread_id is required.")
    
    _validate_summary_title(summary.title)

    async with async_session_maker() as session:
        async with session.begin():

            exisitng_record = await _get_summary_record(summary.thread_id, session)

            if exisitng_record:
                raise ValueError("Thread ID already exists")

            assistants: Assistants = await get_assistant_by_code(
                user.groups, summary.assistant_code, session
            )

            if assistants is None:
                raise ValueError("Invalid assistant_code provided")

            new_summary = ConversationSummary(
                user_id=user.id,
                assistant_id=assistants.id,
                title=summary.title,
                num_of_messages=summary.num_of_messages,
                status=summary.status or "active",
                thread_id=str(summary.thread_id),
            )
            session.add(new_summary)

            await session.flush()

            return new_summary.to_dict()

# async def create_summary_record(user: User, summary):

#     if not summary.thread_id:
#         raise ValueError("thread_id is required.")
    
#     _validate_summary_title(summary.title)

#     async with async_session_maker() as session:
#         async with session.begin():

#             exisitng_record = await _get_summary_record(summary.thread_id, session)
      
#             if exisitng_record:
#                 raise ValueError("Thread ID already exists")

           
#             assistants = await get_assistant_by_code(
#                 user.groups, summary.assistant_code, session
#             )
            
#             if assistants is None:
#                 raise ValueError("Invalid assistant_code provided")

#             # new_summary = ConversationSummary(
#             #     user_id=user.id,
#             #     assistant_id=assistants.id,
#             #     title=summary.title,
#             #     num_of_messages=summary.num_of_messages,
#             #     status=summary.status or "active",
#             #     thread_id=str(summary.thread_id),
#             # )
#             # session.add(new_summary)
#             logging.info(f"assitantsssss,{assistants}")
#             # await session.flush()
#             new_summary={
#                          "id":str(uuid.uuid4()),
#                          "user_id":user.id,
#                          "assistant_id":assistants[0]["id"],
#                          "title":summary.title,
#                           "num_of_messages":summary.num_of_messages,
#                           "status":summary.status or "active",
#                           "thread_id":str(summary.thread_id)
#                          }
#             conv_sum_con=await get_container_client("conversation_summary")
#             await conv_sum_con.create_item(body=new_summary)
#             return new_summary


# Function to update an existing conversation summary record
async def update_summary_record(thread_id, user: User, summary):
        
    async with async_session_maker() as session:
        async with session.begin():

            assistants: Assistants = await get_assistant_by_code(
                user.groups, summary.assistant_code, session
            )

            if assistants is None:
                raise ValueError("Invalid assistant_code provided")

            result = await session.execute(
                select(ConversationSummary).where(
                    ConversationSummary.thread_id == thread_id,
                    ConversationSummary.user_id == user.id,
                )
            )

            record = result.scalars().one_or_none()

            if not record:
                raise ValueError("Record not found")
            else:
                if summary.title:
                    _validate_summary_title(summary.title)
                    record.title = summary.title

                record.num_of_messages = summary.num_of_messages

                if summary.status:
                    record.status = summary.status

                record.updated_at = datetime.now()

                return record.to_dict()


async def _get_summary_record1(thread_id, session: AsyncSession):
    """
    Fetch the conversation history for a specific user based on user_id.
    """
    # Query the conversation_summary table for the specific user's records
    query = select(ConversationSummary).where(
        ConversationSummary.thread_id == str(thread_id)
    )
    result = await session.execute(query)
    record = result.scalars().one_or_none()

    return record
async def _get_summary_record(thread_id, session: AsyncSession):
    """
    Fetch the conversation history for a specific user based on user_id.
    """
    # Query the conversation_summary table for the specific user's records
    container=await get_container_client("conversation_summary")
    query = "SELECT * FROM c WHERE c.thread_id = @thread_id"
    parameters=[{"name": "@thread_id", "value": str(thread_id)}]
    results = []
    async for item in container.query_items(
        query=query,
        parameters=parameters,
        
    ):
        results.append(item)
    return results
    # result = await session.execute(query)
    # record = result.scalars().one_or_none()

    # return record

def _create_ordering_list(order_by: str):
    """
    Create an ordering list based on the provided order_by string.
    The order_by parameter should be in the format "field_name [asc|desc]".
    If no direction is provided, ascending order is used by default.
    The field may belong to either ConversationSummary or Assistants.
    ConversationSummary.updated_at.desc() is always added as a tie-breaker unless the ordering field is updated_at.
    """
    default_ordering = [ConversationSummary.updated_at.desc()]
    if not order_by:
        return default_ordering

    parts = order_by.split()
    field_name = parts[0]
    # Default to 'asc' if no valid direction is provided
    direction = parts[1].lower() if len(parts) > 1 and parts[1].lower() in ['asc', 'desc'] else 'asc'

    # Try to get the column from ConversationSummary first
    column = getattr(ConversationSummary, field_name, None)
    if column is None:
        # If not found, try the Assistants model
        column = getattr(Assistants, field_name, None)

    # If still not found, fall back to the default ordering.
    if column is None:
        return default_ordering

    if field_name.lower() in ['title', 'assistant_name']:
        order_expr = func.lower(column)
    else:
        order_expr = column
        
    order_clause = order_expr.desc() if direction == 'desc' else order_expr.asc()

    # If the provided field is updated_at from ConversationSummary,
    # use it as the sole ordering.
    if field_name == "updated_at" and hasattr(ConversationSummary, field_name):
        return [order_clause]
    else:
        return [order_clause, ConversationSummary.updated_at.desc()]

async def get_summary_records(user: User, page: int = 1, per_page: int = 10, order_by: str = None):
    """
    Fetch the conversation history for a specific user based on user_id.
    """
    async with async_session_maker() as session:
        try:
            total_query = (
                select(func.count())
                .select_from(ConversationSummary)
                .where(ConversationSummary.user_id == user.id)
            )
            total_result = await session.execute(total_query)
            total_count = total_result.scalar()

            ordering_list = _create_ordering_list(order_by)
            
            records_query = (
                select(ConversationSummary, Assistants)
                .join(Assistants, ConversationSummary.assistant_id == Assistants.id)
                .where(ConversationSummary.user_id == user.id)
                .order_by(*ordering_list)
                .offset((page - 1) * per_page)
                .limit(per_page)
            )
            result = await session.execute(records_query)
            rows = result.all()

            records = [
                (row[0].to_dict() | {"assistant_name": row[1].assistant_name})
                for row in rows
            ]

            return {"total_records": total_count, "records": records}
        except Exception as e:
            log.exception("Error while fetching conversation history")
            # Handle the exception gracefully
            return {"total_records": 0, "records": []}


async def delete_summary_record(thread_id: str, user: User, assistant_code: str = None):
    async with async_session_maker() as session:
        async with session.begin():
            # for backward compatibility, we do not mandate the assistant_code for now
            if assistant_code:
                assistants: Assistants = await get_assistant_by_code(
                    user.groups, assistant_code, session
                )

                if assistants is None:
                    raise ValueError("Invalid assistant_code provided")
            
            existing_record = await _get_summary_record(thread_id, session)

            if not existing_record:
                return False

            await session.execute(
                delete(ConversationSummary).where(
                    ConversationSummary.thread_id == thread_id,
                    ConversationSummary.user_id == user.id,
                )
            )
            return True


# Function to mark or unmark a conversation as favorite
async def mark_conversation_favorite(thread_id, favorite, user: User):
        
    async with async_session_maker() as session:
        async with session.begin():

            favorite_flag = True if favorite.favorite_flag == True else False

            result = await session.execute(
                select(ConversationSummary).where(
                    ConversationSummary.thread_id == thread_id,
                    ConversationSummary.user_id == user.id,
                )
            )

            record = result.scalars().one_or_none()

            if not record:
                raise ValueError("Record not found")
            else:
                record.favorite = favorite_flag
                # record.updated_at = datetime.now()  # Do not update updated_at to prevent immediate sorting

                return record.to_dict()

async def get_conversation_summary_details(thread_id, user: User):
    """
    Fetch the conversation summary for a specific user based on thread_id.
    """
    async with async_session_maker() as session:
        try:
            result = await session.execute(
                select(ConversationSummary).where(
                    ConversationSummary.thread_id == thread_id,
                    ConversationSummary.user_id == user.id,
                )
            )

            record = result.scalars().one_or_none()

            return {"record": record}
        except Exception as e:
            log.exception("Error while fetching conversation summary")
            # Handle the exception gracefully
            return {"record": []}
