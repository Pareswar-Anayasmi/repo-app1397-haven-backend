import uuid
from fastapi import APIRouter, Depends, Query, Header
import logging
from fastapi import HTTPException
from typing import Optional

from aiexpert.diam.group_utils import GroupChecker
from aiexpert.utils.configurations import SYSTEM_GROUP_ID
from ..auth.base import get_authenticated_user, User
from pydantic import BaseModel
from ..conversations.base import (create_summary_record,
                                  update_summary_record,
                                  get_summary_records,
                                  delete_summary_record,
                                  mark_conversation_favorite,
                                  get_conversation_summary_details)

log = logging.getLogger(__name__)

router = APIRouter(
    prefix=f"/{__name__.replace(__package__ + '.', '')}", tags=["Conversation Summary"], dependencies=[Depends(GroupChecker(allowed_groups=[SYSTEM_GROUP_ID]))]
)

class ConversationSummaryCreateRequest(BaseModel):
    thread_id: uuid.UUID
    # mark assistant_code as optional for backward compatibility
    assistant_code: Optional[str] = None
    title: str = None
    num_of_messages: int
    status: str = None

class ConversationSummaryUpdateRequest(BaseModel):
    title: str = None
    # mark assistant_code as optional for backward compatibility
    assistant_code: Optional[str] = None
    num_of_messages: int
    status: str = None

class ConversationSummaryFavoriteRequest(BaseModel):
    favorite_flag: bool

@router.post("")
async def create_conversation_summary(
    summary: ConversationSummaryCreateRequest,
    assistant_code: Optional[str] = Header(None), # for backward compatibility, set the assistant_code from header optional
    user: User = Depends(get_authenticated_user),
):
    # for backward compatibility, if assistant_code is available from header, use that one instead of the one in the request
    if assistant_code:
        summary.assistant_code = assistant_code
    
    return await create_summary_record(user, summary)


# API to update an existing conversation summary record
@router.post("/{thread_id}")
async def update_conversation_summary(
    thread_id: str,
    summary: ConversationSummaryUpdateRequest,
    assistant_code: Optional[str] = Header(None), # for backward compatibility, set the assistant_code from header optional
    user: User = Depends(get_authenticated_user),
):
    # for backward compatibility, if assistant_code is available from header, use that one instead of the one in the request
    if assistant_code:
        summary.assistant_code = assistant_code
        
    return await update_summary_record(thread_id, user, summary)


@router.get("")
async def list_conversation_summary(
    page: int = Query(1, ge=1, description="Page number to fetch"),
    per_page: int = Query(10, ge=10, description="Number of records per page"),
    order_by: str = Query("updated_at desc", description="column name to be sorted with format \"field_name [asc|desc]\""),
    user: User = Depends(get_authenticated_user),
):
    """
    API to fetch the conversation history for a specific user based on user_id.
    """
    return await get_summary_records(user, page=page, per_page=per_page, order_by=order_by)


@router.delete("/{thread_id}")
async def delete_conversation_summary(
    thread_id: str,
    assistant_code: Optional[str] = Header(None), # for backward compatibility, set the assistant_code from header optional
    user: User = Depends(get_authenticated_user),
):
    if not await delete_summary_record(thread_id, user, assistant_code):
        raise HTTPException(status_code=404, detail="not_found")


# API to mark or unmark a conversation as favorite
@router.post("/{thread_id}/favorite")
async def update_conversation_favorite(
    thread_id: str,
    favorite_request: ConversationSummaryFavoriteRequest,
    user: User = Depends(get_authenticated_user),
):
    return await mark_conversation_favorite(thread_id, favorite_request, user)


# API to get a conversation by thread_id
@router.get("/{thread_id}")
async def get_conversation_summary(
    thread_id: str,
    user: User = Depends(get_authenticated_user),
):
    return await get_conversation_summary_details(thread_id, user)
