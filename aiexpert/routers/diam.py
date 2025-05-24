from fastapi import APIRouter, Depends
import logging

from ..diam.group_utils import get_groups as get_diam_groups

log = logging.getLogger(__name__)

router = APIRouter(
    prefix=f"/{__name__.replace(__package__ + '.', '')}", tags=["DIAM Related APIs"]
)

@router.get("/internal/groups")
async def get_all_groups():
    """
    Internal API endpoint to list all groups.
    """
    
    return await get_diam_groups()
