from fastapi import APIRouter
import logging
from pydantic import BaseModel

from aiexpert.utils.configurations import SYSTEM_GROUP_ID

from ..initialization.base import run

log = logging.getLogger(__name__)

router = APIRouter(
    prefix=f"/{__name__.replace(__package__ + '.', '')}", tags=["Initialization"]
)

class InitializationRequest(BaseModel):
    owner_email: str
    
@router.post("")
async def init(request: InitializationRequest):
    await run(request)