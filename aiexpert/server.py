from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler
from asyncio import run

from .azure.identity_utils import refresh_tokens as azure_identity_refresh_tokens

from .sql.schema import init as init_schema
from .sql.schema1 import init as init_schema1

from .utils.configurations import (
    ALLOWED_ORIGINS, 
    AZURE_IDENTITY_REFRESH_TOKEN_INTERVAL_IN_MINS, 
    DIAM_REFRESH_TOKEN_INTERVAL_IN_MINS
)

import importlib
import pkgutil

import logging

from . import routers

from pydantic import ValidationError

from .exception_handling.base import exception_handler
from .auth.base import AuthError

from .diam.service_account import refresh_token as diam_refresh_token

from apscheduler.schedulers.asyncio import AsyncIOScheduler

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
# run the job for the first time
    try: 
        log.info(f"Running refresh tokens for the first time")
        azure_identity_refresh_tokens()
        
        # await diam_refresh_token()
                
    except Exception:
        log.exception(f"Error in refreshing tokens")

    log.info(f"Starting scheduler to run refresh tokens")
    scheduler = BackgroundScheduler()
    scheduler.add_job(azure_identity_refresh_tokens, trigger="interval", name="Refresh Azure Identity tokens", minutes=AZURE_IDENTITY_REFRESH_TOKEN_INTERVAL_IN_MINS)
    scheduler.start()

    async_scheduler = AsyncIOScheduler()
    async_scheduler.add_job(diam_refresh_token, trigger="interval", name="Refresh DIAM token", minutes=DIAM_REFRESH_TOKEN_INTERVAL_IN_MINS)
    async_scheduler.start()
    
    log.info("Initializing SQL schema")
    await init_schema()
    await init_schema1()
    yield

    log.info(f"Shutting down scheduler for refresh tokens")
    scheduler.shutdown()
    async_scheduler.shutdown()


# validate user for all requests
app = FastAPI(lifespan=lifespan)

for error_type in [ValueError, ValidationError, AuthError]:
    app.add_exception_handler(error_type, exception_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# import all routers and include them in the app. Each module MUST have a FastAPI router variable
for _, module_name, _ in pkgutil.iter_modules(routers.__path__):
    module = importlib.import_module(f'{__package__}.routers.{module_name}')
    app.include_router(module.router)