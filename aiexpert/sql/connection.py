from typing import Any
from ..azure.identity_utils import get_db_token
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import event
from tzlocal import get_localzone_name

from dateutil.parser import parse

from ..utils.configurations import DB_DB_NAME, DB_USER, DB_HOST, DB_PORT, DB_POOL_SIZE, DB_TOKEN_AUTHEN, DB_PASSWORD

import logging

from datetime import datetime, UTC

log = logging.getLogger(__name__)

def _get_password():
    return get_db_token() if DB_TOKEN_AUTHEN else DB_PASSWORD


def timestamptz_encoder(v):
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=UTC).isoformat()
    if isinstance(v, datetime):
        return v.astimezone(UTC).isoformat()
    if isinstance(v, str):
        return datetime.fromisoformat(v).astimezone(UTC).isoformat()
    raise ValueError


def timestamptz_decoder(s):
    return parse(s)

engine = create_async_engine(
    f"postgresql+asyncpg://{DB_USER}:{{password}}@{DB_HOST}:{DB_PORT}/{DB_DB_NAME}", 
    pool_size=DB_POOL_SIZE, 
    pool_recycle=3600,
    pool_pre_ping=True
)

@event.listens_for(engine.sync_engine, "do_connect")
def before_connect(dialect, conn_rec, cargs, cparams):
    log.debug("before_connect is invoked, injecting token into connection params")
    cparams["password"] = _get_password()

@event.listens_for(engine.sync_engine, "connect")
def update_connection(dbapi_connection, connection_record):
    log.debug("update_connection is invoked, set timezone to %s and set encoder/decoder", get_localzone_name())
    dbapi_connection.run_async(
        lambda connection: connection.execute(f"SET TIME ZONE '{get_localzone_name()}';")
    )    

    dbapi_connection.run_async(
        lambda connection: connection.set_type_codec(
            typename="timestamptz", 
            schema='pg_catalog',
            encoder=timestamptz_encoder,
            decoder=timestamptz_decoder,
        )
    )

def get_async_db_engine():
    return engine

async_session_maker = async_sessionmaker(engine)
