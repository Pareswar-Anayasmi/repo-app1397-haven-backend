from azure.identity import DefaultAzureCredential
import logging
import time

from ..utils.configurations import DB_TOKEN_AUTHEN

from datetime import datetime

import pytz

log = logging.getLogger(__name__)

tokens = {}

credential = DefaultAzureCredential()

DB_SCOPE_ENDPOINT = "https://.database.windows.net/.default"

def get_db_token():
    return _get_token("db_token", DB_SCOPE_ENDPOINT)

def refresh_tokens():

    if DB_TOKEN_AUTHEN:
        _refresh_token("db_token", DB_SCOPE_ENDPOINT)
    else:
        log.debug("DB_TOKEN_AUTHEN is disabled, skip refreshing DB token")
        
def _format_datetime(dt):
    return datetime.fromtimestamp(dt, pytz.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')

def _get_token(token_key, scope):
    now_in_second = int(time.time())
    
    global tokens
    
    token = None

    if token_key in tokens:
        token = tokens[token_key]

    if token is None:
        log.debug("No existing token for %s...", scope)
        token = _refresh_token(token_key, scope)

    else:     
        log.debug("Token exists for %s (expired: %s, now: %s)", scope, _format_datetime(token.expires_on), _format_datetime(now_in_second))

        if now_in_second > token.expires_on - 60:
            log.debug("Existing token has been expired, get a new Azure AD token for %s...", scope)        
            token = _refresh_token(token_key, scope)

        else:       
            log.debug("Using cached Azure AD token for %s", scope)
    
    return token.token    

# Force refresh token
def _refresh_token(token_key, scope):
    now_in_second = int(time.time())
    
    global tokens
    
    token = credential.get_token(scope)
    tokens[token_key] = token
        
    log.debug("Got a new Azure AD token for %s (expires: %s, now: %s)", scope, _format_datetime(token.expires_on), _format_datetime(now_in_second))

    return token
