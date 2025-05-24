import requests

from ..utils.configurations import (
    DIAM_SERVICE_ACCOUNT_CLIENT_ID,
    DIAM_SERVICE_ACCOUNT_CLIENT_SECRET,
    DIAM_API_ENDPOINT_BASE_URL,
)

import logging

from datetime import datetime, timedelta

import httpx


log = logging.getLogger(__name__)

_CACHED_TOKEN = {}

# refresh token earlier than its expiration time
PRE_EXPIRY_BUFFER = timedelta(minutes=130)

def _format_datetime(dt):
    return dt.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')

async def get_token():
    """
    Get the access token, refreshing it if necessary.
    """
    global _CACHED_TOKEN

    current_datetime = datetime.now()

    if _CACHED_TOKEN:
        # Check if the token is expired
        
        expires_at = _CACHED_TOKEN.get("expires_at")
        if expires_at:
            if current_datetime < expires_at - PRE_EXPIRY_BUFFER:
                log.debug("Using cached token. Token expires at: %s, now: %s", _format_datetime(expires_at), _format_datetime(current_datetime))
                return _CACHED_TOKEN["access_token"]
            else:
                log.debug("Cached token expired at: %s, now: %s. Refreshing token.", _format_datetime(expires_at), _format_datetime(current_datetime))

    # If no valid cached token, refresh it
    log.debug("No cached token found or token expired. Refreshing token.")
    await _get_service_account_token()

    return _CACHED_TOKEN["access_token"]

async def refresh_token():
    """
    Force refresh the access token regardless of its expiration status.
    """
    await _get_service_account_token()
    return _CACHED_TOKEN["access_token"]

async def _get_service_account_token():
    """
    Get the service account token
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            # DIAM_API_ENDPOINT_BASE_URL + "/oauth2/token",
            DIAM_API_ENDPOINT_BASE_URL+"/oauth2/v2.0/token",
           
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": DIAM_SERVICE_ACCOUNT_CLIENT_ID,
                "client_secret": DIAM_SERVICE_ACCOUNT_CLIENT_SECRET,
                
            },
        )
        
        response.raise_for_status()

        global _CACHED_TOKEN
        token_data = response.json()

        # Add expiration time to cached token

        current_datetime = datetime.now()

        expires_in = token_data.get("expires_in", 3600)  # Default to 1 hour if not provided
        token_data["expires_at"] = current_datetime + timedelta(seconds=expires_in)

        _CACHED_TOKEN = token_data

        log.debug("Token refreshed successfully. New token expires at: %s, now: %s", _format_datetime(token_data["expires_at"]), _format_datetime(current_datetime))
