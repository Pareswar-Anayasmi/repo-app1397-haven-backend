from ..utils.crypto import encrypt, decrypt
import uuid
import time

from ..auth.base import get_user, User, AuthError

from ..sql.connection import async_session_maker
from sqlalchemy import select, update, and_

import base64

import ast

import httpx

from ..sql.schema import Users, GroupUsers

from ..diam.group_utils import add_user_to_group

from ..utils.configurations import (
    AUTHEN_TOKEN_ENCRYPTION_KEY,
    SYSTEM_GROUP_ID,
    AUTHEN_OIDC_CLIENT_ID,
    AUTHEN_OIDC_CLIENT_SECRET,
    AUTHEN_OIDC_TOKEN_ENDPOINT,
    AUTHEN_OIDC_REDIRECT_URI,
)


from ..sql.schema import AuthenTokens

from datetime import datetime, timedelta

import logging

log = logging.getLogger(__name__)

PRE_EXPIRY_BUFFER = timedelta(minutes=5)

async def delete_tokens(token_id: str):
    """
    Delete the token from the database
    """
    async with async_session_maker() as session:
        async with session.begin():
            result = await session.execute(
                select(AuthenTokens).where(AuthenTokens.session_key == token_id)
            )
            token: AuthenTokens = result.scalars().one_or_none()
            if not token:
                log.debug("Cannot find a token record with ID: %s", token_id)

            await session.delete(token)


async def _add_to_users(user: User):
    async with async_session_maker() as session:
        # add user to users table
        result = await session.execute(select(Users).where(Users.diam_user_id == user.sub))
        diam_user: Users = result.scalars().one_or_none()

        if not diam_user:
            log.debug("User %s cannot be found. Add to users table.", user.email)
            session.add(Users(diam_user_id=user.sub, email=user.email))
            await session.commit()
        else:
            log.debug("User %s is found in users table.", user.email)


def _token_has_system_group(access_token: str):
    user: User = get_user(access_token, use_cache=False, verify_aud=False)
    log.debug("Got user from token: %s", user)
    
    return user, (SYSTEM_GROUP_ID in user.groups)

async def _process_pending_invitation(user: User, has_system_group: bool):
    has_pending_invitation = False
    async with async_session_maker() as session:
        result = await session.execute(
            select(GroupUsers)
            .where(GroupUsers.email == user.email)
            .where(GroupUsers.status == "PENDING")
        )
        
        group_users: GroupUsers = result.scalars().all()
        
        log.debug("Pending group users: %s", [g.to_dict() for g in group_users])
        
        if group_users:
            has_pending_invitation = True
        
            await _add_to_users(user)
        
            pending_group_ids = [g.group_id for g in group_users]
                            
            if not has_system_group:
                # first add user to the system group
                await add_user_to_group(diam_user_id=user.sub, group_id=SYSTEM_GROUP_ID)
            
            for group_id in pending_group_ids:
                # call DIAM to add user into the group
                try:
                    ####
                    #
                    # IMPORTANT: Intentionally update the db record first before calling DIAM.
                    # This avoids DIAM call successful but db update failed which means a user
                    # can access the assistant without being shown in the group
                    #
                    ####
                    await session.execute(
                        update(GroupUsers)
                        .where(
                            and_(
                                GroupUsers.email == user.email,
                                GroupUsers.status == "PENDING",
                                GroupUsers.group_id == group_id,
                            )
                        )
                        .values(
                            status="CONFIRMED",
                            joined_at=datetime.now()
                        )
                    )
                    await session.commit()
                    await add_user_to_group(diam_user_id=user.sub, group_id=group_id)
                    
                    log.info("User (%s) has been added to the group (%s) successfully", user.email, group_id)

                except Exception:
                    log.exception("Error in adding user (%s) to the group (%s)", user.email, group_id)
    
    return has_pending_invitation

async def save_tokens(existing_token_id, access_token: str, refresh_token: str):
    """
    Verify the access token from the OAuth2 provider
    and store the encrypted access token and refresh token in the database

    return the token_id can be used to retrieve the tokens
    """
    
    # User may have been invited to join the app
    user, has_system_group = _token_has_system_group(access_token)
    log.debug("User has the required group (%s)? %s", SYSTEM_GROUP_ID, has_system_group)

    has_pending_invitation = await _process_pending_invitation(user, has_system_group)
    
    if not has_system_group and not has_pending_invitation:
        raise AuthError("User does not have the required permission", 403)
    
    force_refresh_token = False
    if has_pending_invitation:
        log.debug("New groups added to user: %s, force to refresh the token", user.id)
        force_refresh_token = True
        
    current_datetime = datetime.now().astimezone()
    expire_at = datetime.fromtimestamp(user.data.get("exp", 0)).astimezone()
    log.debug(
        "The token for the user: %s is expired at: %s. Current date time: %s. Pre-expiry buffer: %s ",
        user.id,
        expire_at,
        current_datetime,
        PRE_EXPIRY_BUFFER,
    )
    if expire_at < (current_datetime + PRE_EXPIRY_BUFFER):
        log.debug("The token for the user: %s is about to expire, force to refresh the token", user.id)
        force_refresh_token = True
        
    if force_refresh_token: 
        new_tokens = await _refresh_tokens(refresh_token)
        
        access_token = new_tokens["access_token"]
        refresh_token = new_tokens["refresh_token"]
        
    return await _save_tokens(user, existing_token_id, refresh_token), access_token

async def _save_tokens(user: User, existing_token_id: str, refresh_token: str):
    token_id = existing_token_id

    encrypted_tokens = encrypt(refresh_token, AUTHEN_TOKEN_ENCRYPTION_KEY)

    async with async_session_maker() as session:
        async with session.begin():

            if not existing_token_id:
                token_id = base64.b64encode(
                        (str(uuid.uuid4()) + str(int(time.time()))).encode()
                ).decode()
                    
                session.add(
                    AuthenTokens(
                        session_key=token_id,
                        encrypted_tokens=encrypted_tokens,
                    )
                )
            else:
                # update existing token
                result = await session.execute(
                    select(AuthenTokens).where(
                        AuthenTokens.session_key == token_id
                    )
                )
                token: AuthenTokens = result.scalars().one_or_none()
                if not token:
                    log.error("Cannot find a token record with ID: %s", token_id)
                    raise AuthError(
                        "Cannot find a token record.", 401
                    )  

                token.encrypted_tokens = encrypted_tokens
                token.refreshed_at = datetime.now()
            
    return token_id        


async def get_tokens(token_id: str):
    """
    Get token from DB by using token_id
    If the token is expired, try to refresh the token and a new token_id will be returned

    return access_token
    """
    # find the token in the database

    async with async_session_maker() as session:
        async with session.begin():
            result = await session.execute(
                select(AuthenTokens).where(AuthenTokens.session_key == token_id)
            )
            auth_token = result.scalars().one_or_none()
            if not auth_token:
                log.error("Cannot find a token record with ID: %s", token_id)
                raise AuthError(
                    "Cannot find a token record.", 401
                ) 

            # decrypt the token
            refresh_token = decrypt(auth_token.encrypted_tokens, AUTHEN_TOKEN_ENCRYPTION_KEY)

            new_token = await _refresh_tokens(refresh_token)
                
            access_token = new_token["access_token"]
            refresh_token = new_token["refresh_token"]

            _, access_token = await save_tokens(token_id, access_token, refresh_token)

            return access_token


async def _refresh_tokens(refresh_token: str):

    log.debug("Refreshing token with refresh token: %s", refresh_token)
    
    async with httpx.AsyncClient() as client:
        refreshed_token_response = await client.post(
            AUTHEN_OIDC_TOKEN_ENDPOINT,
            data={
                "client_id": AUTHEN_OIDC_CLIENT_ID,
                "grant_type": "refresh_token",
                "client_secret": AUTHEN_OIDC_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "redirect_uri": AUTHEN_OIDC_REDIRECT_URI,
            },
        )
        try:
            refreshed_token_response.raise_for_status()

            refreshed_tokens = refreshed_token_response.json()

            return refreshed_tokens
        except Exception as e:
            log.exception("Error in refreshing token")
            raise AuthError("Error in refreshing token", 401)
