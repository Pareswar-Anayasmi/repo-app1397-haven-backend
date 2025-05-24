from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, Response
import logging

from ..authen_token.base import save_tokens, get_tokens, delete_tokens

from ..utils.crypto import encrypt, decrypt, generate_secret_key

from ..utils.configurations import (
    SESSION_COOKIE_ENCRYPTION_KEY, 
    FRONTEND_URL, 
    FRONTEND_LANDING_PATH,
    SESSION_COOKIE_FOR_DEVELOPMENT, 
    SESSION_COOKIE_DOMAIN,
    AUTHEN_OIDC_REDIRECT_URI,
    AUTHEN_OIDC_CLIENT_ID,
    AUTHEN_OIDC_LOGIN_URL
)

from ..auth.base import AuthError

from pydantic import BaseModel


log = logging.getLogger(__name__)

router = APIRouter(prefix=f"/{__name__.replace(__package__ + '.', '')}", tags=["Authentication"])

REDIRECT_PATH_COOKIE_NAME = "after_login_redirect"
TOKEN_KEY_COOKIE_NAME = "token_key"

OIDC_LOGIN_PATH = AUTHEN_OIDC_LOGIN_URL + (f"?redirect_uri={AUTHEN_OIDC_REDIRECT_URI}&client_id={AUTHEN_OIDC_CLIENT_ID}")

class TokenRequest(BaseModel):
    enc_token_id: str


@router.post("/token")
async def get_token_from_cookie(request: Request):
    """
    Get token by session cookie
    """
    enc_token_id = request.cookies.get(TOKEN_KEY_COOKIE_NAME)
    
    if not enc_token_id:
        log.error("No token_key in the cookie")
        raise AuthError(status_code=401, error="session_expired")

    try:
        return await _get_token(enc_token_id)
    except Exception as e:
        log.exception("Error in getting token from cookie")   
        # treat as session expired 
        raise AuthError(status_code=401, error="session_expired")

async def _get_token(enc_token_id: str):
    token_id = decrypt(bytes.fromhex(enc_token_id), SESSION_COOKIE_ENCRYPTION_KEY)
    return JSONResponse(
        content={
            "access_token": await get_tokens(token_id)
        }, 
        headers={"Cache-Control": "no-cache"})

    
@router.get("/callback")
async def diam_callback(access_token: str, refresh_token: str, request: Request):

    """
    A callback endpoint for DIAM which receives the access token and refresh token. Then, redirect to the frontend with session cookie.
    """

    error = None
    try:
        token_id, _ = await save_tokens(None, access_token, refresh_token)

        encrypted_token_id = encrypt(token_id, SESSION_COOKIE_ENCRYPTION_KEY).hex()
    except AuthError as e:
        log.exception("AuthError is raised in saving tokens")
        error = "session_expired" if e.status_code == 401 else "unauthorized"
    except Exception as e:
        log.exception("Unkown error is raised in saving tokens")
        error = "unknown_error"

    if error:
        response = RedirectResponse(url=FRONTEND_URL + FRONTEND_LANDING_PATH + f"?error={error}" , headers={"Cache-Control": "no-cache"}, status_code=301)
    else:

        after_login_redirect = request.cookies.get(REDIRECT_PATH_COOKIE_NAME) or ""
        
        response = RedirectResponse(url=FRONTEND_URL + after_login_redirect, headers={"Cache-Control": "no-cache"}, status_code=301)
        _self_domain_cookie(REDIRECT_PATH_COOKIE_NAME, response, is_delete=True)
        _wildcard_domain_cookie(TOKEN_KEY_COOKIE_NAME, response, is_delete=False, value=encrypted_token_id)
        
    return response

@router.get("/login")
async def login(redirect_path: str = ""):
        
    log.debug("Redirect to OIDC login page: %s", OIDC_LOGIN_PATH)
    response = RedirectResponse(url=OIDC_LOGIN_PATH, headers={"Cache-Control": "no-cache"}, status_code=301)
    
    if redirect_path:
        _self_domain_cookie(REDIRECT_PATH_COOKIE_NAME, response, is_delete=False, value=redirect_path)

    _wildcard_domain_cookie(TOKEN_KEY_COOKIE_NAME, response, is_delete=True)
    
    return response

@router.get("/logout")
async def logout(request: Request, error: str = None, redirect_path: str = None, message: str = None):
    """
    Logout and delete the token. This only logout the user from the AI Expert Assistant. The user is still logged in the DIAM or Azure.
    """
    
    token_key = request.cookies.get(TOKEN_KEY_COOKIE_NAME)
    
    if token_key:
        # try to delete the token
        try:
            token_id = decrypt(bytes.fromhex(token_key), SESSION_COOKIE_ENCRYPTION_KEY)
            await delete_tokens(token_id)
        except Exception as e:
            log.exception("Error in deleting token")
            # ignore the error and continue to delete the cookie
    
    param = "?message=logged_out"
    if error:
        param = f"?error={error}"
    elif message:
        param = f"?message={message}"
        
    return_url = FRONTEND_URL + FRONTEND_LANDING_PATH + param
    if error == "session_expired":
        # try to login directly if the error is just session expired
        return_url = OIDC_LOGIN_PATH
        
    response = RedirectResponse(url=return_url, headers={"Cache-Control": "no-cache"}, status_code=301)
    
    if redirect_path:
        _self_domain_cookie(REDIRECT_PATH_COOKIE_NAME, response, is_delete=False, value=redirect_path)
    else:
        _self_domain_cookie(REDIRECT_PATH_COOKIE_NAME, response, is_delete=True)
    
    _wildcard_domain_cookie(TOKEN_KEY_COOKIE_NAME, response, is_delete=True)
    return response

@router.post("/key")
async def generate_key(request: Request):
    return generate_secret_key()

def _self_domain_cookie(cookie_name, response: Response, is_delete: bool, value: str = None):
    secure = True 
    samesite = "none" 
        
    if SESSION_COOKIE_FOR_DEVELOPMENT:
        secure = False
        samesite = "lax"

    if is_delete:
        response.delete_cookie(key=cookie_name, secure=secure, httponly=True, samesite=samesite)
    else:
        response.set_cookie(key=cookie_name, value=value, secure=secure, httponly=True, samesite=samesite)

def _wildcard_domain_cookie(cookie_name, response: Response, is_delete: bool, value: str = None):
    secure = True 
    samesite = "none" 
    domain = SESSION_COOKIE_DOMAIN

    if SESSION_COOKIE_FOR_DEVELOPMENT:
        secure = False
        samesite = "lax"
        domain = None

    if is_delete:
        response.delete_cookie(key=cookie_name, secure=secure, httponly=True, samesite=samesite, domain=domain)
    else:
        response.set_cookie(key=cookie_name, value=value, secure=secure, httponly=True, samesite=samesite, domain=domain)
