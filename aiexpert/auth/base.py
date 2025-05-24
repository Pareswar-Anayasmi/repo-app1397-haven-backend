from ..utils.configurations import (
    AUTHEN_HEADER_NAME,
    AUTHEN_OIDC_AUDIENCE,
    AUTHEN_OIDC_ISSUER,
    AUTHEN_OIDC_ISSUER_FOR_SERVICE_ACCOUNT,
    AUTHEN_OIDC_JWKS_URL,
    REQUIRE_AUTHEN,
    MOCK_USER_ID,
    MOCK_USER_EMAIL,
    MOCK_USER_GROUPS,
    MOCK_USER_GIVEN_NAME,
    MOCK_USER_FAMILY_NAME,
)

import jwt
import logging
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, Request

from pydantic import BaseModel, model_validator

from cachetools import TTLCache

log = logging.getLogger(__name__)

cache = TTLCache(maxsize=1000, ttl=120)

class User(BaseModel):
    id: str
    email: str
    sub: Optional[str] = None
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    groups: Optional[List[str]] = None
    data: Dict[str, Any]
    token: Optional[str] = None

    @model_validator(mode='before')  
    def extract_from_data(cls, values):
        data = values.get('data')

        if data and 'sub' in data:
            values['sub'] = data['sub']

        if data and 'groups' in data:
            values['groups'] = data['groups']

        values['family_name'] = ""
        values['given_name'] = ""
        
        values['email'] = None
        if data and 'external_claims' in data:
            external_claims = data['external_claims']
            if "azure:email" in external_claims:
                values['email'] = external_claims['azure:email'].lower()
                
                # Use email as id which will be easier for troubleshooting
                values['id'] = values['email']
                

            if "azure:given_name" in external_claims:
                values['given_name'] = external_claims['azure:given_name']                

            if "azure:family_name" in external_claims:
                values['family_name'] = external_claims['azure:family_name']
        
        elif "client_id" in data:
            # No email address for servie account
            values['id'] = data['client_id']
            values['email'] = values['id'] 
            
            if "user" in data:
                user = data['user']
                if "last_name" in user:
                    values['family_name'] = user["last_name"]
                if "first_name" in user:
                    values['given_name'] = user["first_name"] 
                
        values['name'] = f"{values['given_name']} {values['family_name']}".strip()
        
        if data and 'token' in data:
            values['token'] = data['token']
        
        return values

    def __str__(self) -> str:
        dict_self = dict(self)
        dict_self.pop("data")
        dict_self.pop("token")
        
        return str(dict_self)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

    def __str__(self) -> str:
        return self.error or ""


def get_user(token, use_cache=False, **kwargs) -> dict:

    user = cache.get(token, None)

    if user and use_cache:
        log.debug("User found in cache, returning user: %s", user)

    else:
        data = validate_token(token, **kwargs)
        if not data:
            raise AuthError(error="Invalid token", status_code=401)
        user = User(data=data)
        cache[token] = user

        log.debug("User data retrieved from token: %s", user)

    return user

def _get_user_from_headers(headers, use_cache=False, **kwargs) -> dict:
    token = _get_token_from_headers(headers)

    return get_user(token, use_cache=use_cache, **kwargs)

def _get_token_from_headers(headers) -> str:
    
    auth = headers.get(AUTHEN_HEADER_NAME)
    
    if auth:
        parts = auth.split()

        if parts[0].lower() != "bearer":
            raise AuthError(
                error=f"{AUTHEN_HEADER_NAME} header must start with Bearer", status_code=401)
        elif len(parts) == 1:
            raise AuthError(error="Token not found", status_code=401)
        elif len(parts) > 2:
            raise AuthError(
                error=f"{AUTHEN_HEADER_NAME} header must be Bearer token", status_code=401)

        token = parts[1]

        if token:
            return token

    raise AuthError(error=f"{AUTHEN_HEADER_NAME} header is expected", status_code=401)


def validate_token(token: str, **kwargs):
    if not jwt.algorithms.has_crypto:
        raise AuthError(error="No crypto support for JWT, please install the cryptography dependency", status_code=401)


    try:
        jwks_client = jwt.PyJWKClient(AUTHEN_OIDC_JWKS_URL, cache_jwk_set=True, cache_keys=True, lifespan=900)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=[AUTHEN_OIDC_ISSUER, AUTHEN_OIDC_ISSUER_FOR_SERVICE_ACCOUNT],
            audience=AUTHEN_OIDC_AUDIENCE,
            options={
                "verify_signature": kwargs.get("verify_signature", True),
                "verify_exp": kwargs.get("verify_exp", True),
                "verify_nbf": kwargs.get("verify_nbf", True),
                "verify_iat": kwargs.get("verify_iat", True),
                "verify_aud": kwargs.get("verify_aud", True),
                "verify_iss": kwargs.get("verify_iss", True),
            },
        )
        return data | {"token": token}

    except Exception:
        log.exception("Error in validating access token")
        raise AuthError(error="Error in validating access token", status_code=401)

def get_authenticated_user(request: Request) -> User:
    
    if REQUIRE_AUTHEN:
        user = _get_user_from_headers(request.headers, use_cache=True)
    else:
        
        log.critical(f"""******* ALERT: Authentication Disabled!! User {MOCK_USER_ID} is for local use only. Activate authentication by removing REQUIRE_AUTHEN environment variable for non local environment! *******""")

        user = User(data={
            "sub": MOCK_USER_ID,
            "groups": MOCK_USER_GROUPS,
            "external_claims": {
                "azure:email": MOCK_USER_EMAIL if MOCK_USER_EMAIL else f'{MOCK_USER_ID}@mock.com',
                "azure:given_name": MOCK_USER_GIVEN_NAME,
                "azure:family_name": MOCK_USER_FAMILY_NAME
            },
            "token": "==== mock token ===="
        })

        log.debug("Mock user Data: %s", user)

    return user

def validate_user(request: Request, **kwargs):
    if REQUIRE_AUTHEN:
        _get_user_from_headers(request.headers, use_cache=False, **kwargs)
