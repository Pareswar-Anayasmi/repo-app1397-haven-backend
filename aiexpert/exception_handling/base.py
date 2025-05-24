from fastapi.responses import JSONResponse
from fastapi import Request
import logging

from pydantic import ValidationError

from ..utils.configurations import HIDE_EXCEPTION_MESSAGE

from ..auth.base import AuthError

log = logging.getLogger(__name__)

async def exception_handler(request: Request, e: Exception):
    log.error("Caught exception in handler. %s", e)

    error_code = "unknown_error"
    error_message = str(e) 
    if len(e.args) > 1:
        error_code = e.args[1]
        error_message = e.args[0] 

    error_content = {
        "error_code": error_code,
        "error_message": error_message if not HIDE_EXCEPTION_MESSAGE else "<<hidden>>"
    }
    
    status_code = 500
                
    if isinstance(e, ValueError) or isinstance(e, ValidationError):
        status_code = 400
        error_content["error_code"] = "value_error" if error_code == "unknown_error" else error_code
        
    
    elif isinstance(e, AuthError):
        status_code = e.status_code
        error_content["error_code"] = "session_expired" if e.status_code == 401 else "unauthorized"
        
    return JSONResponse(status_code=status_code, content=error_content)