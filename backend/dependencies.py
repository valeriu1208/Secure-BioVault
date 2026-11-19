from typing import Any

from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer

from security import verify_access_token

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")


def current_user(request: Request, token: str = Depends(oauth2)) -> dict[str, Any]:
    return verify_access_token(token, request.app.state.jwt_public_key)