from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from mysql.connector.connection import MySQLConnection

from app.db.session import get_db
from app.repositories.auth_repository import AuthRepository
from app.services.auth_service import AuthService
from app.core.security import decode_token
from app.core.logger import get_logger

logger = get_logger("auth_deps")

# OAuth2 scheme for reading Bearer token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# -------------------------
# Repository Dependency
# -------------------------

def get_auth_repository(
    db: MySQLConnection = Depends(get_db)
) -> AuthRepository:
    return AuthRepository(db)


# -------------------------
# Service Dependency
# -------------------------

def get_auth_service(
    repository: AuthRepository = Depends(get_auth_repository)
) -> AuthService:
    return AuthService(repository)


# -------------------------
# Get Current User From JWT
# -------------------------

def get_current_user(
    token: str = Depends(oauth2_scheme),
    service: AuthService = Depends(get_auth_service)
):
    payload = decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    return service.get_current_user(int(user_id))


# -------------------------
# Refresh Token Dependency
# -------------------------

def get_refresh_user(
    token: str = Depends(oauth2_scheme),
    service: AuthService = Depends(get_auth_service)
):
    payload = decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    return int(user_id), token