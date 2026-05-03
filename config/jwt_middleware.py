from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from typing import Callable

from config.jwt_config import JwtConfig, JwtSettings
from config.security_config import PUBLIC_ROUTES


# Reusable HTTP Bearer extractor
bearer_scheme = HTTPBearer(auto_error=False)

# Initialise JWT config from env/.env file
_jwt_settings = JwtSettings()
jwt_config = JwtConfig(_jwt_settings)


class JwtAuthMiddleware(BaseHTTPMiddleware):
    """
    Allows PUBLIC_ROUTES through without a token.
    Rejects all other requests without a valid Bearer token.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Permit public routes
        if (
            path in PUBLIC_ROUTES
            or path.startswith("/api/auth/google")
            or any(path.startswith(p) for p in ["/css/", "/js/"])
        ):
            return await call_next(request)

        # Extract Bearer token
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Missing or invalid Authorization header"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header.split(" ", 1)[1]

        try:
            claims = jwt_config._get_all_claims(token)
            username = claims.get("sub")
            if not username:
                raise ValueError("Empty subject")

            # Extract roles from token claims (stored as list of strings e.g. ["ADMIN"])
            roles = claims.get("roles", [])

        except Exception:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Invalid or expired token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Store authenticated user and roles on request state
        request.state.username      = username
        request.state.roles         = roles
        request.state.authenticated = True

        return await call_next(request)


# ---------------------------------------------------------------------------
# Dependency: get current user
# ---------------------------------------------------------------------------

def get_current_user(request: Request) -> dict:
    if not getattr(request.state, "authenticated", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return {
        "username": request.state.username,
        "roles":    request.state.roles,
    }


# ---------------------------------------------------------------------------
# Dependency factory: require specific roles
# ---------------------------------------------------------------------------

def require_roles(*allowed_roles) -> Callable:
    """
    Returns a FastAPI dependency that enforces role-based access.

    Usage:
        current_user = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER))

    The token must contain a 'roles' claim (list of role name strings).
    Roles are matched by their .value if they are enums, or as plain strings.
    """
    # Normalize to string values so both enums and plain strings work
    allowed = {r.value if hasattr(r, "value") else str(r) for r in allowed_roles}

    def dependency(request: Request) -> dict:
        if not getattr(request.state, "authenticated", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )

        user_roles = set(request.state.roles or [])

        if not user_roles.intersection(allowed):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {allowed}",
            )

        return {
            "username": request.state.username,
            "roles":    request.state.roles,
        }

    return dependency