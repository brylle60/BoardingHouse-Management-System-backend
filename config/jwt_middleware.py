from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from config.jwt_config import JwtConfig, JwtSettings
from config.security_config import PUBLIC_ROUTES


# Reusable HTTP Bearer extractor (FastAPI equivalent of reading Authorization header)
bearer_scheme = HTTPBearer(auto_error=False)

# Initialise JWT config from env/.env file
_jwt_settings = JwtSettings()
jwt_config = JwtConfig(_jwt_settings)


class JwtAuthMiddleware(BaseHTTPMiddleware):
    """
    Equivalent to the Spring Security filter chain configured in SecurityConfig.
    - Allows PUBLIC_ROUTES through without a token.
    - Rejects all other requests without a valid Bearer token.
    - Stores the authenticated username on request.state (equivalent to SecurityContextHolder).
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Permit public routes - mirrors .permitAll() in SecurityConfig
        if path in PUBLIC_ROUTES or any(path.startswith(p) for p in ["/css/", "/js/"]):
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
            username = jwt_config.get_username_from_token(token)
            if not username:
                raise ValueError("Empty subject")
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Invalid or expired token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Store authenticated user on request state
        # Equivalent to SecurityContextHolder.getContext().setAuthentication(auth)
        request.state.username = username
        request.state.authenticated = True

        return await call_next(request)


# ---------------------------------------------------------------------------
# Dependency: get current user (use in route handlers like @AuthenticationPrincipal)
# ---------------------------------------------------------------------------

def get_current_user(request: Request) -> str:
    """
    FastAPI dependency - equivalent to injecting Authentication / @AuthenticationPrincipal
    in a Spring controller method.

    Usage:
        @router.get("/protected")
        def protected(username: str = Depends(get_current_user)):
            ...
    """
    if not getattr(request.state, "authenticated", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return request.state.username