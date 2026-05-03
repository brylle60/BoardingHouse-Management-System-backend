from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import bcrypt

# ---------------------------------------------------------------------------
# Password Hashing
# ---------------------------------------------------------------------------

class PasswordEncoder:
    def encode(self, raw_password: str) -> str:
        return bcrypt.hashpw(
            raw_password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

    def matches(self, raw_password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(
            raw_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )

password_encoder = PasswordEncoder()


# ---------------------------------------------------------------------------
# CORS Configuration
# ---------------------------------------------------------------------------

CORS_CONFIG = {
    "allow_origins": ["http://localhost:5173"],
    "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["*"],
    "allow_credentials": True,
}

def configure_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_CONFIG["allow_origins"],
        allow_methods=CORS_CONFIG["allow_methods"],
        allow_headers=CORS_CONFIG["allow_headers"],
        allow_credentials=CORS_CONFIG["allow_credentials"],
    )


# ---------------------------------------------------------------------------
# Route Access Rules
# ---------------------------------------------------------------------------

PUBLIC_ROUTES = {
    "/api/rooms/public/vacant",
    # ── Authentication endpoints ──────────────────────────────────────────
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/forgot-password",
    "/api/auth/verify-otp",
    "/api/auth/reset-password",

    # ── OAuth endpoints (future) ──────────────────────────────────────────
    "/api/auth/google",
    "/api/auth/google/callback",
 
    # ── Health check ──────────────────────────────────────────────────────
    "/health",
 
    # ── FastAPI auto-generated docs ───────────────────────────────────────
    # Remove "/docs", "/redoc", "/openapi.json" in production
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",

    "/room",
}

PROTECTED_ROUTES = {
    "/home",
    "/admin",
}