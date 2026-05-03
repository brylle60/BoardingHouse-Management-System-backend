from pydantic import BaseModel
from typing import Optional


class LoginResponse(BaseModel):
    message:       str
    username:      str
    access_token:  str
    refresh_token: str
    token_type:    str           = "Bearer"
    role:          Optional[str] = None  # ← added: admin redirect
    id:            Optional[str] = None  # ← added: user session
    email:         Optional[str] = None  # ← added: user session