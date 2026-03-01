from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class User:
    id: int
    first_name: str
    last_name: str
    email: str
    password: str
    is_verified: bool
    otp: Optional[str]
    reset_token: Optional[str]
    refresh_token: Optional[str]
    created_at: datetime