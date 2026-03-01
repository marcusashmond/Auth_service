from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


# -------------------------
# Register
# -------------------------

class RegisterRequest(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=100)
    last_name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6)


# -------------------------
# Login
# -------------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# -------------------------
# Verify OTP
# -------------------------

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=4, max_length=10)


# -------------------------
# Change Password (Logged In)
# -------------------------

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6)


# -------------------------
# Forgot Password
# -------------------------

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


# -------------------------
# Reset Password
# -------------------------

class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str = Field(..., min_length=6)


# -------------------------
# Token Response
# -------------------------

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# -------------------------
# Safe User Response
# -------------------------

class UserResponse(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: EmailStr
    is_verified: bool
    created_at: datetime