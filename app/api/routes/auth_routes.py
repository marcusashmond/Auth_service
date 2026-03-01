from fastapi import APIRouter, Depends, status
from app.schemas.auth_schema import (
    RegisterRequest,
    LoginRequest,
    VerifyOTPRequest,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse
)
from app.api.deps import (
    get_auth_service,
    get_current_user,
    get_refresh_user
)
from app.services.auth_service import AuthService
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


# -------------------------
# Register
# -------------------------

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(
    request: RegisterRequest,
    service: AuthService = Depends(get_auth_service)
):
    user_id, otp = service.register_user(
        request.first_name,
        request.last_name,
        request.email,
        request.password
    )
    return {
        "message": "User registered successfully",
        "user_id": user_id,
        "otp": otp 
    }


# -------------------------
# Verify OTP
# -------------------------

@router.post("/verify-otp")
def verify_otp(
    request: VerifyOTPRequest,
    service: AuthService = Depends(get_auth_service)
):
    service.verify_otp(request.email, request.otp)
    return {"message": "Account verified successfully"}


# -------------------------
# Login
# -------------------------

@router.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    service: AuthService = Depends(get_auth_service)
):
    return service.login_user(request.email, request.password)


# -------------------------
# Refresh Token
# -------------------------

@router.post("/refresh", response_model=TokenResponse)
def refresh_tokens(
    refresh_data = Depends(get_refresh_user),
    service: AuthService = Depends(get_auth_service)
):
    user_id, refresh_token = refresh_data
    return service.refresh_tokens(user_id, refresh_token)


# -------------------------
# Logout
# -------------------------

@router.post("/logout")
def logout(
    current_user: User = Depends(get_current_user),
    service: AuthService = Depends(get_auth_service)
):
    service.logout_user(current_user.id)
    return {"message": "Logged out successfully"}


# -------------------------
# Change Password
# -------------------------

@router.post("/change-password")
def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    service: AuthService = Depends(get_auth_service)
):
    service.change_password(
        current_user.id,
        request.old_password,
        request.new_password
    )
    return {"message": "Password changed successfully"}


# -------------------------
# Forgot Password
# -------------------------

@router.post("/forgot-password")
def forgot_password(
    request: ForgotPasswordRequest,
    service: AuthService = Depends(get_auth_service)
):
    reset_token = service.forgot_password(request.email)
    return {
        "message": "Reset token generated",
        "reset_token": reset_token  # In production this would be emailed
    }


# -------------------------
# Reset Password
# -------------------------

@router.post("/reset-password")
def reset_password(
    request: ResetPasswordRequest,
    service: AuthService = Depends(get_auth_service)
):
    service.reset_password(request.reset_token, request.new_password)
    return {"message": "Password reset successfully"}


# -------------------------
# Get Current Logged In User
# -------------------------

@router.get("/me", response_model=UserResponse)
def get_me(
    current_user: User = Depends(get_current_user)
):
    return current_user