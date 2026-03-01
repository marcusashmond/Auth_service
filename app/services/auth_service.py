from fastapi import HTTPException, status

from app.core.logger import get_logger
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    generate_otp,
    generate_reset_token
)
from app.models.user import User
from app.repositories.auth_repository import AuthRepository

logger = get_logger("auth_service")


class AuthService:

    def __init__(self, repository: AuthRepository):
        self.repository = repository

    # -------------------------
    # Register User
    # -------------------------
    def register_user(self, first_name: str, last_name: str, email: str, password: str) -> int:
        existing_user = self.repository.get_user_by_email(email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        hashed = hash_password(password)
        otp = generate_otp()
        user_id = self.repository.create_user(first_name, last_name, email, hashed, otp)
        logger.info(f"User registered: {email}, OTP: {otp}")
        return user_id, otp  # OTP would be emailed in real system

    # -------------------------
    # Verify OTP
    # -------------------------
    def verify_otp(self, email: str, otp: str):
        user = self.repository.get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.is_verified:
            raise HTTPException(status_code=400, detail="User already verified")
        if user.otp != otp:
            raise HTTPException(status_code=400, detail="Invalid OTP")

        self.repository.verify_user(email)
        logger.info(f"User verified successfully: {email}")

    # -------------------------
    # Login
    # -------------------------
    def login_user(self, email: str, password: str) -> dict:
        user = self.repository.get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not user.is_verified:
            raise HTTPException(status_code=401, detail="User not verified")
        if not verify_password(password, user.password):
            logger.warning(f"Failed login attempt: {email}")
            raise HTTPException(status_code=401, detail="Incorrect password")

        access_token = create_access_token({"sub": str(user.id)})
        refresh_token = create_refresh_token({"sub": str(user.id)})
        self.repository.store_refresh_token(user.id, refresh_token)

        logger.info(f"User logged in: {email}")
        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

    # -------------------------
    # Refresh Token
    # -------------------------
    def refresh_tokens(self, user_id: int, refresh_token: str) -> dict:
        user = self.repository.get_user_by_id(user_id)
        if not user or user.refresh_token != refresh_token:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        new_access_token = create_access_token({"sub": str(user.id)})
        new_refresh_token = create_refresh_token({"sub": str(user.id)})
        self.repository.store_refresh_token(user.id, new_refresh_token)

        logger.info(f"Tokens refreshed for user_id: {user.id}")
        return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}

    # -------------------------
    # Logout
    # -------------------------
    def logout_user(self, user_id: int):
        self.repository.remove_refresh_token(user_id)
        logger.info(f"User logged out: {user_id}")

    # -------------------------
    # Change Password
    # -------------------------
    def change_password(self, user_id: int, old_password: str, new_password: str):
        user = self.repository.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not verify_password(old_password, user.password):
            raise HTTPException(status_code=400, detail="Old password incorrect")

        hashed = hash_password(new_password)
        self.repository.update_password(user.id, hashed)
        logger.info(f"Password changed for user_id: {user.id}")

    # -------------------------
    # Forgot Password
    # -------------------------
    def forgot_password(self, email: str) -> str:
        user = self.repository.get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        reset_token = generate_reset_token()
        self.repository.store_reset_token(email, reset_token)
        logger.info(f"Reset token generated for: {email}")
        return reset_token  # Would be emailed in production

    # -------------------------
    # Reset Password
    # -------------------------
    def reset_password(self, reset_token: str, new_password: str):
        user = self.repository.get_user_by_reset_token(reset_token)
        if not user:
            raise HTTPException(status_code=400, detail="Invalid reset token")

        hashed = hash_password(new_password)
        self.repository.update_password(user.id, hashed)
        logger.info(f"Password reset for user_id: {user.id}")

    # -------------------------
    # Get Current User
    # -------------------------
    def get_current_user(self, user_id: int) -> User:
        user = self.repository.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user