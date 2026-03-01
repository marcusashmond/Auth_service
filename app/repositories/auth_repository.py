from typing import Optional
from datetime import datetime
from mysql.connector.connection import MySQLConnection

from app.models.user import User
from app.core.logger import get_logger

logger = get_logger("auth_repository")


class AuthRepository:

    def __init__(self, db: MySQLConnection):
        self.db = db

    # -------------------------
    # Create User
    # -------------------------

    def create_user(
        self,
        first_name: str,
        last_name: str,
        email: str,
        hashed_password: str,
        otp: str
    ) -> int:
        cursor = self.db.cursor()
        query = """
            INSERT INTO users 
            (first_name, last_name, email, password, otp, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(
            query,
            (
                first_name,
                last_name,
                email,
                hashed_password,
                otp,
                datetime.utcnow()
            )
        )
        self.db.commit()
        user_id = cursor.lastrowid
        cursor.close()

        logger.info(f"User created with email: {email}")
        return user_id

    # -------------------------
    # Get User By Email
    # -------------------------

    def get_user_by_email(self, email: str) -> Optional[User]:
        cursor = self.db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cursor.fetchone()
        cursor.close()

        if row:
            return User(**row)
        return None

    # -------------------------
    # Get User By ID
    # -------------------------

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        cursor = self.db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        cursor.close()

        if row:
            return User(**row)
        return None

    # -------------------------
    # Verify User OTP
    # -------------------------

    def verify_user(self, email: str):
        cursor = self.db.cursor()
        query = """
            UPDATE users
            SET is_verified = TRUE, otp = NULL
            WHERE email = %s
        """
        cursor.execute(query, (email,))
        self.db.commit()
        cursor.close()

        logger.info(f"User verified: {email}")

    # -------------------------
    # Store Refresh Token
    # -------------------------

    def store_refresh_token(self, user_id: int, refresh_token: str):
        cursor = self.db.cursor()
        query = """
            UPDATE users
            SET refresh_token = %s
            WHERE id = %s
        """
        cursor.execute(query, (refresh_token, user_id))
        self.db.commit()
        cursor.close()

    # -------------------------
    # Remove Refresh Token (Logout)
    # -------------------------

    def remove_refresh_token(self, user_id: int):
        cursor = self.db.cursor()
        query = """
            UPDATE users
            SET refresh_token = NULL
            WHERE id = %s
        """
        cursor.execute(query, (user_id,))
        self.db.commit()
        cursor.close()

    # -------------------------
    # Store Reset Token
    # -------------------------

    def store_reset_token(self, email: str, reset_token: str):
        cursor = self.db.cursor()
        query = """
            UPDATE users
            SET reset_token = %s
            WHERE email = %s
        """
        cursor.execute(query, (reset_token, email))
        self.db.commit()
        cursor.close()

        logger.info(f"Reset token generated for: {email}")

    # -------------------------
    # Get User By Reset Token
    # -------------------------

    def get_user_by_reset_token(self, reset_token: str) -> Optional[User]:
        cursor = self.db.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM users WHERE reset_token = %s",
            (reset_token,)
        )
        row = cursor.fetchone()
        cursor.close()

        if row:
            return User(**row)
        return None

    # -------------------------
    # Update Password
    # -------------------------

    def update_password(self, user_id: int, hashed_password: str):
        cursor = self.db.cursor()
        query = """
            UPDATE users
            SET password = %s, reset_token = NULL
            WHERE id = %s
        """
        cursor.execute(query, (hashed_password, user_id))
        self.db.commit()
        cursor.close()

        logger.info(f"Password updated for user_id: {user_id}")