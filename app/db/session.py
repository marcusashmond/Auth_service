import mysql.connector
from mysql.connector import Error
from fastapi import HTTPException

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger("db")


def get_db():
    """
    Dependency that provides a MySQL connection
    and ensures it is properly closed after request.
    """
    try:
        connection = mysql.connector.connect(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            user=settings.DB_USER,
            password=settings.DB_PASSWORD,
            database=settings.DB_NAME,
            autocommit=False
        )

        if connection.is_connected():
            logger.info("Database connection established")

        yield connection

    except Error as e:
        logger.error(f"Database connection failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Database connection error")

    finally:
        try:
            if connection.is_connected():
                connection.close()
                logger.info("Database connection closed")
        except Exception:
            pass