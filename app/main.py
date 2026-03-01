from fastapi import FastAPI
from app.core.logger import setup_logger
from app.api.routes.auth_routes import router as auth_router

setup_logger()

app = FastAPI(title="Authentication Service")

app.include_router(auth_router)