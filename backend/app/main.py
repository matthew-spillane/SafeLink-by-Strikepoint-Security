import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.routers import scan

logger = logging.getLogger(__name__)

try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    logger.error("Failed to initialize database: %s", e)

app = FastAPI(
    title="SafeLink API",
    description="Phishing URL analysis and risk scoring API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://safe-link-by-strikepoint-security.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
