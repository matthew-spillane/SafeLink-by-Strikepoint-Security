import logging
from sqlalchemy import inspect, text

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.routers import scan

logger = logging.getLogger(__name__)

try:
    Base.metadata.create_all(bind=engine)
    # Migrate existing databases: add session_id column if missing
    insp = inspect(engine)
    columns = [c["name"] for c in insp.get_columns("scans")]
    if "session_id" not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE scans ADD COLUMN session_id VARCHAR"))
        logger.info("Migrated: added session_id column to scans table")
except Exception as e:
    logger.error("Failed to initialize database: %s", e)

app = FastAPI(
    title="SafeLink API",
    description="Phishing URL analysis and risk scoring API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
