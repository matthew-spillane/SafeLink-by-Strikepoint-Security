from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import CORS_ORIGINS
from app.database import engine, Base
from app.routers import scan

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="PhishScan API",
    description="Phishing URL analysis and risk scoring API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
