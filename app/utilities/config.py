import os
from pathlib import Path

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings


class Settings(BaseSettings):
    database_username: str = "postgres"
    database_password: str = "password"
    database_hostname: str = "localhost"
    database_port: str = "5432"
    database_name: str = "tamenny_db"
    secret_key: str = "changethissecretkey32charsminimum!!"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    virustotal_api_key: str = ""

    class Config:
        env_file = ".env"


settings = Settings()

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
PARSED_DIR = DATA_DIR / "parsed"
RESULTS_DIR = DATA_DIR / "results"
OUTPUT_DIR = DATA_DIR / "flags"

VIRUSTOTAL_API_KEY = settings.virustotal_api_key
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Public API rate limit ≈ 4 requests/min
REQUEST_DELAY = 18  # seconds between requests
