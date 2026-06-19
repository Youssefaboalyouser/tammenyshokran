"""
main.py — Tamenny FastAPI Application
Serves the frontend via Jinja2 and registers all API routers.
Run with: uvicorn main:app --reload
"""

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app import models
from app.database import engine
from app.routers import auth, users, emails, messages

# ── Create DB tables on startup ───────────────────────────────────────────────
models.Base.metadata.create_all(bind=engine)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Tamenny",
    description="Scam & Phishing Detection Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ── CORS (allow all for local dev) ───────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static files + templates ──────────────────────────────────────────────────
import os
from pathlib import Path

# Ensure the static directory exists and mount it
static_path = Path(__file__).resolve().parent / "app" / "static"
if not static_path.exists():
    try:
        static_path.mkdir(parents=True, exist_ok=True)
        print(f"Created missing static directory: {static_path}")
    except Exception:
        # If we cannot create it, skip mounting to avoid startup failure
        print(f"Warning: could not create static directory: {static_path}")

if static_path.is_dir():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

templates = Jinja2Templates(directory="app/templates")

# ── API Routers ───────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(emails.router)
app.include_router(messages.router)

# ── Frontend route — serves index.html for all non-API paths ─────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_frontend(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Catch-all so browser refresh on any sub-path still works
@app.get("/{full_path:path}", response_class=HTMLResponse)
async def catch_all(request: Request, full_path: str):
    # Don't catch API paths
    if full_path.startswith("api/"):
        from fastapi import HTTPException
        raise HTTPException(status_code=404)
    return templates.TemplateResponse("index.html", {"request": request})
