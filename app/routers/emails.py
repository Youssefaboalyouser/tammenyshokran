"""
emails.py — Email analysis router
Handles .eml upload, full analysis pipeline, history, and PDF download.
"""

import asyncio
import hashlib
from typing import Optional, List
from fastapi import (
    APIRouter, Depends, HTTPException, UploadFile, File,
    status, Query
)
from fastapi.responses import StreamingResponse
import io
from sqlalchemy.orm import Session

from .. import schemas, models
from ..database import get_db
from ..utilities.oauth2 import get_current_user
from ..services.emailParser import parse_eml_bytes
from ..services.aggregator import run_virustotal_analysis
from ..services.phishing_detector import analyze_email, compute_risk_score, verdict_from_score
from ..services.nlp_model import predict_spam
from ..services.pdf_report import generate_pdf

router = APIRouter(prefix="/api/emails", tags=["Emails"])

MAX_EML_SIZE = 10 * 1024 * 1024  # 10 MB


# ── Upload + full analysis ────────────────────────────────────────────────────

@router.post("/analyze", response_model=schemas.EmailAnalysisResponse, status_code=status.HTTP_201_CREATED)
async def analyze_eml(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Upload a .eml file and run the full Tamenny analysis pipeline:
    1. Parse EML → structured dict
    2. Run VirusTotal on links + attachments (if any)
    3. Run rule-based phishing detector
    4. Run NLP spam classifier on body text
    5. Compute risk score + verdict
    6. Persist to database and return result
    """
    if not file.filename.endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .eml files are accepted",
        )

    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_EML_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds 10 MB limit",
        )

    file_hash = hashlib.sha256(raw_bytes).hexdigest()
    duplicate = db.query(models.EmailAnalysis).filter(
        models.EmailAnalysis.owner_id == current_user.id,
        models.EmailAnalysis.file_hash == file_hash,
    ).first()
    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This .eml file has already been uploaded",
        )

    # ── Step 1: Parse EML ────────────────────────────────────────────────────
    try:
        parsed = parse_eml_bytes(raw_bytes)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse EML file: {e}",
        )

    # ── Step 2: VirusTotal (links + attachments) ─────────────────────────────
    vt_result = None
    has_links = bool(parsed.get("links"))
    has_attachments = bool(parsed.get("attachments"))

    if has_links or has_attachments:
        # Run in thread pool to avoid blocking event loop
        vt_result = await asyncio.get_event_loop().run_in_executor(
            None, run_virustotal_analysis, parsed
        )

    # ── Step 3: Phishing detector ─────────────────────────────────────────────
    phishing_result = analyze_email(parsed, vt_result)
    flags: list = phishing_result.get("rule_based", {}).get("flags", [])

    # ── Step 4: NLP spam classification ──────────────────────────────────────
    body = parsed.get("body", {})
    text_for_nlp = (
        body.get("plain_text")
        or body.get("html", "")
        or parsed.get("subject", "")
        or ""
    )
    # Strip HTML tags roughly for NLP input
    import re
    text_for_nlp = re.sub(r"<[^>]+>", " ", text_for_nlp).strip()

    nlp_result = await asyncio.get_event_loop().run_in_executor(
        None, predict_spam, text_for_nlp
    )

    # ── Step 5: Score + verdict ───────────────────────────────────────────────
    risk_score = compute_risk_score(
        flags=flags,
        nlp_is_spam=nlp_result["is_spam"],
        nlp_score=nlp_result["score"],
    )
    verdict = verdict_from_score(risk_score)

    # ── Step 6: Persist ───────────────────────────────────────────────────────
    sender = parsed.get("sender", {}) or {}
    record = models.EmailAnalysis(
        owner_id=current_user.id,
        filename=file.filename,
        file_hash=file_hash,
        email_id=parsed.get("email_id"),
        sender_email=sender.get("email"),
        sender_domain=sender.get("domain"),
        subject=parsed.get("subject"),
        recipient=parsed.get("recipient"),
        email_timestamp=parsed.get("timestamp"),
        parsed_data=parsed,
        virustotal_data=vt_result,
        phishing_flags=flags,
        nlp_result=nlp_result,
        risk_score=risk_score,
        verdict=verdict,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


# ── List user's email analyses ────────────────────────────────────────────────

@router.get("", response_model=List[schemas.EmailListItem])
@router.get("/", response_model=List[schemas.EmailListItem])
def list_analyses(
    verdict_filter: Optional[str] = Query(None, description="SAFE | SUSPICIOUS | HIGH RISK"),
    limit: int = Query(4, le=100),
    skip: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    query = db.query(models.EmailAnalysis).filter(
        models.EmailAnalysis.owner_id == current_user.id
    )
    if verdict_filter:
        query = query.filter(models.EmailAnalysis.verdict == verdict_filter.upper())
    # Return the earliest N analyses (oldest first) so the frontend's
    # "Load" control can request the earliest activities in the account.
    return (
        query.order_by(models.EmailAnalysis.created_at.asc())
        .offset(skip)
        .limit(limit)
        .all()
    )


# ── Get single analysis ───────────────────────────────────────────────────────

@router.get("/{analysis_id}", response_model=schemas.EmailAnalysisResponse)
def get_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    record = (
        db.query(models.EmailAnalysis)
        .filter(
            models.EmailAnalysis.id == analysis_id,
            models.EmailAnalysis.owner_id == current_user.id,
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return record


# ── Delete analysis ───────────────────────────────────────────────────────────

@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    record = (
        db.query(models.EmailAnalysis)
        .filter(
            models.EmailAnalysis.id == analysis_id,
            models.EmailAnalysis.owner_id == current_user.id,
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Analysis not found")
    db.delete(record)
    db.commit()


# ── PDF download ──────────────────────────────────────────────────────────────

@router.get("/{analysis_id}/pdf")
def download_pdf(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    record = (
        db.query(models.EmailAnalysis)
        .filter(
            models.EmailAnalysis.id == analysis_id,
            models.EmailAnalysis.owner_id == current_user.id,
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis_dict = {
        "id": record.id,
        "filename": record.filename,
        "subject": record.subject,
        "sender_email": record.sender_email,
        "sender_domain": record.sender_domain,
        "recipient": record.recipient,
        "email_timestamp": record.email_timestamp,
        "phishing_flags": record.phishing_flags,
        "nlp_result": record.nlp_result,
        "virustotal_data": record.virustotal_data,
        "risk_score": record.risk_score,
        "verdict": record.verdict,
    }

    pdf_bytes = generate_pdf(analysis_dict)

    filename = f"tamenny_report_{analysis_id}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
