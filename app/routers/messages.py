"""
messages.py — WhatsApp / SMS analysis router
Accepts raw message text (no EML), extracts links, runs VT + NLP.
No phishing detector (email-only feature).
"""

import asyncio
import re
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..utilities.oauth2 import get_current_user
from ..services.virustotal import scan_url
from ..services.nlp_model import predict_spam
from ..services.phishing_detector import compute_risk_score, verdict_from_score

router = APIRouter(prefix="/api/messages", tags=["Messages"])

# ── Schemas (inline — simple enough) ─────────────────────────────────────────

class MessageAnalyzeRequest(BaseModel):
    channel: str          # "sms" | "whatsapp"
    sender: Optional[str] = None
    receiver: Optional[str] = None
    content: str


class MessageAnalysisResponse(BaseModel):
    channel: str
    sender: Optional[str]
    receiver: Optional[str]
    content_preview: str
    links: List[str]
    vt_results: List[dict]
    nlp_result: dict
    risk_score: float
    verdict: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_links(text: str) -> List[str]:
    urls = re.findall(r'https?://[^\s\'"<>]+', text)
    seen: set = set()
    return [u for u in urls if not (u in seen or seen.add(u))]


# ── Route ─────────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=MessageAnalysisResponse)
async def analyze_message(
    payload: MessageAnalyzeRequest,
    current_user: models.User = Depends(get_current_user),
):
    channel = payload.channel.lower()
    if channel not in ("sms", "whatsapp"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="channel must be 'sms' or 'whatsapp'",
        )
    if not payload.content or not payload.content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="content must not be empty",
        )

    links = _extract_links(payload.content)

    # ── VirusTotal (only if links present) ───────────────────────────────────
    vt_results: List[dict] = []
    if links:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(None, scan_url, url) for url in links]
        vt_results = list(await asyncio.gather(*tasks))

    # ── NLP ───────────────────────────────────────────────────────────────────
    nlp_result = await asyncio.get_event_loop().run_in_executor(
        None, predict_spam, payload.content
    )

    # ── Score — no phishing flags for SMS/WA ─────────────────────────────────
    # Build simple flag list from VT results
    vt_flags = []
    for r in vt_results:
        if r.get("verdict") == "malicious":
            vt_flags.append("Malicious link detected by VirusTotal")
        elif r.get("verdict") == "suspicious":
            vt_flags.append("Suspicious link detected by VirusTotal")

    risk_score = compute_risk_score(
        flags=vt_flags,
        nlp_is_spam=nlp_result["is_spam"],
        nlp_score=nlp_result["score"],
    )
    verdict = verdict_from_score(risk_score)

    return MessageAnalysisResponse(
        channel=channel,
        sender=payload.sender,
        receiver=payload.receiver,
        content_preview=payload.content[:200],
        links=links,
        vt_results=vt_results,
        nlp_result=nlp_result,
        risk_score=risk_score,
        verdict=verdict,
    )
