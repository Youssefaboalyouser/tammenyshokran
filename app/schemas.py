from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any
from datetime import datetime


# ── Auth ────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_id: Optional[int] = None
    email: Optional[EmailStr] = None


# ── Email Analysis ───────────────────────────────────────────────────────────

class NLPResult(BaseModel):
    label: str           # SPAM | HAM
    score: float         # model confidence
    is_spam: bool


class EmailAnalysisResponse(BaseModel):
    id: int
    filename: Optional[str]
    email_id: Optional[str]
    sender_email: Optional[str]
    sender_domain: Optional[str]
    subject: Optional[str]
    recipient: Optional[str]
    email_timestamp: Optional[str]
    parsed_data: Optional[Any]
    virustotal_data: Optional[Any]
    phishing_flags: Optional[list]
    nlp_result: Optional[dict]
    risk_score: Optional[float]
    verdict: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class EmailListItem(BaseModel):
    id: int
    filename: Optional[str]
    subject: Optional[str]
    sender_email: Optional[str]
    risk_score: Optional[float]
    verdict: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}
