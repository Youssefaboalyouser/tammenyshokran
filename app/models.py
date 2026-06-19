from .database import Base
from sqlalchemy import Column, Integer, String, Boolean, Float, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import text
from sqlalchemy.sql.sqltypes import TIMESTAMP


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, nullable=False, index=True)
    username = Column(String(50), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    password = Column(String, nullable=False)
    is_active = Column(Boolean, server_default="TRUE", nullable=False)
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=text("now()"), nullable=False
    )

    emails = relationship("EmailAnalysis", back_populates="owner", cascade="all, delete")


class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id = Column(Integer, primary_key=True, nullable=False, index=True)
    owner_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # File metadata
    filename = Column(String(255), nullable=True)
    email_id = Column(String(36), nullable=True)  # UUID from parser
    file_hash = Column(String(64), nullable=True, index=True)

    # Parsed email fields (snapshot)
    sender_email = Column(String(255), nullable=True)
    sender_domain = Column(String(255), nullable=True)
    subject = Column(Text, nullable=True)
    recipient = Column(String(255), nullable=True)
    email_timestamp = Column(String(50), nullable=True)

    # Analysis results (stored as JSON blobs)
    parsed_data = Column(JSON, nullable=True)
    virustotal_data = Column(JSON, nullable=True)
    phishing_flags = Column(JSON, nullable=True)   # list of flag strings
    nlp_result = Column(JSON, nullable=True)       # {label, score, is_spam}

    # Scoring
    risk_score = Column(Float, nullable=True)      # 0.0 – 100.0
    verdict = Column(String(20), nullable=True)    # SAFE | SUSPICIOUS | HIGH RISK

    # Record timestamps
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=text("now()"), nullable=False
    )

    owner = relationship("User", back_populates="emails")
