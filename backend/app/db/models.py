from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, Text,
    DateTime, ForeignKey, JSON, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from app.db.base import Base


class ChannelType(str, enum.Enum):
    email = "email"
    sms = "sms"
    chat = "chat"
    url = "url"


class VerdictType(str, enum.Enum):
    safe = "safe"
    suspicious = "suspicious"
    scam = "scam"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    channel = Column(SAEnum(ChannelType), nullable=False, default=ChannelType.chat)
    input_text = Column(Text, nullable=False)
    input_url = Column(String(2048), nullable=True)

    # Results
    verdict = Column(SAEnum(VerdictType), nullable=False)
    risk_score = Column(Float, nullable=False)          # 0.0 – 1.0
    ml_score = Column(Float, nullable=True)
    rule_score = Column(Float, nullable=True)
    reasons = Column(JSON, nullable=False, default=list)
    highlighted_tokens = Column(JSON, nullable=False, default=list)

    # Metadata
    user_feedback = Column(String(20), nullable=True)   # correct / false_positive / false_negative
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    flags = relationship("ScanFlag", back_populates="scan", cascade="all, delete-orphan")


class ScanFlag(Base):
    """Individual flag entries linked to a scan — one row per triggered rule/pattern."""
    __tablename__ = "scan_flags"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"))
    flag_type = Column(String(50))   # keyword | url | pattern | ml
    value = Column(String(500))      # the matched token or pattern
    weight = Column(Float)           # contribution to risk score
    description = Column(String(300))

    scan = relationship("Scan", back_populates="flags")


class Rule(Base):
    """DB-backed rule engine — editable without redeployment."""
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    pattern = Column(String(500), nullable=False)       # regex or keyword
    pattern_type = Column(String(20), default="keyword")  # keyword | regex | combo
    weight = Column(Float, default=0.2)                 # added to risk score
    description = Column(String(300))
    category = Column(String(50))                       # urgency | phishing | financial | otp
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SuspiciousDomain(Base):
    """Known bad / free / shortener domains."""
    __tablename__ = "suspicious_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(253), unique=True, nullable=False)
    reason = Column(String(100))    # shortener | free_tld | known_phishing
    risk_weight = Column(Float, default=0.3)
    added_at = Column(DateTime(timezone=True), server_default=func.now())
