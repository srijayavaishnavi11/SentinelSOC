from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from .database import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False)
    source_ip = Column(String(45), nullable=False)
    username = Column(String(100), nullable=True)
    destination_port = Column(Integer, nullable=True)
    severity = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(
        DateTime,
        nullable=False,
        server_default=func.now()
    )

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    risk_score = Column(Integer, nullable=False, default=0)
    source_ip = Column(String(45), nullable=False)
    username = Column(String(100), nullable=True)
    message = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="open")
    created_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now()
    )