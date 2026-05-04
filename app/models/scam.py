from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from app.db import Base


class Scam(Base):
    __tablename__ = "scams"

    id = Column(String(128), primary_key=True)
    title_en = Column(String(255), nullable=False)
    title_hi = Column(String(255), nullable=False)
    title_te = Column(String(255), nullable=False)
    description_en = Column(Text, nullable=False)
    description_hi = Column(Text, nullable=False)
    description_te = Column(Text, nullable=False)
    category = Column(String(100), nullable=False, index=True)
    risk_level = Column(String(32), nullable=True)
    read_time = Column(Integer, nullable=False)
    content_en = Column(JSONB, nullable=False)
    content_hi = Column(JSONB, nullable=False)
    content_te = Column(JSONB, nullable=False)
    related = Column(JSONB, nullable=True)
    quick_tips = Column(JSONB, nullable=True)
