"""PostgreSQL database setup with SQLAlchemy async ORM."""

from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import (
    String, Text, Integer, Float, Boolean, DateTime, ForeignKey,
    JSON, Table, Column, Index, func
)
from typing import Optional, List
from datetime import datetime

from config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG, pool_size=10)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


# ── Junction Tables ────────────────────────────────────────────────────────────

exploit_tags = Table(
    "exploit_tags",
    Base.metadata,
    Column("exploit_id", Integer, ForeignKey("exploits.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


# ── ORM Models ─────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(50), default="pentester")
    reputation_score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    exploits: Mapped[List["Exploit"]] = relationship(back_populates="author")
    chains: Mapped[List["AttackChainDB"]] = relationship(back_populates="author")


class Exploit(Base):
    __tablename__ = "exploits"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    attack_type: Mapped[str] = mapped_column(String(50), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    affected_software: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    affected_versions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    prerequisites: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    steps: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_type: Mapped[str] = mapped_column(String(20), default="user_submitted")
    source_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    raw_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parsed_content: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    author_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    upvotes: Mapped[int] = mapped_column(Integer, default=0)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    embedding_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    author: Mapped[Optional["User"]] = relationship(back_populates="exploits")
    files: Mapped[List["ExploitFile"]] = relationship(back_populates="exploit", cascade="all, delete-orphan")
    tags: Mapped[List["Tag"]] = relationship(secondary=exploit_tags, back_populates="exploits")

    __table_args__ = (
        Index("idx_exploit_type_severity", "attack_type", "severity"),
    )


class ExploitFile(Base):
    __tablename__ = "exploit_files"

    id: Mapped[int] = mapped_column(primary_key=True)
    exploit_id: Mapped[int] = mapped_column(ForeignKey("exploits.id", ondelete="CASCADE"))
    filename: Mapped[str] = mapped_column(String(500))
    file_type: Mapped[str] = mapped_column(String(20))
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    parsed_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    exploit: Mapped["Exploit"] = relationship(back_populates="files")


class AttackChainDB(Base):
    __tablename__ = "attack_chains"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    chain_type: Mapped[str] = mapped_column(String(50))
    total_steps: Mapped[int] = mapped_column(Integer, default=0)
    success_conditions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    overall_impact: Mapped[str] = mapped_column(Text, default="")
    author_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    upvotes: Mapped[int] = mapped_column(Integer, default=0)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    embedding_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    author: Mapped[Optional["User"]] = relationship(back_populates="chains")
    steps: Mapped[List["ChainStep"]] = relationship(
        back_populates="chain", cascade="all, delete-orphan", order_by="ChainStep.step_order"
    )


class ChainStep(Base):
    __tablename__ = "chain_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(ForeignKey("attack_chains.id", ondelete="CASCADE"))
    step_order: Mapped[int] = mapped_column(Integer)
    exploit_id: Mapped[Optional[int]] = mapped_column(ForeignKey("exploits.id"), nullable=True)
    step_type: Mapped[str] = mapped_column(String(30), default="exploit")
    description: Mapped[str] = mapped_column(Text)
    prerequisites: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    input_from_previous: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    output_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    chain: Mapped["AttackChainDB"] = relationship(back_populates="steps")


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    category: Mapped[str] = mapped_column(String(50), default="general")

    exploits: Mapped[List["Exploit"]] = relationship(secondary=exploit_tags, back_populates="tags")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    target_url: Mapped[str] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(30), default="queued")
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    findings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    chains_discovered: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    endpoints_discovered: Mapped[int] = mapped_column(Integer, default=0)
    scan_config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# ── Database Initialization ────────────────────────────────────────────────────

async def init_db():
    """Create all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@asynccontextmanager
async def get_session():
    """Get a database session."""
    async with async_session() as session:
        yield session
