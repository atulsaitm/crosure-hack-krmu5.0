"""Knowledge Base API routes."""

import json
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from typing import List, Optional

from core.models import ExploitCreate, ExploitResponse, ChainCreate, ChainResponse
from kb.database import get_session, Exploit, ExploitFile, AttackChainDB, ChainStep, Tag
from kb.embeddings import embed_exploit, embed_chain, search_exploits, search_chains_for_findings
from kb.parser import parse_exploit_file
from sqlalchemy import select
from sqlalchemy.orm import selectinload

router = APIRouter(prefix="/api/kb", tags=["knowledge-base"])


@router.post("/exploits", response_model=ExploitResponse)
async def create_exploit(exploit: ExploitCreate):
    """Add a new exploit to the knowledge base."""
    async with get_session() as session:
        db_exploit = Exploit(
            title=exploit.title,
            description=exploit.description,
            attack_type=exploit.attack_type,
            severity=exploit.severity,
            cve_id=exploit.cve_id,
            prerequisites=exploit.prerequisites,
            steps=exploit.steps,
            impact=exploit.impact,
            remediation=exploit.remediation,
        )
        session.add(db_exploit)
        await session.flush()

        # Handle tags
        for tag_name in (exploit.tags or []):
            tag = await session.execute(select(Tag).where(Tag.name == tag_name))
            tag = tag.scalar_one_or_none()
            if not tag:
                tag = Tag(name=tag_name)
                session.add(tag)
            db_exploit.tags.append(tag)

        await session.commit()
        await session.refresh(db_exploit, attribute_names=["tags"])

        # Embed in vector store
        embed_exploit(
            exploit_id=db_exploit.id,
            text=f"{exploit.title}. {exploit.description or ''}",
            metadata={"attack_type": exploit.attack_type, "severity": exploit.severity},
        )

        return ExploitResponse(
            id=str(db_exploit.id),
            title=db_exploit.title,
            description=db_exploit.description,
            attack_type=db_exploit.attack_type,
            severity=db_exploit.severity,
            cve_id=db_exploit.cve_id,
            tags=[t.name for t in db_exploit.tags] if db_exploit.tags else [],
        )


@router.get("/exploits", response_model=List[ExploitResponse])
async def list_exploits(limit: int = 50, offset: int = 0):
    """List all exploits."""
    async with get_session() as session:
        result = await session.execute(
            select(Exploit)
            .options(selectinload(Exploit.tags))
            .order_by(Exploit.created_at.desc())
            .offset(offset).limit(limit)
        )
        exploits = result.scalars().all()

        return [
            ExploitResponse(
                id=str(e.id),
                title=e.title,
                description=e.description,
                attack_type=e.attack_type,
                severity=e.severity,
                cve_id=e.cve_id,
                tags=[t.name for t in e.tags] if e.tags else [],
            )
            for e in exploits
        ]


@router.get("/exploits/search")
async def search_exploits_endpoint(
    query: str,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 10,
):
    """Semantic search for exploits."""
    results = search_exploits(query, n_results=limit, attack_type=attack_type, severity=severity)
    return results


@router.post("/upload")
async def upload_exploit_file(
    file: UploadFile = File(...),
    title: Optional[str] = Form(None),
):
    """Upload and parse an exploit file (markdown, code, etc.)."""
    content = await file.read()
    content_str = content.decode("utf-8", errors="ignore")

    # Parse with LLM
    parsed = await parse_exploit_file(file.filename or "unknown", content_str)

    if not parsed:
        raise HTTPException(status_code=422, detail="Could not parse exploit file")

    # Store in DB
    exploit_data = ExploitCreate(
        title=title or parsed.get("title", file.filename),
        description=parsed.get("description", ""),
        attack_type=parsed.get("attack_type", "other"),
        severity=parsed.get("severity", "medium"),
        cve_id=parsed.get("cve_id"),
        prerequisites=parsed.get("prerequisites", []),
        steps=parsed.get("steps", []),
        impact=parsed.get("impact", ""),
        remediation=parsed.get("remediation", ""),
        tags=parsed.get("tags", []),
    )

    # Reuse create endpoint logic
    async with get_session() as session:
        db_exploit = Exploit(
            title=exploit_data.title,
            description=exploit_data.description,
            attack_type=exploit_data.attack_type,
            severity=exploit_data.severity,
            cve_id=exploit_data.cve_id,
            prerequisites=exploit_data.prerequisites,
            steps=exploit_data.steps,
            impact=exploit_data.impact,
            remediation=exploit_data.remediation,
            parsed_content=parsed,
        )
        session.add(db_exploit)

        # Store original file
        db_file = ExploitFile(
            exploit=db_exploit,
            filename=file.filename or "unknown",
            file_type=file.content_type or "text/plain",
            file_path="uploaded",
            content=content_str,
        )
        session.add(db_file)

        await session.commit()
        await session.refresh(db_exploit)

        # Embed
        embed_exploit(
            exploit_id=db_exploit.id,
            text=f"{exploit_data.title}. {exploit_data.description or ''}",
            metadata={"attack_type": exploit_data.attack_type, "severity": exploit_data.severity},
        )

        return {
            "id": str(db_exploit.id),
            "title": db_exploit.title,
            "parsed": parsed,
            "message": "Exploit uploaded and parsed successfully",
        }


@router.post("/chains", response_model=ChainResponse)
async def create_chain(chain: ChainCreate):
    """Add a known attack chain to the knowledge base."""
    async with get_session() as session:
        db_chain = AttackChainDB(
            title=chain.name,
            description=chain.description or "",
            chain_type=chain.chain_type,
            total_steps=len(chain.steps),
        )
        session.add(db_chain)
        await session.flush()

        for idx, step in enumerate(chain.steps):
            db_step = ChainStep(
                chain_id=db_chain.id,
                step_order=idx + 1,
                step_type=step.vuln_type,
                description=step.description,
            )
            session.add(db_step)

        await session.commit()
        await session.refresh(db_chain)

        # Embed in vector store
        embed_chain(
            chain_id=db_chain.id,
            text=f"{chain.name}. {chain.description or ''}. Steps: {', '.join(s.vuln_type for s in chain.steps)}",
            metadata={"chain_type": chain.chain_type, "is_chain": True},
        )

        return ChainResponse(
            id=str(db_chain.id),
            name=db_chain.title,
            description=db_chain.description,
            chain_type=db_chain.chain_type,
        )


@router.get("/chains", response_model=List[ChainResponse])
async def list_chains(limit: int = 50, offset: int = 0):
    """List all known attack chains."""
    async with get_session() as session:
        result = await session.execute(
            select(AttackChainDB)
            .order_by(AttackChainDB.created_at.desc())
            .offset(offset).limit(limit)
        )
        chains = result.scalars().all()

        return [
            ChainResponse(
                id=str(c.id),
                name=c.title,
                description=c.description,
                chain_type=c.chain_type,
            )
            for c in chains
        ]


@router.get("/stats")
async def kb_stats():
    """Get knowledge base statistics."""
    async with get_session() as session:
        from sqlalchemy import func
        exploit_count = await session.scalar(select(func.count(Exploit.id)))
        chain_count = await session.scalar(select(func.count(AttackChainDB.id)))

        return {
            "total_exploits": exploit_count or 0,
            "total_chains": chain_count or 0,
        }
