"""
CyberGuard AI — Assessments Router

Endpoints for managing VAPT assessment targets, scopes, and lifecycle states.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Assessment, Finding, ScanResult, ChatMessage, Report
from schemas import (
    AssessmentCreate,
    AssessmentUpdate,
    AssessmentResponse,
    AssessmentList,
)

router = APIRouter(prefix="/api/assessments", tags=["Assessments"])


async def _enrich_assessment_counts(db: AsyncSession, assessment: Assessment) -> AssessmentResponse:
    """Helper to calculate severity and finding counts for an assessment."""
    q = select(Finding.severity, func.count(Finding.id)).where(
        Finding.assessment_id == assessment.id
    ).group_by(Finding.severity)
    res = await db.execute(q)
    counts = {row[0].lower(): row[1] for row in res.all() if row[0]}

    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)
    low = counts.get("low", 0)
    info = counts.get("info", 0)
    total = sum(counts.values())

    return AssessmentResponse(
        id=assessment.id,
        name=assessment.name,
        target=assessment.target,
        scope=assessment.scope or "",
        status=assessment.status,
        description=assessment.description or "",
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
        findings_count=total,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        info_count=info,
    )


@router.post("", response_model=AssessmentResponse, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    payload: AssessmentCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new VAPT assessment session."""
    assessment = Assessment(
        name=payload.name.strip(),
        target=payload.target.strip(),
        scope=payload.scope.strip() if payload.scope else "",
        description=payload.description.strip() if payload.description else "",
        status="created",
    )
    db.add(assessment)
    await db.commit()
    await db.refresh(assessment)

    # Automatically add an initial system welcome message
    welcome_msg = ChatMessage(
        assessment_id=assessment.id,
        role="assistant",
        content=(
            f"👋 Welcome to **CyberGuard AI**. I am your conversational security assessment agent.\n\n"
            f"**Target:** `{assessment.target}`\n"
            f"**Scope:** {assessment.scope or 'Full authorized sandbox scope'}\n\n"
            f"I will help you execute an authorized VAPT from initial reconnaissance through to a "
            f"client-ready report. Would you like me to begin with an **Nmap network reconnaissance scan** "
            f"or specify a targeted testing strategy?"
        ),
    )
    db.add(welcome_msg)
    await db.commit()

    return await _enrich_assessment_counts(db, assessment)


@router.get("", response_model=AssessmentList)
async def list_assessments(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve all assessments with current finding statistics."""
    q = select(Assessment).order_by(Assessment.created_at.desc()).offset(skip).limit(limit)
    res = await db.execute(q)
    assessments = res.scalars().all()

    total_q = select(func.count(Assessment.id))
    total_res = await db.execute(total_q)
    total = total_res.scalar_one()

    items = []
    for a in assessments:
        enriched = await _enrich_assessment_counts(db, a)
        items.append(enriched)

    return AssessmentList(items=items, total=total)


@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get single assessment details and severity statistics."""
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return await _enrich_assessment_counts(db, assessment)


@router.put("/{assessment_id}", response_model=AssessmentResponse)
async def update_assessment(
    assessment_id: int,
    payload: AssessmentUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update assessment properties or status."""
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    if payload.name is not None:
        assessment.name = payload.name.strip()
    if payload.target is not None:
        assessment.target = payload.target.strip()
    if payload.scope is not None:
        assessment.scope = payload.scope.strip()
    if payload.status is not None:
        assessment.status = payload.status
    if payload.description is not None:
        assessment.description = payload.description.strip()

    await db.commit()
    await db.refresh(assessment)
    return await _enrich_assessment_counts(db, assessment)


@router.delete("/{assessment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_assessment(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete an assessment and all associated scans, findings, chat logs, and reports."""
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    await db.delete(assessment)
    await db.commit()
    return None
