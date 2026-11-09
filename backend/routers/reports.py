"""
CyberGuard AI — Reports Router

Endpoints for generating, listing, and downloading client-ready VAPT PDF deliverables.
"""

import os
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Assessment, Report
from schemas import ReportResponse
from services.report_generator import ReportGenerator

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/{assessment_id}/generate", response_model=ReportResponse)
async def generate_vapt_report(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Generate a client-ready VAPT PDF report using ReportLab."""
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    generator = ReportGenerator(db)
    try:
        report_path = await generator.generate(assessment_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {exc}")

    # Fetch newly created report record
    q = (
        select(Report)
        .where(Report.assessment_id == assessment_id)
        .order_by(Report.id.desc())
        .limit(1)
    )
    res = await db.execute(q)
    report_record = res.scalar_one_or_none()

    if not report_record:
        raise HTTPException(status_code=500, detail="Report generated but database record missing")

    return ReportResponse(
        id=report_record.id,
        assessment_id=report_record.assessment_id,
        title=report_record.title,
        executive_summary=report_record.executive_summary or "",
        filepath=report_record.filepath,
        created_at=report_record.created_at,
    )


@router.get("/{assessment_id}", response_model=List[ReportResponse])
async def list_reports(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
):
    """List all generated reports for an assessment."""
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    q = (
        select(Report)
        .where(Report.assessment_id == assessment_id)
        .order_by(Report.created_at.desc())
    )
    res = await db.execute(q)
    reports = res.scalars().all()

    return [
        ReportResponse(
            id=r.id,
            assessment_id=r.assessment_id,
            title=r.title,
            executive_summary=r.executive_summary or "",
            filepath=r.filepath,
            created_at=r.created_at,
        )
        for r in reports
    ]


@router.get("/download/{report_id}")
async def download_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Download a generated PDF assessment report."""
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if not os.path.exists(report.filepath):
        raise HTTPException(status_code=404, detail="Report PDF file not found on disk")

    filename = os.path.basename(report.filepath)
    return FileResponse(
        path=report.filepath,
        filename=filename,
        media_type="application/pdf",
    )
