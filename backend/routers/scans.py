"""
CyberGuard AI — Scans & Findings Router

Endpoints for inspecting scanner outputs, filtering vulnerabilities, updating finding statuses,
and handling approval actions.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Assessment, ScanResult, Finding
from schemas import (
    ScanResultResponse,
    FindingResponse,
    FindingUpdate,
    ApprovalResponse,
)
from routers.chat import _active_agents
from scanners.nmap_scanner import NmapScanner
from scanners.zap_scanner import ZapScanner
from scanners.nikto_scanner import NiktoScanner
from services.vulnerability_db import VulnerabilityKB

router = APIRouter(tags=["Scans & Findings"])


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@router.get("/api/scans/{assessment_id}", response_model=List[ScanResultResponse])
async def list_assessment_scans(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
):
    """List all scans executed during an assessment."""
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    q = (
        select(ScanResult)
        .where(ScanResult.assessment_id == assessment_id)
        .order_by(ScanResult.id.desc())
    )
    res = await db.execute(q)
    scans = res.scalars().all()

    return [
        ScanResultResponse(
            id=s.id,
            assessment_id=s.assessment_id,
            tool=s.tool,
            scan_type=s.scan_type,
            target=s.target,
            raw_output=s.raw_output or "",
            parsed_results=s.parsed_results,
            status=s.status,
            started_at=s.started_at,
            completed_at=s.completed_at,
        )
        for s in scans
    ]


@router.get("/api/scans/result/{scan_id}", response_model=ScanResultResponse)
async def get_scan_detail(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve detailed execution output and raw data for a specific scan."""
    scan = await db.get(ScanResult, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResultResponse(
        id=scan.id,
        assessment_id=scan.assessment_id,
        tool=scan.tool,
        scan_type=scan.scan_type,
        target=scan.target,
        raw_output=scan.raw_output or "",
        parsed_results=scan.parsed_results,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@router.get("/api/findings/{assessment_id}", response_model=List[FindingResponse])
async def list_findings(
    assessment_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (open, confirmed, false_positive, remediated)"),
    tool: Optional[str] = Query(None, description="Filter by originating tool (nmap, zap, nikto)"),
    db: AsyncSession = Depends(get_db),
):
    """List all vulnerabilities and findings identified in an assessment."""
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    q = select(Finding).where(Finding.assessment_id == assessment_id)
    if severity:
        q = q.where(Finding.severity == severity.lower())
    if status_filter:
        q = q.where(Finding.status == status_filter.lower())
    if tool:
        q = q.where(Finding.found_by_tool == tool.lower())

    q = q.order_by(Finding.id.asc())
    res = await db.execute(q)
    findings = res.scalars().all()

    return [
        FindingResponse(
            id=f.id,
            assessment_id=f.assessment_id,
            scan_result_id=f.scan_result_id,
            title=f.title,
            description=f.description or "",
            severity=f.severity,
            cvss_score=f.cvss_score,
            cve_ids=f.cve_ids,
            evidence=f.evidence or "",
            remediation=f.remediation or "",
            status=f.status,
            found_by_tool=f.found_by_tool or "",
            created_at=f.created_at,
        )
        for f in findings
    ]


@router.put("/api/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update status, severity, CVSS score, or remediation details of a finding."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if payload.status is not None:
        finding.status = payload.status
    if payload.severity is not None:
        finding.severity = payload.severity
    if payload.cvss_score is not None:
        finding.cvss_score = payload.cvss_score
    if payload.remediation is not None:
        finding.remediation = payload.remediation
    if payload.description is not None:
        finding.description = payload.description

    await db.commit()
    await db.refresh(finding)

    return FindingResponse(
        id=finding.id,
        assessment_id=finding.assessment_id,
        scan_result_id=finding.scan_result_id,
        title=finding.title,
        description=finding.description or "",
        severity=finding.severity,
        cvss_score=finding.cvss_score,
        cve_ids=finding.cve_ids,
        evidence=finding.evidence or "",
        remediation=finding.remediation or "",
        status=finding.status,
        found_by_tool=finding.found_by_tool or "",
        created_at=finding.created_at,
    )


# ---------------------------------------------------------------------------
# Human-in-the-Loop Approval Endpoint (REST)
# ---------------------------------------------------------------------------

@router.post("/api/scans/{assessment_id}/approve/{action_id}")
async def approve_scan_action(
    assessment_id: int,
    action_id: str,
    payload: ApprovalResponse,
    db: AsyncSession = Depends(get_db),
):
    """
    REST endpoint to submit human sign-off or denial for gated offensive/exploitation actions.
    """
    agent = _active_agents.get(assessment_id)
    if not agent:
        raise HTTPException(status_code=400, detail="No active agent session found for this assessment")

    results = []
    async for frame in agent.handle_approval(action_id, payload.approved, payload.comment):
        results.append(frame)

    await db.commit()
    return {"status": "processed", "approved": payload.approved, "events": results}
