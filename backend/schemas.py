"""
CyberGuard AI — Pydantic Schemas

Request / response models for the REST and WebSocket APIs.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

class AssessmentCreate(BaseModel):
    """Payload for creating a new assessment."""
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable assessment name")
    target: str = Field(..., min_length=1, max_length=512, description="Primary target host/IP/URL")
    scope: str = Field("", description="Textual scope description (e.g. 'Web application at port 443 only')")
    description: str = Field("", description="Additional notes about the assessment")


class AssessmentUpdate(BaseModel):
    """Payload for updating an existing assessment."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    target: Optional[str] = Field(None, min_length=1, max_length=512)
    scope: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(created|in_progress|completed)$")
    description: Optional[str] = None


class AssessmentResponse(BaseModel):
    """Full assessment detail returned by the API."""
    id: int
    name: str
    target: str
    scope: str
    status: str
    description: str
    created_at: datetime.datetime
    updated_at: datetime.datetime
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    class Config:
        from_attributes = True


class AssessmentList(BaseModel):
    """Paginated list of assessments."""
    items: List[AssessmentResponse]
    total: int


# ---------------------------------------------------------------------------
# Scan Results
# ---------------------------------------------------------------------------

class ScanResultResponse(BaseModel):
    """Scan result returned by the API."""
    id: int
    assessment_id: int
    tool: str
    scan_type: str
    target: str
    raw_output: str = ""
    parsed_results: Dict[str, Any] = {}
    status: str
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class FindingResponse(BaseModel):
    """Security finding returned by the API."""
    id: int
    assessment_id: int
    scan_result_id: Optional[int] = None
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    cve_ids: List[str] = []
    evidence: str = ""
    remediation: str = ""
    status: str
    found_by_tool: str = ""
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Payload for updating a finding (e.g. confirming or marking false-positive)."""
    status: Optional[str] = Field(None, pattern="^(open|confirmed|false_positive|remediated)$")
    severity: Optional[str] = Field(None, pattern="^(critical|high|medium|low|info)$")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    remediation: Optional[str] = None
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------

class ChatMessageCreate(BaseModel):
    """Payload for sending a chat message (REST fallback)."""
    content: str = Field(..., min_length=1, description="User message text")


class ChatMessageResponse(BaseModel):
    """Chat message returned by the API."""
    id: int
    assessment_id: int
    role: str
    content: str
    metadata: Dict[str, Any] = {}
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportResponse(BaseModel):
    """Report metadata returned by the API."""
    id: int
    assessment_id: int
    title: str
    executive_summary: str = ""
    filepath: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Agent internals (exposed via WebSocket frames)
# ---------------------------------------------------------------------------

class AgentAction(BaseModel):
    """Represents a tool the agent wants to invoke."""
    action_id: str = Field(..., description="Unique ID for this action (for approval tracking)")
    tool_name: str = Field(..., description="Name of the tool to execute")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool arguments")
    requires_approval: bool = Field(False, description="Whether human approval is needed first")
    reasoning: str = Field("", description="Agent's explanation for choosing this tool")


class ApprovalRequest(BaseModel):
    """Sent to the frontend when human approval is required."""
    action_id: str
    tool_name: str
    arguments: Dict[str, Any] = {}
    reasoning: str = ""
    risk_warning: str = ""


class ApprovalResponse(BaseModel):
    """Sent from the frontend to approve or deny an action."""
    action_id: str
    approved: bool
    comment: str = ""


# ---------------------------------------------------------------------------
# WebSocket frame envelope
# ---------------------------------------------------------------------------

class WSFrame(BaseModel):
    """Envelope for every WebSocket JSON frame sent to the client."""
    type: str = Field(
        ...,
        description=(
            "Frame type: text | tool_call | tool_result | "
            "approval_request | reasoning | error | status"
        ),
    )
    content: Any = None
