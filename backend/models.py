"""
CyberGuard AI — SQLAlchemy ORM Models

Defines the relational schema for assessments, scan results, findings,
chat messages, and reports.
"""

import datetime
import json
from typing import Optional, List

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    DateTime,
    ForeignKey,
    Enum as SAEnum,
    func,
)
from sqlalchemy.orm import relationship

from database import Base


class Assessment(Base):
    """A VAPT assessment session covering a specific target and scope."""

    __tablename__ = "assessments"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    name: str = Column(String(255), nullable=False)
    target: str = Column(String(512), nullable=False)
    scope: str = Column(Text, nullable=True, default="")
    status: str = Column(
        String(32), nullable=False, default="created"
    )  # created | in_progress | completed
    description: str = Column(Text, nullable=True, default="")
    created_at: datetime.datetime = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: datetime.datetime = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    scan_results = relationship(
        "ScanResult", back_populates="assessment", cascade="all, delete-orphan"
    )
    findings = relationship(
        "Finding", back_populates="assessment", cascade="all, delete-orphan"
    )
    chat_messages = relationship(
        "ChatMessage", back_populates="assessment", cascade="all, delete-orphan"
    )
    reports = relationship(
        "Report", back_populates="assessment", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Assessment id={self.id} name={self.name!r} target={self.target!r}>"


class ScanResult(Base):
    """Raw and parsed output from a security scanning tool."""

    __tablename__ = "scan_results"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id: int = Column(
        Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    tool: str = Column(String(64), nullable=False)  # nmap | zap | nikto
    scan_type: str = Column(String(64), nullable=False)
    target: str = Column(String(512), nullable=False)
    raw_output: str = Column(Text, nullable=True, default="")
    _parsed_results: str = Column("parsed_results", Text, nullable=True, default="{}")
    status: str = Column(
        String(32), nullable=False, default="pending"
    )  # pending | running | completed | failed
    started_at: Optional[datetime.datetime] = Column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Optional[datetime.datetime] = Column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    assessment = relationship("Assessment", back_populates="scan_results")
    findings = relationship("Finding", back_populates="scan_result")

    @property
    def parsed_results(self) -> dict:
        """Deserialize JSON stored in the parsed_results column."""
        if self._parsed_results:
            try:
                return json.loads(self._parsed_results)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}

    @parsed_results.setter
    def parsed_results(self, value: dict) -> None:
        self._parsed_results = json.dumps(value) if value else "{}"

    def __repr__(self) -> str:
        return f"<ScanResult id={self.id} tool={self.tool!r} status={self.status!r}>"


class Finding(Base):
    """A security finding (vulnerability, misconfiguration, informational note)."""

    __tablename__ = "findings"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id: int = Column(
        Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    scan_result_id: Optional[int] = Column(
        Integer, ForeignKey("scan_results.id", ondelete="SET NULL"), nullable=True
    )
    title: str = Column(String(512), nullable=False)
    description: str = Column(Text, nullable=True, default="")
    severity: str = Column(
        String(32), nullable=False, default="info"
    )  # critical | high | medium | low | info
    cvss_score: Optional[float] = Column(Float, nullable=True)
    _cve_ids: str = Column("cve_ids", Text, nullable=True, default="[]")
    evidence: str = Column(Text, nullable=True, default="")
    remediation: str = Column(Text, nullable=True, default="")
    status: str = Column(
        String(32), nullable=False, default="open"
    )  # open | confirmed | false_positive | remediated
    found_by_tool: str = Column(String(64), nullable=True, default="")
    created_at: datetime.datetime = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    assessment = relationship("Assessment", back_populates="findings")
    scan_result = relationship("ScanResult", back_populates="findings")

    @property
    def cve_ids(self) -> List[str]:
        if self._cve_ids:
            try:
                return json.loads(self._cve_ids)
            except (json.JSONDecodeError, TypeError):
                return []
        return []

    @cve_ids.setter
    def cve_ids(self, value: List[str]) -> None:
        self._cve_ids = json.dumps(value) if value else "[]"

    def __repr__(self) -> str:
        return f"<Finding id={self.id} title={self.title!r} severity={self.severity!r}>"


class ChatMessage(Base):
    """A single message in the AI chat conversation for an assessment."""

    __tablename__ = "chat_messages"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id: int = Column(
        Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    role: str = Column(
        String(32), nullable=False
    )  # user | assistant | system
    content: str = Column(Text, nullable=False, default="")
    _metadata: str = Column("metadata", Text, nullable=True, default="{}")
    created_at: datetime.datetime = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    assessment = relationship("Assessment", back_populates="chat_messages")

    @property
    def msg_metadata(self) -> dict:
        if self._metadata:
            try:
                return json.loads(self._metadata)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}

    @msg_metadata.setter
    def msg_metadata(self, value: dict) -> None:
        self._metadata = json.dumps(value) if value else "{}"

    def __repr__(self) -> str:
        return f"<ChatMessage id={self.id} role={self.role!r}>"


class Report(Base):
    """A generated PDF assessment report."""

    __tablename__ = "reports"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id: int = Column(
        Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    title: str = Column(String(512), nullable=False)
    executive_summary: str = Column(Text, nullable=True, default="")
    filepath: str = Column(String(1024), nullable=False)
    created_at: datetime.datetime = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    assessment = relationship("Assessment", back_populates="reports")

    def __repr__(self) -> str:
        return f"<Report id={self.id} title={self.title!r}>"
