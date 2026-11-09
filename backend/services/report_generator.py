"""
CyberGuard AI — ReportLab PDF Report Generator

Generates client-ready, professional Vulnerability Assessment & Penetration
Testing (VAPT) reports complete with executive summary, methodology,
severity heatmaps, detailed finding dossiers, and remediation roadmap.
"""

from __future__ import annotations

import datetime
import os
from typing import Optional, List, Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.pdfgen import canvas

from config import settings
from models import Assessment, ScanResult, Finding, Report


SEVERITY_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#D97706"),
    "low": colors.HexColor("#2563EB"),
    "info": colors.HexColor("#4B5563"),
}


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and draw total page numbers and running footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        if self._pageNumber == 1:
            # Suppress running header/footer on title cover page
            return

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#00d4ff"))

        # Running header
        self.drawString(54, 750, "CYBERGUARD AI")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawRightString(558, 750, "CONFIDENTIAL & PROPRIETARY — VAPT REPORT")

        # Header rule
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 742, 558, 742)

        # Running footer rule
        self.line(54, 45, 558, 45)

        # Running footer
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(54, 32, "Strictly for authorized recipient evaluation only")
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(558, 32, page_str)

        self.restoreState()


class ReportGenerator:
    """Orchestrates generation of comprehensive PDF assessment deliverables."""

    def __init__(self, db_session: AsyncSession) -> None:
        self.db = db_session

    async def generate(self, assessment_id: int) -> str:
        """
        Generate a client-ready VAPT PDF report for the given assessment.
        Saves the file to reports directory and registers a Report record in the database.
        Returns the absolute filepath to the created PDF.
        """
        # Load assessment
        assessment = await self.db.get(Assessment, assessment_id)
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} not found.")

        # Load findings
        q_find = select(Finding).where(Finding.assessment_id == assessment_id).order_by(Finding.id)
        res_find = await self.db.execute(q_find)
        findings: List[Finding] = res_find.scalars().all()

        # Load scans
        q_scans = select(ScanResult).where(ScanResult.assessment_id == assessment_id)
        res_scans = await self.db.execute(q_scans)
        scans: List[ScanResult] = res_scans.scalars().all()

        # Ensure directory exists
        os.makedirs(settings.REPORTS_DIR, exist_ok=True)
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c for c in assessment.name if c.isalnum() or c in ("-", "_")).rstrip()
        filename = f"CyberGuard_{safe_name}_{assessment_id}_{timestamp_str}.pdf"
        output_path = os.path.abspath(os.path.join(settings.REPORTS_DIR, filename))

        # Severity breakdown
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.severity or "info").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1

        # Setup document styles
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        styles = getSampleStyleSheet()
        normal = styles["Normal"]

        title_style = ParagraphStyle(
            "CoverTitle",
            parent=normal,
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=colors.HexColor("#0B132B"),
            spaceAfter=10,
        )
        subtitle_style = ParagraphStyle(
            "CoverSubtitle",
            parent=normal,
            fontName="Helvetica",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0096C7"),
            spaceAfter=25,
        )
        meta_label = ParagraphStyle(
            "MetaLabel",
            parent=normal,
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#334155"),
        )
        meta_val = ParagraphStyle(
            "MetaVal",
            parent=normal,
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#0F172A"),
        )
        h1 = ParagraphStyle(
            "Heading1_Custom",
            parent=normal,
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0F172A"),
            spaceBefore=18,
            spaceAfter=10,
        )
        h2 = ParagraphStyle(
            "Heading2_Custom",
            parent=normal,
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=14,
            spaceAfter=6,
        )
        body = ParagraphStyle(
            "Body_Custom",
            parent=normal,
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#334155"),
            spaceAfter=8,
        )
        badge_style = ParagraphStyle(
            "BadgeStyle",
            parent=normal,
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=10,
            textColor=colors.white,
            alignment=1,
        )

        story = []

        # =====================================================================
        # 1. COVER PAGE
        # =====================================================================
        story.append(Spacer(1, 40))
        # Top banner decor
        story.append(
            Table(
                [[Paragraph("<b>CYBERGUARD AI</b> • AUTONOMOUS SECURITY AUDIT SYSTEM", ParagraphStyle("BrandTag", parent=normal, fontName="Helvetica-Bold", fontSize=9, textColor=colors.HexColor("#0284C7")))]],
                colWidths=[504],
                style=[
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0F9FF")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#BAE6FD")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ],
            )
        )
        story.append(Spacer(1, 40))
        story.append(Paragraph("Vulnerability Assessment &<br/>Penetration Testing Report", title_style))
        story.append(Paragraph(f"Security Evaluation for: <b>{assessment.name}</b>", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284C7"), spaceAfter=30))

        # Metadata table
        meta_data = [
            [Paragraph("Target Host / Scope:", meta_label), Paragraph(f"<code>{assessment.target}</code>", meta_val)],
            [Paragraph("Assessment ID:", meta_label), Paragraph(str(assessment.id), meta_val)],
            [Paragraph("Assessment Date:", meta_label), Paragraph(datetime.datetime.now().strftime("%B %d, %Y - %H:%M UTC"), meta_val)],
            [Paragraph("Status:", meta_label), Paragraph(assessment.status.upper(), meta_val)],
            [Paragraph("Scope Constraints:", meta_label), Paragraph(assessment.scope or "Authorized Laboratory Target Scope Only", meta_val)],
            [Paragraph("Total Vulnerabilities:", meta_label), Paragraph(f"<b>{len(findings)}</b> findings correlated", meta_val)],
        ]
        t_meta = Table(meta_data, colWidths=[150, 354])
        t_meta.setStyle(
            TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ])
        )
        story.append(t_meta)

        story.append(Spacer(1, 60))
        # Confidentiality warning box
        warning_text = (
            "<b>CONFIDENTIALITY NOTICE:</b> The information contained in this document is strictly "
            "confidential and intended solely for the authorized technical evaluation of the designated target. "
            "Unauthorized copying, distribution, or utilization of the vulnerabilities identified herein is strictly "
            "prohibited by law and organizational policy."
        )
        t_warn = Table([[Paragraph(warning_text, body)]], colWidths=[504])
        t_warn.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF2F2")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#FCA5A5")),
                ("PADDING", (0, 0), (-1, -1), 10),
            ])
        )
        story.append(t_warn)

        story.append(PageBreak())

        # =====================================================================
        # 2. EXECUTIVE SUMMARY & STATISTICAL METRICS
        # =====================================================================
        story.append(Paragraph("1. Executive Summary", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0"), spaceAfter=12))

        exec_summary = (
            f"CyberGuard AI conducted a guided, authorized Vulnerability Assessment and Penetration Testing "
            f"(VAPT) engagement targeting <b>{assessment.target}</b>. The evaluation orchestrated network discovery, "
            f"service fingerprinting, web application security scanning, and automated correlation. "
            f"During the assessment, a total of <b>{len(findings)}</b> security items were documented, spanning "
            f"<b>{counts['critical']}</b> Critical, <b>{counts['high']}</b> High, <b>{counts['medium']}</b> Medium, "
            f"<b>{counts['low']}</b> Low, and <b>{counts['info']}</b> Informational issues."
        )
        story.append(Paragraph(exec_summary, body))

        if assessment.description:
            story.append(Paragraph(f"<b>Engagement Notes:</b> {assessment.description}", body))

        story.append(Spacer(1, 10))
        story.append(Paragraph("Risk Breakdown & Posture Overview", h2))

        # Metric cards table
        summary_table_data = [
            [
                Paragraph("<b>CRITICAL</b>", ParagraphStyle("H_Crit", parent=normal, textColor=colors.HexColor("#DC2626"), alignment=1)),
                Paragraph("<b>HIGH</b>", ParagraphStyle("H_High", parent=normal, textColor=colors.HexColor("#EA580C"), alignment=1)),
                Paragraph("<b>MEDIUM</b>", ParagraphStyle("H_Med", parent=normal, textColor=colors.HexColor("#D97706"), alignment=1)),
                Paragraph("<b>LOW</b>", ParagraphStyle("H_Low", parent=normal, textColor=colors.HexColor("#2563EB"), alignment=1)),
                Paragraph("<b>INFO</b>", ParagraphStyle("H_Inf", parent=normal, textColor=colors.HexColor("#4B5563"), alignment=1)),
            ],
            [
                Paragraph(f"<font size=16><b>{counts['critical']}</b></font>", ParagraphStyle("V_Crit", parent=normal, alignment=1)),
                Paragraph(f"<font size=16><b>{counts['high']}</b></font>", ParagraphStyle("V_High", parent=normal, alignment=1)),
                Paragraph(f"<font size=16><b>{counts['medium']}</b></font>", ParagraphStyle("V_Med", parent=normal, alignment=1)),
                Paragraph(f"<font size=16><b>{counts['low']}</b></font>", ParagraphStyle("V_Low", parent=normal, alignment=1)),
                Paragraph(f"<font size=16><b>{counts['info']}</b></font>", ParagraphStyle("V_Inf", parent=normal, alignment=1)),
            ],
        ]
        t_summary = Table(summary_table_data, colWidths=[100, 100, 100, 100, 104])
        t_summary.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, 1), colors.HexColor("#FEF2F2")),
                ("BACKGROUND", (1, 0), (1, 1), colors.HexColor("#FFF7ED")),
                ("BACKGROUND", (2, 0), (2, 1), colors.HexColor("#FFFBEB")),
                ("BACKGROUND", (3, 0), (3, 1), colors.HexColor("#EFF6FF")),
                ("BACKGROUND", (4, 0), (4, 1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (0, 1), 1, colors.HexColor("#FCA5A5")),
                ("BOX", (1, 0), (1, 1), 1, colors.HexColor("#FDBA74")),
                ("BOX", (2, 0), (2, 1), 1, colors.HexColor("#FCD34D")),
                ("BOX", (3, 0), (3, 1), 1, colors.HexColor("#93C5FD")),
                ("BOX", (4, 0), (4, 1), 1, colors.HexColor("#CBD5E1")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 8),
            ])
        )
        story.append(t_summary)

        # =====================================================================
        # 3. METHODOLOGY & TOOL PIPELINE
        # =====================================================================
        story.append(Spacer(1, 15))
        story.append(Paragraph("2. Scope & Assessment Methodology", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0"), spaceAfter=10))

        method_text = (
            "CyberGuard AI executes a multi-phase, reasoning-guided assessment methodology strictly within "
            "authorized boundaries:<br/>"
            "• <b>Phase 1: Reconnaissance & Discovery</b> — Target domain/IP verification and non-intrusive port identification (Nmap).<br/>"
            "• <b>Phase 2: Service Enumeration & Fingerprinting</b> — Banner grabbing, version detection, and cipher inspection.<br/>"
            "• <b>Phase 3: Web Vulnerability Assessment</b> — Automated crawler exploration, OWASP Top 10 passive & active inspection (OWASP ZAP).<br/>"
            "• <b>Phase 4: Misconfiguration & Server Audit</b> — Server header auditing and outdated software detection (Nikto).<br/>"
            "• <b>Phase 5: Evidence Correlation & Human Gatekeeping</b> — Cross-tool finding deduplication, CVSS calculation, and gating offensive validation."
        )
        story.append(Paragraph(method_text, body))

        # Tool audit table
        tool_records = [
            [
                Paragraph("<b>Execution Time</b>", meta_label),
                Paragraph("<b>Scanner Tool</b>", meta_label),
                Paragraph("<b>Type / Profile</b>", meta_label),
                Paragraph("<b>Target</b>", meta_label),
                Paragraph("<b>Status</b>", meta_label),
            ]
        ]
        for s in scans:
            ts = s.started_at.strftime("%H:%M:%S") if s.started_at else "N/A"
            tool_records.append([
                Paragraph(ts, body),
                Paragraph(s.tool.upper(), body),
                Paragraph(s.scan_type, body),
                Paragraph(s.target[:30], body),
                Paragraph(s.status.capitalize(), body),
            ])

        if len(tool_records) > 1:
            story.append(Paragraph("Executed Scanners Audit Log", h2))
            t_tools = Table(tool_records, colWidths=[80, 80, 110, 154, 80])
            t_tools.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ])
            )
            story.append(t_tools)

        story.append(PageBreak())

        # =====================================================================
        # 4. FINDINGS INVENTORY & DETAILS
        # =====================================================================
        story.append(Paragraph("3. Vulnerability Findings & Remediation Dossier", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0"), spaceAfter=15))

        if not findings:
            story.append(Paragraph("<i>No vulnerabilities were identified during this assessment session.</i>", body))
        else:
            # Sort findings by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                findings,
                key=lambda x: (severity_order.get((x.severity or "").lower(), 5), -(x.cvss_score or 0.0)),
            )

            for idx, item in enumerate(sorted_findings, start=1):
                sev_key = (item.severity or "info").lower()
                sev_color = SEVERITY_COLORS.get(sev_key, colors.HexColor("#64748B"))
                cves = ", ".join(item.cve_ids) if item.cve_ids else "N/A"
                cvss_display = f"{item.cvss_score:.1f}" if item.cvss_score is not None else "Unscored"

                finding_block = [
                    # Header row with title and severity tag
                    Table(
                        [
                            [
                                Paragraph(f"<b>#{idx}. {item.title}</b>", ParagraphStyle("FindTitle", parent=normal, fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#0F172A"))),
                                Paragraph(f"<b>{item.severity.upper()}</b>", badge_style),
                            ]
                        ],
                        colWidths=[414, 90],
                        style=[
                            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#F8FAFC")),
                            ("BACKGROUND", (1, 0), (1, 0), sev_color),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                            ("PADDING", (0, 0), (-1, -1), 5),
                        ],
                    ),
                    # Meta info
                    Table(
                        [
                            [
                                Paragraph("<b>CVSS Score:</b>", meta_label),
                                Paragraph(cvss_display, meta_val),
                                Paragraph("<b>Tool Origin:</b>", meta_label),
                                Paragraph(item.found_by_tool.upper() if item.found_by_tool else "AI Agent", meta_val),
                                Paragraph("<b>CVE(s):</b>", meta_label),
                                Paragraph(cves, meta_val),
                            ]
                        ],
                        colWidths=[70, 70, 75, 95, 55, 139],
                        style=[
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                            ("PADDING", (0, 0), (-1, -1), 4),
                            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                        ],
                    ),
                    # Description
                    Spacer(1, 4),
                    Paragraph(f"<b>Description:</b> {item.description or 'No description provided.'}", body),
                ]

                # Evidence
                if item.evidence:
                    clean_evidence = item.evidence[:800] + ("..." if len(item.evidence) > 800 else "")
                    finding_block.append(Paragraph(f"<b>Technical Evidence / Observations:</b><br/><code>{clean_evidence}</code>", body))

                # Remediation
                if item.remediation:
                    remed_table = Table(
                        [[Paragraph(f"<b>Recommended Action / Fix:</b><br/>{item.remediation}", body)]],
                        colWidths=[504],
                        style=[
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
                            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#86EFAC")),
                            ("PADDING", (0, 0), (-1, -1), 6),
                        ],
                    )
                    finding_block.append(Spacer(1, 3))
                    finding_block.append(remed_table)

                finding_block.append(Spacer(1, 14))
                story.append(KeepTogether(finding_block))

        # =====================================================================
        # 5. REMEDIATION ROADMAP & SIGN-OFF
        # =====================================================================
        story.append(Spacer(1, 10))
        story.append(Paragraph("4. Strategic Remediation Roadmap", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0"), spaceAfter=10))

        roadmap = (
            "CyberGuard AI recommends prioritizing fixes based on exploitability and impact:<br/>"
            "1. <b>Immediate (24–48 Hours):</b> Remediate all CRITICAL vulnerabilities, especially unauthenticated RCE, "
            "exposed admin panels, or database injection vectors.<br/>"
            "2. <b>Near-Term (1–2 Weeks):</b> Patch HIGH-severity findings such as outdated server software, SSL misconfigurations, "
            "and missing security headers.<br/>"
            "3. <b>Scheduled Sprint (30 Days):</b> Resolve MEDIUM and LOW vulnerabilities including informational disclosures "
            "and service banners.<br/>"
            "4. <b>Verification:</b> Re-run CyberGuard AI assessment pipeline to validate closure."
        )
        story.append(Paragraph(roadmap, body))

        # Sign-off box
        story.append(Spacer(1, 30))
        sign_table = Table(
            [
                [Paragraph("<b>Lead Security Analyst:</b> CyberGuard AI Autonomous Engine", meta_label), Paragraph("<b>Signature / Approval:</b> Verified [Authorized Lab]", meta_label)],
                [Paragraph("<b>Report Generated:</b> " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"), meta_val), Paragraph("<b>Assessment State:</b> " + assessment.status.upper(), meta_val)],
            ],
            colWidths=[252, 252],
            style=[
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#94A3B8")),
                ("PADDING", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ],
        )
        story.append(sign_table)

        # Build PDF
        doc.build(story, canvasmaker=NumberedCanvas)

        # Register report record in database
        report_record = Report(
            assessment_id=assessment_id,
            title=f"VAPT Report - {assessment.name}",
            executive_summary=exec_summary,
            filepath=output_path,
        )
        self.db.add(report_record)
        await self.db.commit()

        return output_path
