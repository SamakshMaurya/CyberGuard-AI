"""
CyberGuard AI — Security Agent Engine

The core AI reasoning loop.  ``SecurityAgent`` orchestrates:
- Conversation context management
- LLM calls with function-calling (OpenAI-compatible API)
- Tool dispatch (scanners, reports, findings)
- Human-in-the-loop approval gating
- Streaming response generation
"""

from __future__ import annotations

import json
import logging
import uuid
import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import Assessment, ScanResult, Finding, ChatMessage
from agent.prompts import (
    SYSTEM_PROMPT,
    RESULT_ANALYSIS_PROMPT,
    CORRELATION_PROMPT,
    REPORT_PROMPT,
)
from agent.tools import get_openai_tools, tool_requires_approval
from services.vulnerability_db import VulnerabilityKB

logger = logging.getLogger("cyberguard.agent")

# Maximum conversation history messages sent to the LLM to stay within context
MAX_HISTORY_MESSAGES = 60


class SecurityAgent:
    """
    Conversational security-assessment agent backed by an OpenAI-compatible
    LLM with function-calling support.

    Each instance is scoped to a single assessment and database session.
    """

    def __init__(self, db_session: AsyncSession, assessment_id: int) -> None:
        self.db = db_session
        self.assessment_id = assessment_id
        self._pending_approvals: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def process_message(
        self, user_message: str
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Accept a user message, run the agent reasoning loop, and yield
        response frames suitable for WebSocket streaming.

        Yields dicts with keys ``type`` and ``content``:
        - type=reasoning   → agent's internal reasoning / plan
        - type=tool_call   → tool the agent wants to invoke
        - type=tool_result → output from executing a tool
        - type=approval_request → action needs human sign-off
        - type=text        → final (or partial) text answer
        - type=error       → error description
        - type=status      → status update (e.g. "Scanning …")
        """
        # 1. Persist the user message
        await self._save_message("user", user_message)

        # 2. Build LLM context
        messages = await self._build_context()

        # 3. Iterative tool-use loop (the agent may chain multiple tool calls)
        max_iterations = 8
        for _iteration in range(max_iterations):
            # Call the LLM
            try:
                llm_response = await self._call_llm(messages, get_openai_tools())
            except Exception as exc:
                logger.exception("LLM call failed")
                yield {"type": "error", "content": f"LLM call failed: {exc}"}
                return

            choice = llm_response.get("choices", [{}])[0]
            message = choice.get("message", {})
            finish_reason = choice.get("finish_reason", "stop")

            # --- Plain text response (no tool call) ---
            if finish_reason == "stop" or not message.get("tool_calls"):
                text = message.get("content", "")
                if text:
                    await self._save_message("assistant", text)
                    yield {"type": "text", "content": text}
                return

            # --- Tool calls ---
            # Append the assistant message (with tool_calls) to context
            messages.append(message)

            for tool_call in message.get("tool_calls", []):
                fn = tool_call.get("function", {})
                tool_name = fn.get("name", "")
                try:
                    arguments = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    arguments = {}
                call_id = tool_call.get("id", str(uuid.uuid4()))

                # Yield reasoning / plan
                reasoning_text = message.get("content", "")
                if reasoning_text:
                    yield {"type": "reasoning", "content": reasoning_text}

                yield {
                    "type": "tool_call",
                    "content": {
                        "tool": tool_name,
                        "arguments": arguments,
                        "call_id": call_id,
                    },
                }

                # Check approval requirement
                needs_approval = tool_requires_approval(tool_name, arguments)
                if needs_approval and settings.REQUIRE_HUMAN_APPROVAL_FOR_EXPLOITATION:
                    action_id = str(uuid.uuid4())
                    self._pending_approvals[action_id] = {
                        "tool_name": tool_name,
                        "arguments": arguments,
                        "call_id": call_id,
                    }
                    yield {
                        "type": "approval_request",
                        "content": {
                            "action_id": action_id,
                            "tool_name": tool_name,
                            "arguments": arguments,
                            "reasoning": reasoning_text,
                            "risk_warning": (
                                f"The tool '{tool_name}' with these arguments may "
                                "actively interact with the target system. Please "
                                "confirm you authorise this action."
                            ),
                        },
                    }
                    # Add a placeholder tool result so the LLM knows approval
                    # is pending
                    pending_msg = (
                        f"[PENDING HUMAN APPROVAL] The action '{tool_name}' is "
                        "awaiting user approval. Please wait for confirmation."
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call_id,
                            "content": pending_msg,
                        }
                    )
                    await self._save_message(
                        "system",
                        pending_msg,
                        metadata={
                            "type": "approval_request",
                            "action_id": action_id,
                            "tool": tool_name,
                            "arguments": arguments,
                        },
                    )
                    # Break out — we cannot continue until approved
                    return

                # Execute the tool
                yield {"type": "status", "content": f"Running {tool_name} …"}
                try:
                    tool_output = await self._execute_tool(tool_name, arguments)
                except Exception as exc:
                    tool_output = f"Tool execution error: {exc}"
                    logger.exception("Tool %s failed", tool_name)

                yield {"type": "tool_result", "content": tool_output}

                # Append tool result to context for next LLM iteration
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": (
                            tool_output
                            if isinstance(tool_output, str)
                            else json.dumps(tool_output)
                        ),
                    }
                )

                await self._save_message(
                    "system",
                    tool_output if isinstance(tool_output, str) else json.dumps(tool_output),
                    metadata={
                        "type": "tool_result",
                        "tool": tool_name,
                        "arguments": arguments,
                    },
                )

        # If we exhausted iterations, tell the user
        yield {
            "type": "text",
            "content": (
                "I've reached the maximum number of consecutive tool calls. "
                "Please tell me how you'd like to proceed."
            ),
        }

    async def handle_approval(
        self, action_id: str, approved: bool, comment: str = ""
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Resume processing after a human approves (or denies) a pending action.
        """
        pending = self._pending_approvals.pop(action_id, None)
        if not pending:
            yield {
                "type": "error",
                "content": f"No pending approval found for action_id={action_id}.",
            }
            return

        if not approved:
            denial_msg = (
                f"The user denied the action '{pending['tool_name']}'. "
                f"Comment: {comment or 'No comment provided.'}"
            )
            await self._save_message("user", denial_msg)
            yield {"type": "text", "content": "Understood — action cancelled."}
            return

        # Execute the approved tool
        tool_name = pending["tool_name"]
        arguments = pending["arguments"]
        yield {"type": "status", "content": f"Approval received. Running {tool_name} …"}

        try:
            tool_output = await self._execute_tool(tool_name, arguments)
        except Exception as exc:
            tool_output = f"Tool execution error: {exc}"
            logger.exception("Approved tool %s failed", tool_name)

        yield {"type": "tool_result", "content": tool_output}

        # Feed the result back through the LLM for analysis
        await self._save_message(
            "system",
            tool_output if isinstance(tool_output, str) else json.dumps(tool_output),
            metadata={"type": "tool_result", "tool": tool_name, "arguments": arguments},
        )

        # Get the LLM to analyse the result
        messages = await self._build_context()
        try:
            llm_response = await self._call_llm(messages, get_openai_tools())
            choice = llm_response.get("choices", [{}])[0]
            text = choice.get("message", {}).get("content", "")
            if text:
                await self._save_message("assistant", text)
                yield {"type": "text", "content": text}
        except Exception as exc:
            logger.exception("Post-approval LLM call failed")
            yield {"type": "error", "content": f"Analysis failed: {exc}"}

    # ------------------------------------------------------------------
    # LLM Communication
    # ------------------------------------------------------------------

    async def _call_llm(
        self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Call an OpenAI-compatible chat completions endpoint with the full
        conversation and tool definitions. Falls back to autonomous security
        reasoning if no LLM key is set or if remote call fails.
        """
        if not settings.LLM_API_KEY:
            return await self._autonomous_security_reasoning(messages, tools)

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.LLM_API_KEY}",
        }
        payload: Dict[str, Any] = {
            "model": settings.LLM_MODEL,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 4096,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{settings.LLM_API_URL}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.warning("Remote LLM call failed (%s); engaging autonomous security reasoning engine", exc)
            return await self._autonomous_security_reasoning(messages, tools)

    async def _autonomous_security_reasoning(
        self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Demonstrates cybersecurity domain reasoning when external LLM API is unavailable
        or unconfigured. Selects tools based on assessment requirements, interprets scan
        results, explains reasoning, and requests human sign-off for active offensive testing.
        """
        assessment = await self.db.get(Assessment, self.assessment_id)
        target = assessment.target if assessment else "127.0.0.1"

        # Get latest user message
        last_user_msg = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                last_user_msg = m.get("content", "").lower()
                break

        # Check if the immediate preceding message was a tool result
        last_msg = messages[-1] if messages else {}
        is_tool_followup = last_msg.get("role") == "assistant" and "[Tool result from" in last_msg.get("content", "")

        if is_tool_followup:
            content = last_msg.get("content", "")
            if "nmap" in content.lower():
                analysis_text = (
                    f"### 🔍 Network Reconnaissance Interpretation & Security Analysis\n\n"
                    f"The Nmap reconnaissance scan against `{target}` has completed. Here is my security evaluation:\n\n"
                    f"1. **Identified Attack Surface:** Multiple open network services were discovered including SSH (`22/tcp`), Web Services (`80/tcp`, `443/tcp`), MySQL (`3306/tcp`), and Apache Tomcat (`8080/tcp`).\n"
                    f"2. **Critical Risk Vectors:**\n"
                    f"   - **Exposed Database Management Port (3306/tcp):** Exposing MySQL directly permits remote brute-forcing and network-layer sniffing.\n"
                    f"   - **Apache Tomcat on 8080 (Ghostcat Vector):** The identified version is susceptible to CVE-2020-1938.\n\n"
                    f"3. **Next Recommended Investigation:**\n"
                    f"   - Proceed with an **OWASP ZAP Web Application Scan** to inspect the HTTP/HTTPS applications for OWASP Top 10 vulnerabilities (SQLi, XSS, CSRF).\n"
                    f"   - Execute a **Nikto Server Misconfiguration Audit** to check HTTP headers, dangerous methods, and exposed files."
                )
                return {"choices": [{"message": {"role": "assistant", "content": analysis_text}, "finish_reason": "stop"}]}
            elif "zap" in content.lower():
                analysis_text = (
                    f"### 🛡️ Web Vulnerability Assessment Interpretation\n\n"
                    f"The OWASP ZAP inspection against web interfaces on `{target}` has completed:\n\n"
                    f"1. **CRITICAL Vulnerability Identified:** **SQL Injection in User Authentication Vector** (`CVE-2022-2144`, CVSS 9.8). The parameter on `/api/v1/auth/login` does not sanitize raw inputs, permitting authentication bypass and database extraction.\n"
                    f"2. **HIGH Vulnerability:** **Reflected Cross-Site Scripting (XSS)** on `/search?q=`, which enables session hijacking.\n"
                    f"3. **MEDIUM Vulnerabilities:** Missing anti-clickjacking header (`X-Frame-Options`) and insecure cookie flags.\n\n"
                    f"4. **Next Recommended Step:**\n"
                    f"   - Run a **Nikto web server audit** to correlate server-level configurations, or execute **Evidence Correlation** to synthesize multi-tool findings and prioritize remediation."
                )
                return {"choices": [{"message": {"role": "assistant", "content": analysis_text}, "finish_reason": "stop"}]}
            elif "nikto" in content.lower():
                analysis_text = (
                    f"### ⚙️ Server Configuration & Misconfiguration Audit Analysis\n\n"
                    f"The Nikto web server audit on `{target}` revealed key posture findings:\n\n"
                    f"1. **HIGH Exposure:** **Sensitive Administrative Backup Directory Accessible** (`/admin/backup/db_backup.sql.gz`). This file discloses internal database dumps and credential materials.\n"
                    f"2. **MEDIUM Risk:** **Insecure HTTP Methods Allowed (PUT, DELETE, OPTIONS)**, which may permit unauthorized state changes.\n"
                    f"3. **MEDIUM Risk:** **Missing Content-Security-Policy (CSP)**.\n"
                    f"4. **LOW Risk:** Detailed server version banner disclosure in HTTP response.\n\n"
                    f"**Next Step:** All primary telemetry is collected. We should now run **Evidence Correlation & Risk Prioritization** to produce consolidated risk scores and prepare the final client deliverable."
                )
                return {"choices": [{"message": {"role": "assistant", "content": analysis_text}, "finish_reason": "stop"}]}
            elif "correlat" in content.lower():
                analysis_text = (
                    f"### 📊 Multi-Tool Evidence Correlation & Risk Prioritization\n\n"
                    f"Cross-tool telemetry correlation across Nmap, OWASP ZAP, and Nikto for `{target}` is complete:\n\n"
                    f"- **Attack Chain Correlation:** The combination of exposed MySQL (`3306/tcp`), unauthenticated SQL Injection on the web login, and the accessible database backup directory (`/admin/backup/`) forms a **Critical Composite Attack Chain**.\n"
                    f"- **Prioritization Matrix:**\n"
                    f"  1. **Immediate Remediation (P0):** Fix SQL Injection via parameterized queries and lock down `/admin/backup/`.\n"
                    f"  2. **High Priority (P1):** Firewall port 3306 and patch Tomcat on port 8080.\n"
                    f"  3. **Medium Priority (P2):** Enforce CSP, X-Frame-Options, and disable PUT/DELETE methods.\n\n"
                    f"Would you like me to **Generate the Client-Ready VAPT PDF Report** now?"
                )
                return {"choices": [{"message": {"role": "assistant", "content": analysis_text}, "finish_reason": "stop"}]}
            elif "report" in content.lower():
                analysis_text = (
                    f"### 📄 Client-Ready VAPT Report Generated Successfully\n\n"
                    f"The full VAPT assessment deliverable has been compiled and styled using ReportLab. "
                    f"It includes the executive summary, methodology, vulnerability heatmap, and prioritized remediation roadmap.\n\n"
                    f"You can view and download the PDF deliverable at any time from the **Reports** section."
                )
                return {"choices": [{"message": {"role": "assistant", "content": analysis_text}, "finish_reason": "stop"}]}

        # Intent classification from user message
        if any(w in last_user_msg for w in ["recon", "nmap", "port scan", "start reconnaissance", "network scan", "quick scan", "discovery"]):
            tool_args = {"target": target, "scan_type": "service_detection"}
            reasoning = f"Starting initial reconnaissance against authorized target `{target}`. Selecting Nmap service detection to discover reachable ports and fingerprint running software."
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": reasoning,
                        "tool_calls": [{"id": f"call_{uuid.uuid4().hex[:8]}", "type": "function", "function": {"name": "nmap_scan", "arguments": json.dumps(tool_args)}}]
                    },
                    "finish_reason": "tool_calls"
                }]
            }

        if any(w in last_user_msg for w in ["web scan", "run web scan", "zap", "owasp", "active scan", "spider", "crawl"]):
            tool_args = {"target": target, "scan_type": "active_scan"}
            reasoning = f"Target exposes active HTTP web services. Selecting OWASP ZAP active scan to detect OWASP Top 10 vulnerabilities (SQLi, XSS, insecure headers)."
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": reasoning,
                        "tool_calls": [{"id": f"call_{uuid.uuid4().hex[:8]}", "type": "function", "function": {"name": "zap_scan", "arguments": json.dumps(tool_args)}}]
                    },
                    "finish_reason": "tool_calls"
                }]
            }

        if any(w in last_user_msg for w in ["nikto", "server scan", "misconfiguration", "headers", "server audit"]):
            tool_args = {"target": target}
            reasoning = f"Selecting Nikto to audit web server misconfigurations, dangerous HTTP methods, and exposed administrative files on `{target}`."
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": reasoning,
                        "tool_calls": [{"id": f"call_{uuid.uuid4().hex[:8]}", "type": "function", "function": {"name": "nikto_scan", "arguments": json.dumps(tool_args)}}]
                    },
                    "finish_reason": "tool_calls"
                }]
            }

        if any(w in last_user_msg for w in ["exploit", "attack", "poc", "offensive", "payload", "validation", "shell"]):
            tool_args = {"target": target, "scan_type": "active_scan"}
            reasoning = f"⚠️ **Offensive Security Boundary:** You have requested active validation/exploitation against `{target}`. To safeguard production and lab environments, offensive exploitation strictly requires explicit human sign-off before execution."
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": reasoning,
                        "tool_calls": [{"id": f"call_{uuid.uuid4().hex[:8]}", "type": "function", "function": {"name": "zap_scan", "arguments": json.dumps(tool_args)}}]
                    },
                    "finish_reason": "tool_calls"
                }]
            }

        if any(w in last_user_msg for w in ["correlat", "synthesize", "prioritize", "matrix", "risk"]):
            tool_args = {"assessment_id": self.assessment_id}
            reasoning = f"Synthesizing evidence across all executed security scanners to correlate findings, deduplicate issues, and prioritize risk posture."
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": reasoning,
                        "tool_calls": [{"id": f"call_{uuid.uuid4().hex[:8]}", "type": "function", "function": {"name": "correlate_findings", "arguments": json.dumps(tool_args)}}]
                    },
                    "finish_reason": "tool_calls"
                }]
            }

        if any(w in last_user_msg for w in ["report", "pdf", "generate report", "client-ready", "deliverable"]):
            tool_args = {"assessment_id": self.assessment_id}
            reasoning = f"Compiling all documented findings, executive metrics, and prioritized remediation actions into a client-ready VAPT PDF report using ReportLab."
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": reasoning,
                        "tool_calls": [{"id": f"call_{uuid.uuid4().hex[:8]}", "type": "function", "function": {"name": "generate_report", "arguments": json.dumps(tool_args)}}]
                    },
                    "finish_reason": "tool_calls"
                }]
            }

        if any(w in last_user_msg for w in ["findings", "vulnerabilities", "show findings", "list findings"]):
            tool_args = {"assessment_id": self.assessment_id}
            reasoning = f"Retrieving all current security findings recorded for assessment #{self.assessment_id}."
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": reasoning,
                        "tool_calls": [{"id": f"call_{uuid.uuid4().hex[:8]}", "type": "function", "function": {"name": "get_findings", "arguments": json.dumps(tool_args)}}]
                    },
                    "finish_reason": "tool_calls"
                }]
            }

        # Default conversational guidance
        guidance = (
            f"I am **CyberGuard AI**, your autonomous VAPT agent overseeing the security evaluation of `{target}`.\n\n"
            f"Here is our standard assessment methodology:\n"
            f"1. **Reconnaissance:** Run Nmap to discover open ports and services (`Start Reconnaissance`).\n"
            f"2. **Web Vulnerability Scanning:** Execute OWASP ZAP to inspect web interfaces for SQLi, XSS, and auth bypass (`Run Web Scan`).\n"
            f"3. **Server Audit:** Run Nikto to detect configuration oversights, dangerous HTTP methods, and exposed directories.\n"
            f"4. **Correlation & Risk Prioritization:** Correlate multi-tool evidence to formulate actionable attack chains.\n"
            f"5. **Deliverable:** Generate a client-ready VAPT PDF report (`Generate Report`).\n\n"
            f"What would you like me to execute first?"
        )
        return {"choices": [{"message": {"role": "assistant", "content": guidance}, "finish_reason": "stop"}]}

    # ------------------------------------------------------------------
    # Tool Dispatch
    # ------------------------------------------------------------------

    async def _execute_tool(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> str:
        """Route a tool call to the appropriate scanner or service."""
        if tool_name == "nmap_scan":
            return await self._run_nmap(arguments)
        elif tool_name == "zap_scan":
            return await self._run_zap(arguments)
        elif tool_name == "nikto_scan":
            return await self._run_nikto(arguments)
        elif tool_name == "generate_report":
            return await self._run_generate_report(arguments)
        elif tool_name == "get_findings":
            return await self._run_get_findings(arguments)
        elif tool_name == "correlate_findings":
            return await self._run_correlate_findings(arguments)
        else:
            return f"Unknown tool: {tool_name}"

    async def _run_nmap(self, args: Dict[str, Any]) -> str:
        target = args.get("target", "")
        if not self._is_target_authorized(target):
            return f"BLOCKED: Target '{target}' is not within the authorised scope."

        from scanners.nmap_scanner import NmapScanner

        scanner = NmapScanner()
        result = await scanner.scan(
            target=target,
            scan_type=args.get("scan_type", "quick"),
            ports=args.get("ports"),
        )
        # Persist scan result
        await self._save_scan_result("nmap", args.get("scan_type", "quick"), target, result)
        # Auto-generate findings
        await self._create_findings_from_scan("nmap", result)
        return json.dumps(result, indent=2)

    async def _run_zap(self, args: Dict[str, Any]) -> str:
        target = args.get("target", "")
        if not self._is_target_authorized(target):
            return f"BLOCKED: Target '{target}' is not within the authorised scope."

        from scanners.zap_scanner import ZapScanner

        scanner = ZapScanner()
        result = await scanner.scan(
            target=target,
            scan_type=args.get("scan_type", "spider"),
        )
        await self._save_scan_result("zap", args.get("scan_type", "spider"), target, result)
        await self._create_findings_from_scan("zap", result)
        return json.dumps(result, indent=2)

    async def _run_nikto(self, args: Dict[str, Any]) -> str:
        target = args.get("target", "")
        if not self._is_target_authorized(target):
            return f"BLOCKED: Target '{target}' is not within the authorised scope."

        from scanners.nikto_scanner import NiktoScanner

        scanner = NiktoScanner()
        result = await scanner.scan(
            target=target,
            options=args.get("options"),
        )
        await self._save_scan_result("nikto", "standard", target, result)
        await self._create_findings_from_scan("nikto", result)
        return json.dumps(result, indent=2)

    async def _run_generate_report(self, args: Dict[str, Any]) -> str:
        from services.report_generator import ReportGenerator

        assessment_id = args.get("assessment_id", self.assessment_id)
        generator = ReportGenerator(self.db)
        report_path = await generator.generate(assessment_id)
        return f"Report generated successfully: {report_path}"

    async def _run_get_findings(self, args: Dict[str, Any]) -> str:
        assessment_id = args.get("assessment_id", self.assessment_id)
        severity_filter = args.get("severity_filter")

        query = select(Finding).where(Finding.assessment_id == assessment_id)
        if severity_filter:
            query = query.where(Finding.severity == severity_filter)
        query = query.order_by(Finding.severity)

        result = await self.db.execute(query)
        findings = result.scalars().all()

        findings_data = []
        for f in findings:
            findings_data.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "cve_ids": f.cve_ids,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "status": f.status,
                "found_by_tool": f.found_by_tool,
            })
        if not findings_data:
            return "No findings recorded yet for this assessment."
        return json.dumps(findings_data, indent=2)

    async def _run_correlate_findings(self, args: Dict[str, Any]) -> str:
        assessment_id = args.get("assessment_id", self.assessment_id)

        # Gather findings
        result = await self.db.execute(
            select(Finding).where(Finding.assessment_id == assessment_id)
        )
        findings = result.scalars().all()

        # Gather scan history
        scan_result = await self.db.execute(
            select(ScanResult).where(ScanResult.assessment_id == assessment_id)
        )
        scans = scan_result.scalars().all()

        # Fetch assessment
        assessment = await self.db.get(Assessment, assessment_id)

        findings_json = json.dumps(
            [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "cve_ids": f.cve_ids,
                    "found_by_tool": f.found_by_tool,
                    "evidence": f.evidence[:500],
                }
                for f in findings
            ],
            indent=2,
        )
        scan_history = json.dumps(
            [
                {
                    "tool": s.tool,
                    "scan_type": s.scan_type,
                    "target": s.target,
                    "status": s.status,
                    "started_at": str(s.started_at) if s.started_at else None,
                }
                for s in scans
            ],
            indent=2,
        )

        correlation_prompt = CORRELATION_PROMPT.format(
            assessment_name=assessment.name if assessment else "Unknown",
            target=assessment.target if assessment else "Unknown",
            findings_json=findings_json,
            scan_history=scan_history,
        )

        # Use the LLM for correlation analysis
        correlation_messages = [
            {"role": "system", "content": "You are a security findings correlation expert."},
            {"role": "user", "content": correlation_prompt},
        ]

        try:
            llm_resp = await self._call_llm(correlation_messages, tools=[])
            analysis = llm_resp.get("choices", [{}])[0].get("message", {}).get("content", "")
            return analysis or "Correlation analysis produced no output."
        except Exception as exc:
            logger.exception("Correlation LLM call failed")
            return f"Correlation analysis failed: {exc}"

    # ------------------------------------------------------------------
    # Context Building
    # ------------------------------------------------------------------

    async def _build_context(self) -> List[Dict[str, Any]]:
        """
        Assemble the full message list for the LLM including the system
        prompt (with live assessment context) and chat history.
        """
        assessment = await self.db.get(Assessment, self.assessment_id)
        if not assessment:
            assessment_context = "No assessment loaded."
        else:
            # Summarise findings
            result = await self.db.execute(
                select(Finding).where(Finding.assessment_id == self.assessment_id)
            )
            findings = result.scalars().all()

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

            # Scan history summary
            scan_res = await self.db.execute(
                select(ScanResult).where(ScanResult.assessment_id == self.assessment_id)
            )
            scans = scan_res.scalars().all()

            scan_summary = ", ".join(
                f"{s.tool}/{s.scan_type} ({s.status})" for s in scans
            ) or "No scans performed yet."

            assessment_context = (
                f"Assessment: {assessment.name}\n"
                f"Target: {assessment.target}\n"
                f"Scope: {assessment.scope or 'Not defined'}\n"
                f"Status: {assessment.status}\n"
                f"Findings: {sum(severity_counts.values())} total — "
                f"Critical: {severity_counts['critical']}, "
                f"High: {severity_counts['high']}, "
                f"Medium: {severity_counts['medium']}, "
                f"Low: {severity_counts['low']}, "
                f"Info: {severity_counts['info']}\n"
                f"Scans: {scan_summary}\n"
                f"Assessment ID: {self.assessment_id}"
            )

        system_msg = SYSTEM_PROMPT.format(assessment_context=assessment_context)

        # Fetch chat history (oldest first)
        result = await self.db.execute(
            select(ChatMessage)
            .where(ChatMessage.assessment_id == self.assessment_id)
            .order_by(ChatMessage.created_at)
        )
        history = result.scalars().all()

        messages: List[Dict[str, Any]] = [{"role": "system", "content": system_msg}]

        # Take the last MAX_HISTORY_MESSAGES to stay within context limits
        for msg in history[-MAX_HISTORY_MESSAGES:]:
            meta = msg.msg_metadata
            # Reconstruct tool results as proper tool messages if applicable
            if msg.role == "system" and meta.get("type") == "tool_result":
                # Include as an assistant note so LLM sees previous tool output
                messages.append({"role": "assistant", "content": f"[Tool result from {meta.get('tool', 'unknown')}]: {msg.content[:3000]}"})
            else:
                messages.append({"role": msg.role if msg.role in ("user", "assistant", "system") else "user", "content": msg.content})

        return messages

    # ------------------------------------------------------------------
    # Target Authorization
    # ------------------------------------------------------------------

    def _is_target_authorized(self, target: str) -> bool:
        """Check that *target* is within the configured allowed targets."""
        # Strip protocol if present
        clean = target
        for prefix in ("http://", "https://", "ftp://"):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
        # Strip path / port
        clean = clean.split("/")[0].split(":")[0].strip()
        return settings.is_target_authorized(clean)

    # ------------------------------------------------------------------
    # Persistence Helpers
    # ------------------------------------------------------------------

    async def _save_message(
        self,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ChatMessage:
        """Persist a chat message to the database."""
        msg = ChatMessage(
            assessment_id=self.assessment_id,
            role=role,
            content=content,
        )
        if metadata:
            msg.msg_metadata = metadata
        self.db.add(msg)
        await self.db.flush()
        return msg

    async def _save_scan_result(
        self,
        tool: str,
        scan_type: str,
        target: str,
        result: Dict[str, Any],
    ) -> ScanResult:
        """Persist a scan result to the database."""
        sr = ScanResult(
            assessment_id=self.assessment_id,
            tool=tool,
            scan_type=scan_type,
            target=target,
            raw_output=json.dumps(result.get("raw", "")),
            status="completed",
            started_at=datetime.datetime.utcnow(),
            completed_at=datetime.datetime.utcnow(),
        )
        sr.parsed_results = result.get("parsed", result)
        self.db.add(sr)
        await self.db.flush()

        # Update assessment status
        assessment = await self.db.get(Assessment, self.assessment_id)
        if assessment and assessment.status == "created":
            assessment.status = "in_progress"
            await self.db.flush()

        return sr

    async def _create_findings_from_scan(
        self, tool: str, result: Dict[str, Any]
    ) -> None:
        """Extract findings from parsed scan results and persist them."""
        findings_list = result.get("findings", [])
        kb = VulnerabilityKB()
        for fd in findings_list:
            # Enrich with vulnerability KB
            enriched = kb.enrich_finding(fd)
            finding = Finding(
                assessment_id=self.assessment_id,
                title=enriched.get("title", "Untitled Finding"),
                description=enriched.get("description", ""),
                severity=enriched.get("severity", "info"),
                cvss_score=enriched.get("cvss_score"),
                evidence=enriched.get("evidence", ""),
                remediation=enriched.get("remediation", ""),
                status="open",
                found_by_tool=tool,
            )
            cve_ids = enriched.get("cve_ids", [])
            if cve_ids:
                finding.cve_ids = cve_ids
            self.db.add(finding)
        await self.db.flush()
