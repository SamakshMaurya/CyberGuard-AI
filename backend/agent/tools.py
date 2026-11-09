"""
CyberGuard AI — Agent Tool Definitions

Structured descriptions of every tool available to the SecurityAgent for
LLM function-calling.  Each entry includes a JSON-Schema–compatible
parameter spec and a flag indicating whether human approval is required
before execution.
"""

from typing import Any, Dict, List

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": (
                "Run an Nmap network scan against a target host or subnet. "
                "Use this for host discovery, port scanning, service/version "
                "detection, OS fingerprinting, and vulnerability script scans."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address, hostname, or CIDR range to scan.",
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": [
                            "quick",
                            "full",
                            "service_detection",
                            "vuln_scan",
                            "os_detection",
                        ],
                        "description": (
                            "Type of Nmap scan to perform: "
                            "'quick' — ping sweep / fast port scan (-sn); "
                            "'full' — SYN scan with service/OS detection (-sS -sV -O -A); "
                            "'service_detection' — version detection only (-sV); "
                            "'vuln_scan' — run NSE vuln scripts (--script vuln); "
                            "'os_detection' — OS fingerprinting (-O)."
                        ),
                    },
                    "ports": {
                        "type": "string",
                        "description": (
                            "Optional port specification (e.g. '22,80,443' or '1-1024'). "
                            "Omit for default port selection."
                        ),
                    },
                },
                "required": ["target", "scan_type"],
            },
        },
        "requires_approval": False,
        "risk_level": "low",
    },
    {
        "type": "function",
        "function": {
            "name": "zap_scan",
            "description": (
                "Run an OWASP ZAP web application scan against a URL. "
                "Use this for web crawling (spidering), passive analysis, "
                "and active vulnerability scanning of web applications."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL (e.g. http://example.com) to scan.",
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": [
                            "spider",
                            "active_scan",
                            "passive_scan",
                            "ajax_spider",
                        ],
                        "description": (
                            "Type of ZAP scan: "
                            "'spider' — crawl the application to discover pages; "
                            "'active_scan' — actively test for vulnerabilities (CAUTION: may modify data); "
                            "'passive_scan' — analyse responses without sending attack payloads; "
                            "'ajax_spider' — crawl JavaScript-heavy applications."
                        ),
                    },
                },
                "required": ["target", "scan_type"],
            },
        },
        "requires_approval": False,  # active_scan checked at runtime
        "risk_level": "medium",
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_scan",
            "description": (
                "Run a Nikto web server scanner against a target URL. "
                "Nikto checks for dangerous files, outdated server software, "
                "version-specific problems, and server configuration issues."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL or host:port to scan.",
                    },
                    "options": {
                        "type": "string",
                        "description": (
                            "Additional Nikto CLI options (e.g. '-Tuning x' to "
                            "select specific test types). Optional."
                        ),
                    },
                },
                "required": ["target"],
            },
        },
        "requires_approval": False,
        "risk_level": "low",
    },
    {
        "type": "function",
        "function": {
            "name": "generate_report",
            "description": (
                "Generate a professional PDF VAPT report for the current "
                "assessment. Includes executive summary, findings, remediation "
                "guidance, and appendices."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {
                        "type": "integer",
                        "description": "ID of the assessment to generate a report for.",
                    },
                },
                "required": ["assessment_id"],
            },
        },
        "requires_approval": False,
        "risk_level": "none",
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings",
            "description": (
                "Retrieve security findings for the current assessment, "
                "optionally filtered by severity level."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {
                        "type": "integer",
                        "description": "ID of the assessment.",
                    },
                    "severity_filter": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Optional severity level to filter by.",
                    },
                },
                "required": ["assessment_id"],
            },
        },
        "requires_approval": False,
        "risk_level": "none",
    },
    {
        "type": "function",
        "function": {
            "name": "correlate_findings",
            "description": (
                "Analyse and correlate findings across all scans in an "
                "assessment. Identifies duplicates, attack chains, and "
                "re-assesses severity with the full picture in mind."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_id": {
                        "type": "integer",
                        "description": "ID of the assessment to correlate.",
                    },
                },
                "required": ["assessment_id"],
            },
        },
        "requires_approval": False,
        "risk_level": "none",
    },
]


def get_openai_tools() -> List[Dict[str, Any]]:
    """
    Return tool definitions in the format expected by the OpenAI
    chat-completions API (type + function, no extra keys).
    """
    return [
        {"type": t["type"], "function": t["function"]}
        for t in TOOL_DEFINITIONS
    ]


def tool_requires_approval(tool_name: str, arguments: dict | None = None) -> bool:
    """
    Determine whether executing *tool_name* with *arguments* requires
    human approval.

    Rules:
    - ZAP ``active_scan`` always requires approval (it sends attack payloads).
    - Nmap ``vuln_scan`` requires approval (runs exploit-adjacent scripts).
    - Any tool explicitly flagged ``requires_approval=True``.
    """
    # Runtime checks
    if tool_name == "zap_scan" and arguments and arguments.get("scan_type") == "active_scan":
        return True
    if tool_name == "nmap_scan" and arguments and arguments.get("scan_type") == "vuln_scan":
        return True

    for t in TOOL_DEFINITIONS:
        if t["function"]["name"] == tool_name:
            return t.get("requires_approval", False)

    return False


def get_tool_description(tool_name: str) -> str:
    """Return the natural-language description for a tool."""
    for t in TOOL_DEFINITIONS:
        if t["function"]["name"] == tool_name:
            return t["function"]["description"]
    return "Unknown tool."
