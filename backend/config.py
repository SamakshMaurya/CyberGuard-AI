"""
CyberGuard AI — Configuration Module

Loads all application settings from environment variables with sensible defaults.
Uses python-dotenv to support .env files for local development.
"""

import os
import ipaddress
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application-wide settings loaded from environment variables."""

    # --- LLM Configuration ---
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", "")
    LLM_API_URL: str = os.getenv("LLM_API_URL", "https://api.openai.com/v1")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4")

    # --- Database ---
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./cyberguard.db")

    # --- OWASP ZAP ---
    ZAP_API_KEY: str = os.getenv("ZAP_API_KEY", "")
    ZAP_URL: str = os.getenv("ZAP_URL", "http://localhost:8080")

    # --- Safety & Authorization ---
    ALLOWED_TARGETS_RAW: str = os.getenv(
        "ALLOWED_TARGETS",
        "127.0.0.1,localhost,scanme.nmap.org,10.0.0.0/8,192.168.0.0/16",
    )
    REQUIRE_HUMAN_APPROVAL_FOR_EXPLOITATION: bool = os.getenv(
        "REQUIRE_HUMAN_APPROVAL", "true"
    ).lower() in ("true", "1", "yes")

    # --- Reports ---
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", "reports")

    # --- Server ---
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    @property
    def allowed_targets(self) -> List[str]:
        """Parse the comma-separated ALLOWED_TARGETS into a list."""
        return [t.strip() for t in self.ALLOWED_TARGETS_RAW.split(",") if t.strip()]

    def is_target_authorized(self, target: str) -> bool:
        """
        Check whether *target* (hostname or IP) falls within any allowed target
        or CIDR range.  Hostnames are compared case-insensitively.
        """
        target_lower = target.lower().strip()
        for allowed in self.allowed_targets:
            allowed_lower = allowed.lower().strip()
            # Exact hostname / IP match
            if target_lower == allowed_lower:
                return True
            # CIDR match
            try:
                network = ipaddress.ip_network(allowed, strict=False)
                target_ip = ipaddress.ip_address(target)
                if target_ip in network:
                    return True
            except (ValueError, TypeError):
                # allowed or target is not a valid IP/CIDR — skip
                continue
        return False


settings = Settings()
