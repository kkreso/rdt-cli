"""Authentication for Reddit CLI.

Credential chain: environment variables, then ~/.config/rdt-cli/credential.json.
This fork never reads browser cookie stores.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from .constants import (
    CREDENTIAL_FILE,
    ENV_COOKIE,
    ENV_MODHASH,
    ENV_SESSION,
)

logger = logging.getLogger(__name__)

# ── Credential data class ───────────────────────────────────────────


class Credential:
    """Holds Reddit session cookies."""

    def __init__(
        self,
        cookies: dict[str, str],
        *,
        source: str = "unknown",
        username: str | None = None,
        modhash: str | None = None,
        saved_at: float | None = None,
        last_verified_at: float | None = None,
    ):
        self.cookies = cookies
        self.source = source
        self.username = username
        self.modhash = modhash
        self.saved_at = saved_at
        self.last_verified_at = last_verified_at

    @property
    def is_valid(self) -> bool:
        return bool(self.cookies)

    def to_dict(self) -> dict[str, Any]:
        saved_at = self.saved_at or time.time()
        return {
            "cookies": self.cookies,
            "source": self.source,
            "username": self.username,
            "modhash": self.modhash,
            "saved_at": saved_at,
            "last_verified_at": self.last_verified_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Credential:
        return cls(
            cookies=data.get("cookies", {}),
            source=data.get("source", "saved"),
            username=data.get("username"),
            modhash=data.get("modhash"),
            saved_at=data.get("saved_at"),
            last_verified_at=data.get("last_verified_at"),
        )

    def as_cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())


# ── Persistence ─────────────────────────────────────────────────────


def load_credential() -> Credential | None:
    """Load the saved credential file."""
    if not CREDENTIAL_FILE.exists():
        return None
    try:
        data = json.loads(CREDENTIAL_FILE.read_text())
        cred = Credential.from_dict(data)
        if not cred.is_valid:
            return None

        return cred
    except (json.JSONDecodeError, KeyError):
        return None


def clear_credential() -> None:
    """Remove saved credential file."""
    if CREDENTIAL_FILE.exists():
        CREDENTIAL_FILE.unlink()


# ── Environment variable credential ─────────────────────────────────


def parse_cookie_header(header: str) -> dict[str, str]:
    """Parse a raw Cookie header ("a=1; b=2") into a name→value dict.

    Splits each pair on the first '=' only (cookie values such as JWTs may
    contain '='). Blank segments and nameless pairs are skipped.
    """
    cookies: dict[str, str] = {}
    for part in header.split(";"):
        name, sep, value = part.strip().partition("=")
        name = name.strip()
        if not sep or not name:
            continue
        cookies[name] = value.strip()
    return cookies


def extract_env_credential() -> Credential | None:
    """Build a credential from environment variables (no browser access).

    - RDT_COOKIE  : full raw Cookie header (most robust — carries the whole set)
    - RDT_SESSION : reddit_session cookie value (convenience; overlays RDT_COOKIE)
    - RDT_MODHASH : modhash (enables write actions)

    Returned in-memory only; env credentials are never written to disk.
    """
    raw = os.getenv(ENV_COOKIE)
    session = os.getenv(ENV_SESSION)
    modhash = os.getenv(ENV_MODHASH)

    cookies: dict[str, str] = {}
    if raw:
        cookies.update(parse_cookie_header(raw))
    if session:
        cookies["reddit_session"] = session.strip()
    if modhash:
        cookies["modhash"] = modhash.strip()

    if not cookies:
        return None

    return Credential(
        cookies=cookies,
        source="env",
        modhash=modhash.strip() if modhash else None,
    )


# ── Credential chain ────────────────────────────────────────────────


def get_credential() -> Credential | None:
    """Resolve a credential: environment variables, then the saved file, else None."""
    return extract_env_credential() or load_credential()
