"""Interactive, single-use authorization for Reddit write operations."""

from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import click

from .exceptions import WriteBlockedError

WRITE_POLICY = "interactive_confirmation"
_GATE_ISSUER = object()


def _canonical_payload(data: Mapping[str, Any] | None) -> tuple[tuple[str, str], ...]:
    if data is None:
        return ()
    return tuple(sorted((str(name), str(value)) for name, value in data.items()))


@dataclass(frozen=True)
class WriteAuthorization:
    """Capability for one exact Reddit write request."""

    method: str
    endpoint: str
    payload: tuple[tuple[str, str], ...]
    _issuer: object | None = field(default=None, repr=False, compare=False)

    def allows(self, method: str, endpoint: str, data: Mapping[str, Any] | None) -> bool:
        return (
            self._issuer is _GATE_ISSUER
            and self.method == method.upper()
            and self.endpoint == endpoint
            and self.payload == _canonical_payload(data)
        )


def _is_interactive() -> bool:
    return bool(click.get_text_stream("stdin").isatty())


def authorize_write(
    *,
    operation: str,
    target: str,
    endpoint: str,
    data: Mapping[str, Any],
) -> WriteAuthorization:
    """Require a human-visible TTY challenge for one exact write."""
    if not _is_interactive():
        raise WriteBlockedError("Reddit writes require an interactive terminal")

    challenge = secrets.token_hex(3).upper()
    expected = f"WRITE {operation.upper()} {challenge}"
    safe_target = json.dumps(target, ensure_ascii=True)

    click.echo(f"Reddit write requested: {operation} target={safe_target}", err=True)
    click.echo(f"Type exactly to authorize this one request: {expected}", err=True)
    click.echo("Confirmation: ", nl=False, err=True)

    try:
        response = click.get_text_stream("stdin").readline()
    except (KeyboardInterrupt, EOFError) as exc:
        raise WriteBlockedError("Reddit write authorization was cancelled") from exc

    if not response:
        raise WriteBlockedError("Reddit write authorization reached end of input")
    if not secrets.compare_digest(response.rstrip("\r\n"), expected):
        raise WriteBlockedError("Reddit write authorization did not match")

    return WriteAuthorization(
        method="POST",
        endpoint=endpoint,
        payload=_canonical_payload(data),
        _issuer=_GATE_ISSUER,
    )
