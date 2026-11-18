"""Epistemic HTTP Gateway & Live Lineage Graph Explorer.

Gateway HTTP/REST local endurecido (100% Python stdlib) para integração de
sistemas externos (Node.js, Go, Rust, C#, webhooks e microsserviços) ao
Epistemic Memory Core, acompanhado de inspetor visual SVG de linhagem e
raio de impacto (*stale-on-write*).
"""
from __future__ import annotations

from .server import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    MAX_BODY_BYTES,
    EpistemicGatewayRuntime,
    bootstrap_gateway_workspace,
    create_gateway_server,
)

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "MAX_BODY_BYTES",
    "EpistemicGatewayRuntime",
    "bootstrap_gateway_workspace",
    "create_gateway_server",
]

__version__ = "0.5.8"
