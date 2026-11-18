"""Epistemic Agent Memory SDK — Adaptador in-process e Function-Calling sobre o Epistemic Memory Core."""
from __future__ import annotations

from .client import (
    EpistemicAccessDeniedError,
    EpistemicMemoryClient,
    ErrorCode,
    bootstrap_workspace_env,
    make_operation_key,
)

__version__ = "0.5.7"

__all__ = [
    "__version__",
    "EpistemicAccessDeniedError",
    "EpistemicMemoryClient",
    "ErrorCode",
    "bootstrap_workspace_env",
    "make_operation_key",
]
