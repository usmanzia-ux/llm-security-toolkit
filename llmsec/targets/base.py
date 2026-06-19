"""The Target abstraction: anything the scanner can send a prompt to.

A target represents the LLM-backed application under test as a black box. The
scanner only controls the *user* message; whatever system prompt, tools or
guardrails the deployed app uses are exactly what we are trying to probe.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class Target(ABC):
    """Send a user prompt to the application, get the model's text reply back."""

    #: human-readable label shown in reports
    label: str = "target"

    @abstractmethod
    def ask(self, prompt: str) -> str:
        """Send a single user prompt and return the assistant's text response."""
        raise NotImplementedError


class TargetError(RuntimeError):
    """Raised when a target cannot be reached or returns an unusable response."""
