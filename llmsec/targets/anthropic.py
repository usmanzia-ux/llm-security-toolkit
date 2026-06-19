"""Anthropic Messages API target.

Uses only the standard library. See https://docs.anthropic.com/en/api/messages
for the wire format. The latest models at time of writing include
``claude-opus-4-8``, ``claude-sonnet-4-6`` and ``claude-haiku-4-5``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import Target, TargetError

_API_VERSION = "2023-06-01"


class AnthropicTarget(Target):
    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        base_url: str = "https://api.anthropic.com/v1",
        api_key: str | None = None,
        system: str | None = None,
        max_tokens: int = 1024,
        timeout: int = 60,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.system = system
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.label = f"anthropic:{model}"

    def ask(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if self.system:
            payload["system"] = self.system
        body = json.dumps(payload).encode()

        req = urllib.request.Request(
            f"{self.base_url}/messages",
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": _API_VERSION,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:  # pragma: no cover - network
            raise TargetError(f"HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}")
        except urllib.error.URLError as exc:  # pragma: no cover - network
            raise TargetError(f"connection failed: {exc.reason}")
        try:
            return "".join(
                block.get("text", "")
                for block in data["content"]
                if block.get("type") == "text"
            )
        except (KeyError, TypeError) as exc:
            raise TargetError(f"unexpected response shape: {exc}")
