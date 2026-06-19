"""OpenAI-compatible Chat Completions target.

Works with the OpenAI API and any server that speaks the same wire format —
Azure OpenAI, Ollama (``/v1``), vLLM, LM Studio, OpenRouter, Together, etc. Uses
only the standard library so there is no SDK dependency to install.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import Target, TargetError


class OpenAITarget(Target):
    def __init__(
        self,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        system: str | None = None,
        timeout: int = 60,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.system = system
        self.timeout = timeout
        self.label = f"openai:{model} @ {self.base_url}"

    def ask(self, prompt: str) -> str:
        messages = []
        if self.system:
            messages.append({"role": "system", "content": self.system})
        messages.append({"role": "user", "content": prompt})
        body = json.dumps({"model": self.model, "messages": messages}).encode()

        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
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
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise TargetError(f"unexpected response shape: {exc}")
