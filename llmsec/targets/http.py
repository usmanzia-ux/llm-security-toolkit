"""Generic HTTP target — point the scanner at any chatbot endpoint.

Configured from a small YAML/JSON file so you don't need a custom parser for
every bespoke app. The request body is a template containing ``{{prompt}}``;
the response is dug out with a dotted JSON path. Example config in
``examples/http_target.yaml``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict

from .base import Target, TargetError


def _dig(data: Any, path: str) -> Any:
    """Walk a dotted path like ``choices.0.message.content`` (list indices ok)."""
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


class HTTPTarget(Target):
    def __init__(self, config: Dict[str, Any]) -> None:
        self.url = config["url"]
        self.method = config.get("method", "POST").upper()
        self.headers = config.get("headers", {"Content-Type": "application/json"})
        # body_template is a JSON string with a {{prompt}} placeholder.
        self.body_template = config.get("body_template", '{"prompt": "{{prompt}}"}')
        self.response_path = config.get("response_path", "response")
        self.timeout = int(config.get("timeout", 60))
        self.label = config.get("label", f"http:{self.url}")

    def ask(self, prompt: str) -> str:
        # JSON-escape the prompt so quotes/newlines don't corrupt the body.
        safe = json.dumps(prompt)[1:-1]
        body = self.body_template.replace("{{prompt}}", safe).encode()

        req = urllib.request.Request(
            self.url, data=body, headers=self.headers, method=self.method
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode(errors="replace")
        except urllib.error.HTTPError as exc:  # pragma: no cover - network
            raise TargetError(f"HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}")
        except urllib.error.URLError as exc:  # pragma: no cover - network
            raise TargetError(f"connection failed: {exc.reason}")

        if not self.response_path:
            return raw
        try:
            return str(_dig(json.loads(raw), self.response_path))
        except (KeyError, IndexError, ValueError) as exc:
            raise TargetError(f"could not extract '{self.response_path}': {exc}")
