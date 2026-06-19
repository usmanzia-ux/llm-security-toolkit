"""Target registry + factory.

``build_target("mock")`` or ``build_target("openai:gpt-4o-mini")`` returns a
ready Target. The string before the colon selects the backend; everything after
is backend-specific (usually the model name).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from .base import Target, TargetError

__all__ = ["Target", "TargetError", "build_target", "BACKENDS"]

BACKENDS = ("mock", "mock-secure", "openai", "anthropic", "http")


def build_target(spec: str, *, system: str | None = None, config_file: str | None = None) -> Target:
    """Construct a Target from a ``backend[:model]`` spec string.

    Examples::

        build_target("mock")
        build_target("mock-secure")
        build_target("openai:gpt-4o-mini")
        build_target("anthropic:claude-sonnet-4-6")
        build_target("http", config_file="examples/http_target.yaml")
    """
    backend, _, detail = spec.partition(":")
    backend = backend.strip().lower()

    if backend == "mock":
        from .mock import MockTarget
        return MockTarget()
    if backend == "mock-secure":
        from .mock import SecureMockTarget
        return SecureMockTarget()
    if backend == "openai":
        from .openai import OpenAITarget
        kwargs: Dict[str, Any] = {"system": system}
        if detail:
            kwargs["model"] = detail
        return OpenAITarget(**kwargs)
    if backend == "anthropic":
        from .anthropic import AnthropicTarget
        kwargs = {"system": system}
        if detail:
            kwargs["model"] = detail
        return AnthropicTarget(**kwargs)
    if backend == "http":
        from .http import HTTPTarget
        if not config_file:
            raise TargetError("http target requires --config <file>")
        return HTTPTarget(_load_config(config_file))

    raise TargetError(f"unknown target backend '{backend}'. Choose from: {', '.join(BACKENDS)}")


def _load_config(path: str) -> Dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    if path.lower().endswith((".yaml", ".yml")):
        import yaml
        return yaml.safe_load(text)
    import json
    return json.loads(text)
