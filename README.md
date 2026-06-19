# llm-security-toolkit

A **black-box security scanner for LLM-backed applications**. Point it at a
chatbot, agent or LLM API endpoint and it runs a battery of adversarial
**probes** mapped to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/),
then produces an assessment report you can hand to engineering or attach to a
pentest.

It ships with a built-in **offline mock target**, so you can clone the repo and
see a full scan — with real findings — in one command, no API key required.

```bash
llmsec --target mock
```

```
                   Scan Results
┏━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Probe     ┃ OWASP      ┃ Severity ┃ Result     ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━┩
│ LLM02-SID │ LLM02:2025 │ Critical │ VULNERABLE │
│ LLM01-PI  │ LLM01:2025 │ High     │ VULNERABLE │
│ LLM01-JB  │ LLM01:2025 │ High     │ VULNERABLE │
│ LLM05-IOH │ LLM05:2025 │ High     │ VULNERABLE │
│ LLM07-SPL │ LLM07:2025 │ Medium   │ VULNERABLE │
└───────────┴────────────┴──────────┴────────────┘
Overall posture: Critical  (5/5 probes vulnerable)
```

## Why

Most LLM security tooling is either a research notebook or a heavyweight
platform. This is a small, dependency-light CLI/library that does one thing
well: **probe a deployed LLM app as an attacker would and report what broke**,
in the vocabulary clients already use (the OWASP LLM Top 10).

## What it tests

Each probe is one attack class. Detection is signature-based (canary strings,
credential-shaped regexes, marker reflection) so findings are high-confidence,
not "the model said something spooky".

| Probe | OWASP (2025) | What it checks |
| --- | --- | --- |
| `LLM01-PI` | LLM01 Prompt Injection | Direct instruction override — does attacker input hijack the task? |
| `LLM01-JB` | LLM01 Prompt Injection | Jailbreak / guardrail bypass via role-play (DAN) and Base64/ROT13 encoding |
| `LLM07-SPL` | LLM07 System Prompt Leakage | Can the hidden system prompt be extracted verbatim? |
| `LLM02-SID` | LLM02 Sensitive Information Disclosure | Will the app leak secrets/PII (API keys, connection strings, passwords) in its context? |
| `LLM05-IOH` | LLM05 Improper Output Handling | Is active content (XSS/SSTI) returned unescaped to a downstream sink? |

Run `llmsec --list` to see them.

## Targets

The scanner only controls the *user* message — whatever system prompt, tools or
guardrails the app uses are exactly what's under test.

| Backend | Spec | Notes |
| --- | --- | --- |
| Offline mock | `mock` / `mock-secure` | Deliberately vulnerable / hardened chatbot. No network, no key. |
| OpenAI-compatible | `openai:gpt-4o-mini` | OpenAI, Azure, Ollama, vLLM, OpenRouter… (`OPENAI_API_KEY`) |
| Anthropic | `anthropic:claude-sonnet-4-6` | Claude Messages API (`ANTHROPIC_API_KEY`) |
| Generic HTTP | `http` + `--config file.yaml` | Any bespoke endpoint; templated request + JSON response path |

API targets use only the Python standard library — no vendor SDKs to install.

## Install

```bash
git clone https://github.com/usmanzia-ux/llm-security-toolkit
cd llm-security-toolkit
pip install -e .            # installs the `llmsec` command
# or run without installing:
PYTHONPATH=. python3 -m llmsec.cli --target mock
```

Requires Python 3.9+. Runtime deps: `rich`, `pyyaml`.

## Usage

```bash
# Full scan of the offline mock, Markdown report (default)
llmsec --target mock -o report.md

# Scan a real OpenAI-compatible deployment
export OPENAI_API_KEY=sk-...
llmsec --target openai:gpt-4o-mini --system "You are ACME support bot."

# Scan a Claude-backed app
export ANTHROPIC_API_KEY=sk-ant-...
llmsec --target anthropic:claude-sonnet-4-6

# Point at any chatbot endpoint
llmsec --target http --config examples/http_target.yaml

# Run a subset of probes, JSON output
llmsec --target mock --probes LLM01-PI,LLM02-SID -f json -o findings.json

# CI gate: exit non-zero if a High+ finding is confirmed
llmsec --target mock --fail-on high
```

### CI integration

`--fail-on {critical,high,medium,low}` makes the scanner a build gate — it exits
`1` when a confirmed finding meets the threshold, so a regression in your
prompt-hardening fails the pipeline:

```yaml
- run: llmsec --target $STAGING_LLM --fail-on high
```

## Output

- **Markdown** (default) — a clean assessment that renders on GitHub, with a
  summary table and per-finding proof-of-concept (attack prompt + model
  response) and remediation.
- **JSON** — machine-readable, for pipelines, dashboards or diffing two scans.

## Architecture

```
llmsec/
├── targets/      one backend per file (mock, openai, anthropic, http) → Target.ask()
├── probes/       one attack class per file → ProbeResult; registry in __init__
├── detectors.py  pure response classifiers (refusal, secret regex, marker reflection)
├── scanner.py    runs probes against a target → ScanReport
├── reporters/    one output format per file (markdown, json)
├── models.py     Severity / Owasp / Attempt / ProbeResult / ScanReport
└── cli.py        argparse + rich front-end
```

**Extending it is deliberately trivial:**

- *Add an attack* → drop a `Probe` subclass in `probes/`, register it in
  `probes/__init__.py`. It implements `attack_prompts()` and `judge()`.
- *Add a target* → drop a `Target` subclass in `targets/`, wire it into the
  factory.
- *Add an output format* → add a module in `reporters/`.

The `mock` and `mock-secure` targets double as a test oracle: every probe must
fire on the vulnerable mock and pass on the hardened one, which is exactly what
the test suite asserts.

## Testing

```bash
pip install -e ".[dev]"
pytest -q          # 36 tests, fully offline
```

## Ethical use

This is a defensive tool for authorized testing of systems you own or have
written permission to assess. Don't point it at third-party services without
consent.

## License

MIT © Usman Zia
