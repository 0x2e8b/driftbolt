# Documentation & Comment Style Guide

How to write docstrings and comments in this codebase. This governs
in-code documentation only — `src/`, `tests/`, and infra-as-code/shell
files. It does not cover standalone docs (`README.md`, `SPEC.md`, design
docs under `docs/superpowers/`), and it does not apply to `old/` (legacy
code being replaced, already exhaustively described by `SPEC.md`).

There is no linter enforcing this — it's a convention for whoever writes
or reviews code, human or LLM.

## Core philosophy

Comments and docstrings explain **why**, not **what**. The code already
says what it does — a docstring or comment that just restates the
function name, parameter types, or an obvious line of code adds nothing
and rots the moment the code changes. Write one when there's a hidden
constraint, a non-obvious invariant, a deviation from what a reader would
reasonably expect, or the reasoning behind a design choice that isn't
visible from the code itself. If you can't say something the code
doesn't already say, don't write it.

## Python — module docstrings

Every `.py` module in `src/` gets a docstring stating its role in the
system, in its own words — self-contained, so a reader (or an LLM
reading one file in isolation) understands the module's purpose without
opening another file.

Add a one-line pointer to the relevant `SPEC.md` section only where deep
legacy-compatibility rationale actually lives there — most modules won't
need this.

```python
"""Parses loosely-shaped Sycope alert JSON into a ParsedAlert.

Field aliases and fallback order replicate the legacy contract exactly
(see SPEC.md §5.3) — Sycope payload shape varies by alert type/version
and this is the main compatibility surface with it.
"""
```

## Python — function and class docstrings

Every `def` and `class` in `src/` gets a docstring. No exceptions for
being "obvious" — trivial functions just get a correspondingly short
docstring, so coverage never becomes a judgment call.

- **Format**: plain freeform prose. One sentence for trivial functions;
  a short paragraph when there's a real *why* to state (an edge case, a
  contract the caller must honor, a deviation from the obvious approach).
- **No mechanical Args/Returns/Raises sections.** Mention a specific
  parameter or return value only when its meaning isn't already obvious
  from its name and type hint.
- **Dataclasses** get a class-level docstring. Individual fields get a
  trailing `#` comment only when a field's meaning isn't obvious from its
  name/type (e.g. an `Any`-typed field, or a field whose valid values
  aren't the full range its type would suggest).

Examples, calibrated to actual functions in this codebase:

```python
def sanitize_id(raw: object) -> str:
    """Strip to [A-Za-z0-9_-], cap at 64 chars; "alert" if that leaves nothing."""
    ...

def build_bpf_filter(parsed: ParsedAlert, mode: str) -> str | None:
    """Build a BPF filter string for npcapextract from a parsed alert.

    Returns None (never an empty string) if no filter can be built — e.g.
    mode selects only fields the alert doesn't have, or the only term
    would be a bare protocol name with no host/port (too broad to be a
    useful filter). Callers must treat None as "skip extraction".
    """
    ...

@dataclass
class ParsedAlert:
    """Alert fields normalized from Sycope's loosely-shaped JSON payload."""

    client_ip: str | None
    server_ip: str | None
    server_port: int | None
    protocol: str | None
    timestamp: float
    alert_id: Any  # str, int, or None depending on the source payload's "id"/"alertId" field
    alert_name: str
```

## Python — tests

Test functions are **exempt** from the "every function" rule. A
descriptive test name (`test_bpf_rejects_bare_protocol_only`) already
states the intent — a docstring restating it adds nothing.

Add a docstring only when the test encodes a non-obvious edge case or
regression that the name alone can't fully convey:

```python
def test_alert_id_null_uses_string_none_not_synthesized_fallback():
    """Presence-vs-truthiness asymmetry: id=None is used as-is (str "None"),
    NOT replaced by the alert_<ts> fallback — see alert.py module note."""
    ...
```

## Python — inline comments

Add an inline comment wherever behavior would surprise a reader coming
in cold:

- An intentional deviation from the "obvious" approach (why ASCII-only
  instead of Unicode-aware in `extraction.py`'s `_ID_ALLOWED`).
- A non-obvious business rule inherited from the legacy contract (the
  ICMP+port suppression rule in `bpf.py`).
- A workaround for an external constraint (a subprocess quirk, a
  third-party tool's behavior).

Don't add a comment for anything a competent reader already gets from
the code. Prefer a comment placed above the line/block it explains over
a trailing comment, except for very short one-word-of-context notes.

## Infra-as-code (Caddyfile, compose.yaml, Dockerfile, gunicorn.conf.py)

Every file gets a short header comment stating its role in the system.
Every non-obvious directive or value gets a comment explaining *why that
value*, not what the directive does. Self-evident directives (`admin
off`) don't need a comment.

The existing Caddyfile comment is the model to match elsewhere:

```
# Authoritative body size cap: enforced regardless of a lying/absent
# Content-Length header. Must match the app's MAX_BODY_BYTES (2 MiB
# exactly = 2*1024*1024 bytes); use MiB not MB (MB = 2,000,000 bytes).
request_body {
	max_size 2MiB
}
```

## Shell scripts

Header comment stating purpose and usage — `zip_project.sh`'s existing
header is the template to match:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Zips the current git repository, respecting .gitignore.
# Usage: ./zip_project.sh [output.zip]
```

Any function defined in a script gets a one-line comment above it
describing its purpose. Non-obvious flags (e.g. `set -euo pipefail`, an
unusual `xargs`/`zip` flag combination) get an inline comment explaining
why that flag is needed, if it isn't already covered by the header.
