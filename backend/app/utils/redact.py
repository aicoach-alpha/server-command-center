"""Secret redaction helpers.

Process command lines can contain things like
`--api-key-file /home/user/.config/example/llama-api-key` (path only, fine) but
could equally contain `--api-key sk-...` or `Authorization: Bearer ...`. Every
command line that leaves the backend passes through `redact_text` first.

The rule is deliberately conservative: it only rewrites values, never the whole
string, so the dashboard still shows *which* flag carried a secret.
"""

from __future__ import annotations

import re

REDACTED = "***REDACTED***"

# Credential words recognised inside an identifier.
#
# Names are matched by SPLITTING on `_`/`.`/`-` rather than by one large regex.
# A monolithic `[\w.\-]*SECRET_WORD` regex cannot express the two rules that
# actually matter, and getting them wrong in either direction is a real defect:
#
#   * MUST match namespaced names: TUYA_LOCAL_KEY, GITHUB_TOKEN, DB_PASSWORD.
#     Their credential word starts right after a `_` separator.
#   * MUST NOT match words that merely END in a credential word: `--monkey`,
#     `hockey`, `--turkey`, `keynote`. "key" is a suffix of all of them.
#
# Splitting into tokens makes both rules fall out naturally: the last token must
# BE a credential word (or be "key"), which rejects `monkey` (last token is
# "monkey", not "key") and accepts `TUYA_LOCAL_KEY` (last token is "key").
_CREDENTIAL_WORDS = frozenset(
    {
        "key",
        "keys",
        "secret",
        "secrets",
        "token",
        "tokens",
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "credential",
        "credentials",
        "authorization",
    }
)

# `TOKEN`, `TOKEN_FILE`, `KEYSTORE` -> secret-bearing by suffix.
_SECRET_NAME_SUFFIXES = ("_key", "_token", "_secret", "_password", "_passwd", "_pwd")

_NAME_SEPARATORS = re.compile(r"[_\-.]+")


def is_secret_name(name: str) -> bool:
    """True when `name` looks like a credential variable/flag name.

    `name` may include leading dashes (`--api-key`). An identifier containing
    `.` is skipped entirely: it is a file path or hostname, and redacting
    `--api-key-file /path/to/key` would hide which key file is in use.
    """
    if not name:
        return False

    cleaned = name.lstrip("-")
    if not cleaned:
        return False

    # Paths/filenames: `--keyfile=/x`, `secret.json`, `app.key`. Never a value.
    if "/" in cleaned:
        return False

    parts = [p for p in _NAME_SEPARATORS.split(cleaned) if p]
    if not parts:
        return False

    lowered = [p.lower() for p in parts]
    if lowered[-1] in _CREDENTIAL_WORDS:
        return True

    # Suffix forms: OPENAI_API_KEY, EXAMPLE_BETA_SECRET (case-insensitive).
    joined = "_".join(lowered)
    return any(joined.endswith(sfx) for sfx in _SECRET_NAME_SUFFIXES)


# `NAME = VALUE`, `NAME: VALUE`, `--flag VALUE`
_ASSIGN_RE = re.compile(
    r"(?P<name>--?[\w.\-]*[\w]|-?[\w][\w.\-]*)(?P<sep>\s*[=:]\s*|\s+)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s\"',;]+)"
)

# `Authorization: Bearer xyz`
_BEARER = re.compile(r"(?i)\b(authorization\s*[:=]\s*)(bearer\s+)?([^\s\"',;]+)")

# `Bearer xyz` standalone
_BEARER_BARE = re.compile(r"(?i)\b(bearer)\s+([A-Za-z0-9._\-+/=]{8,})")

# Free-standing high-entropy tokens that are obviously credentials.
_TOKEN_SHAPED = re.compile(
    r"\b("
    r"sk-[A-Za-z0-9]{16,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|gho_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"
    r")\b"
)

# Values that must never be redacted because they are paths/config files we
# deliberately want visible (they carry no secret material themselves).
_PATH_LIKE = re.compile(r"^[\w./~-]*$")


def _assignment_repl(m: re.Match[str]) -> str:
    name = m.group("name")
    if not is_secret_name(name):
        return m.group(0)
    sep, value = m.group("sep"), m.group("value")
    # A bare path is not a secret. `--api-key-file /home/.../llama-api-key`
    # must keep its path so operators can see WHICH key file is in use.
    if "/" in value:
        return m.group(0)
    return f"{name}{sep}{REDACTED}"


def redact_text(value: str | None) -> str:
    """Redact credential-looking material from a free-form string."""
    if not value:
        return ""
    # Bearer headers MUST be handled first. `Authorization: Bearer <token>`
    # matches `_ASSIGN_RE` as name=`Authorization` value=`Bearer`, which would
    # redact only the literal word "Bearer" and leave the actual token exposed
    # in the remainder of the string.
    out = _BEARER.sub(
        lambda m: f"{m.group(1)}{REDACTED}", value
    )
    out = _BEARER_BARE.sub(lambda m: f"{m.group(1)} {REDACTED}", out)
    out = _ASSIGN_RE.sub(_assignment_repl, out)
    out = _TOKEN_SHAPED.sub(REDACTED, out)
    return out


def _is_path_like(value: str) -> bool:
    """A bare filesystem path is not itself a secret.

    `--api-key-file /home/user/.config/example/llama-api-key` must keep its
    path so operators can tell *which* key file is in use.
    """
    return bool(value) and "/" in value and not value.startswith("-")


def redact_cmdline(argv: list[str] | None) -> list[str]:
    """Redact credential-looking material from an argv, preserving boundaries.

    Handles three shapes, using the same `is_secret_name` rule as free text:
      1. `--api-key=SECRET`     -> `--api-key=***REDACTED***`
      2. `--api-key SECRET`     -> `--api-key`, `***REDACTED***`
      3. `PASSWORD=SECRET`      -> `PASSWORD=***REDACTED***`

    Path-like values are preserved (case 2 above), because a key *file path* is
    useful to see and carries no secret itself.
    """
    if not argv:
        return []

    out: list[str] = []
    redact_next = False

    for i, raw in enumerate(argv):
        if redact_next:
            out.append(raw if _is_path_like(raw) else REDACTED)
            redact_next = False
            continue

        # Inline `--flag=VALUE` / `NAME=VALUE`.
        if "=" in raw:
            name, _, value = raw.partition("=")
            if is_secret_name(name):
                out.append(raw if "/" in value else f"{name}={REDACTED}")
                continue

        if raw.startswith("-") and is_secret_name(raw):
            out.append(raw)
            nxt = argv[i + 1] if i + 1 < len(argv) else None
            # Only consume the next element if it is a value, not another flag.
            if nxt is not None and not nxt.startswith("-"):
                redact_next = True
            continue

        out.append(redact_text(raw))

    return out


def redact_env_keys(names: list[str]) -> list[str]:
    """Only ever surface variable *names*, never values."""
    return sorted({n for n in names if n})


def redact_mapping(data: dict[str, str]) -> dict[str, str]:
    return {k: REDACTED for k in data}