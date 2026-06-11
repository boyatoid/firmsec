"""Credential-finding heuristics: location-aware severity, false-positive
suppression, and value-quality filtering.

These keep the credential scanner's output meaningful by dropping the many
incidental grep matches that are not real secrets.
"""

import re
from pathlib import Path

from constants import (
    CRITICAL, HIGH,
    WEB_ACCESSIBLE_DIRS, ALWAYS_CRITICAL_LABELS, FALSE_POSITIVE_RULES,
)


def is_web_accessible(path: Path) -> bool:
    """True if any component of the path is a known web-served directory."""
    return bool({p.lower() for p in path.parts} & WEB_ACCESSIBLE_DIRS)


def credential_severity(base_severity: str, label: str, fpath: Path) -> tuple:
    """Return (effective_severity, context_note) using location-aware rules."""
    if label in ALWAYS_CRITICAL_LABELS:
        return CRITICAL, ""
    if is_web_accessible(fpath):
        return CRITICAL, " [web-exposed — retrievable without authentication]"
    if base_severity == CRITICAL:
        return HIGH, " [requires firmware image or local filesystem access]"
    return base_severity, " [requires firmware image or local filesystem access]"


def is_false_positive(fpath: str, matched_content: str) -> bool:
    """Return True when the finding matches a known false positive rule."""
    fname = Path(fpath).name
    for fname_pat, content_pat in FALSE_POSITIVE_RULES:
        if re.search(fname_pat, fname, re.IGNORECASE):
            if content_pat == r'.*' or re.search(content_pat, matched_content, re.IGNORECASE):
                return True
    return False


# ── Credential value quality filter ──────────────────────────────────────────
#
# The grep patterns match any non-whitespace value after "password =", "token =",
# etc. — which includes sed patterns, shell variable references, chown args, type
# annotations, and other incidental matches that are clearly not real secrets.
#
# _is_credlike() extracts the value portion and returns False if it is obviously
# not a real credential, so those findings are silently dropped.

# Line-level check: if the whole line is a command invocation, the "=" match is
# incidental (e.g. sed / chown / awk argument that happens to contain the keyword).
_COMMAND_LINE_RE = re.compile(
    r'^\s*(?:sed|awk|grep|find|chown|chmod|chgrp|xargs|echo|printf|export|'
    r'logger|install|cp|mv|ln)\s',
    re.IGNORECASE,
)

# Value-level check: patterns that are definitely not real credential values.
_NON_CRED_VALUE_RE = re.compile(
    r'^(?:'
    r'""|\'\''                                          # empty string literals
    r'|false|true|yes|no|on|off|enabled|disabled'       # booleans
    r'|null|none|nil|n/?a|undefined|unset|empty'        # null-like
    r'|0+(?:\.0+)?'                                     # zero / 0.0
    r'|\$[\({]\S*|\$[A-Za-z_]\w*'                      # $VAR  ${VAR}  $(cmd)
    r'|`[^`]*`'                                         # `backtick substitution`
    r'|%[sdifgqr]|%\{\w+\}|\{[\w._:-]+\}'              # printf / Jinja / Python fmt
    r'|<[\w/_ -]+>'                                     # <placeholder>
    r'|\*{2,}|x{4,}|-{4,}|\.{3,}'                     # masking: **** xxxx ----
    r'|changeme|change[-_]?me|tbd|todo|fixme|set[-_]?this'
    r'|writeonly|readonly|maxlen|minlen|type'            # type-annotation keywords
    r'|basic|digest|bearer|ntlm|negotiate|kerberos|oauth\d?'  # auth method names
    r'|/[\w/.-]{3,}'                                   # file paths
    r'|\w+:\w+'                                        # user:group pairs (chown)
    r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'           # IP addresses
    r').*$',
    re.IGNORECASE,
)

# Case-sensitive: purely uppercase-plus-underscores identifiers like
# PTZ_AUTO_PT_CALIBRATION are system constants, not credential values.
_ALL_CAPS_IDENTIFIER_RE = re.compile(r'^[A-Z][A-Z0-9]{1,}_[A-Z0-9_]+$')


def _is_credlike(matched_line: str) -> bool:
    """
    Return True only when matched_line plausibly contains a real credential value.

    Rejects:
      - Command invocations (sed / chown / awk / …) where the keyword match is
        incidental to the command syntax.
      - Values that are shell substitutions, variable references, regex metachar
        sequences, type annotations, boolean/null keywords, masking placeholders,
        auth method names, file paths, or user:group pairs.
      - Purely ALL_CAPS_WITH_UNDERSCORES system constant identifiers.
      - Values shorter than 4 characters (too short to be meaningful).
    """
    if _COMMAND_LINE_RE.search(matched_line):
        return False

    # Extract the value portion after the first = or :
    m = re.search(r'[=:]\s*["\']?(.*?)["\']?\s*(?:#.*)?$', matched_line.strip())
    if not m:
        return False
    value = m.group(1).strip().strip('"\'').strip()

    if len(value) < 4:
        return False
    # Regex metacharacters → sed/grep pattern context, not a credential
    if re.search(r'\.\*|\\\d|\\\w|\(\?', value):
        return False
    # Case-insensitive keyword / structural checks
    if _NON_CRED_VALUE_RE.match(value):
        return False
    # Case-sensitive: purely uppercase identifier with underscore separator
    if _ALL_CAPS_IDENTIFIER_RE.match(value):
        return False
    return True
