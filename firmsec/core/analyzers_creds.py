"""Credential-focused analyzers: hardcoded credentials, passwd/shadow audit,
and private-key / certificate discovery."""

import re
from datetime import datetime
from pathlib import Path

from .constants import (
    CRITICAL, HIGH, MEDIUM,
    CRED_PATTERNS, CRED_FILE_EXTS, AXIS_DEFAULT_CREDS,
)
from .console import _info, _ok
from .finding import Finding
from .filters import credential_severity, is_false_positive, _is_credlike
from .utils import run_cmd


def find_credentials(root: Path):
    _info("Searching for hardcoded credentials in config/script/web files...")
    findings = []

    ext_glob = " ".join(f'--include="{e}"' for e in CRED_FILE_EXTS)
    false_positive_filter = r'example|sample|template|placeholder|YOUR_|<FILL|TODO|FIXME|dummy|test123'

    for pattern, base_severity, label in CRED_PATTERNS:
        stdout, _, _ = run_cmd(
            f'grep -rni {ext_glob} -E "{pattern}" "{root}" 2>/dev/null | '
            f'grep -viE "{false_positive_filter}" | head -60'
        )
        if stdout.strip():
            for line in stdout.strip().splitlines()[:15]:
                parts = line.split(":", 2)
                fpath_str = parts[0] if len(parts) >= 1 else "?"
                matched   = parts[2].strip() if len(parts) >= 3 else line

                if not Path(fpath_str).is_file():
                    continue  # grep parsing artifact — path does not exist

                if is_false_positive(fpath_str, matched):
                    continue

                if not _is_credlike(matched):
                    continue

                # Redact everything after the first separator so multi-token
                # values (e.g. "password = my secret") don't leak their tail.
                redacted  = re.sub(r'([=:]\s*).*$', r'\1[REDACTED]', matched, count=1)

                sev, note = credential_severity(base_severity, label, Path(fpath_str))
                findings.append(Finding(
                    "Hardcoded Credential", sev, fpath_str,
                    f"{label}{note}: {redacted}"
                ))

    count = len([f for f in findings if f.category == "Hardcoded Credential"])
    _ok(f"Credential scan: {count} potential matches")
    return findings


def find_passwd_shadow(root: Path):
    _info("Auditing passwd and shadow files for weak/default accounts...")
    findings = []

    WEAK_HASHES = {
        "$1$": "MD5crypt (weak)",
        "$2$": "Blowfish/bcrypt (verify cost factor)",
        "$apr1$": "Apache MD5 (weak)",
    }

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.name not in ("passwd", "shadow"):
            continue
        try:
            content = p.read_text(errors="replace")
        except (IOError, OSError):
            continue

        if p.name == "passwd":
            for lineno, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                user, pw_field, uid, gid = parts[0], parts[1], parts[2], parts[3]
                # Password hash in passwd (not shadow)
                if pw_field not in ("x", "*", "!") and pw_field != "":
                    findings.append(Finding(
                        "System Account", CRITICAL, p,
                        f"User '{user}' has password hash directly in /etc/passwd — shadow not used",
                        line=str(lineno)
                    ))
                # Empty password field
                if pw_field == "":
                    findings.append(Finding(
                        "System Account", CRITICAL, p,
                        f"User '{user}' has EMPTY password in /etc/passwd",
                        line=str(lineno)
                    ))
                # Root UID=0 account enabled
                if uid == "0" and user != "root":
                    findings.append(Finding(
                        "System Account", HIGH, p,
                        f"Non-root user '{user}' has UID=0 (root privileges)",
                        line=str(lineno)
                    ))
                # Check for default Axis credentials
                for default_user, _ in AXIS_DEFAULT_CREDS:
                    if user == default_user and pw_field not in ("x", "*", "!"):
                        findings.append(Finding(
                            "System Account", CRITICAL, p,
                            f"Default Axis credential username '{user}' with non-shadowed password",
                            line=str(lineno)
                        ))

        elif p.name == "shadow":
            for lineno, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                user, hash_field = parts[0], parts[1]
                if hash_field in ("", "0"):
                    findings.append(Finding(
                        "System Account", CRITICAL, p,
                        f"User '{user}' has empty/no password in /etc/shadow",
                        line=str(lineno)
                    ))
                elif hash_field in ("*", "!"):
                    pass  # disabled/locked — OK
                else:
                    for prefix, desc in WEAK_HASHES.items():
                        if hash_field.startswith(prefix):
                            sev = CRITICAL if "MD5" in desc else MEDIUM
                            findings.append(Finding(
                                "System Account", sev, p,
                                f"User '{user}' uses {desc} password hash",
                                line=str(lineno)
                            ))

    _ok(f"passwd/shadow audit: {len(findings)} findings")
    return findings


def find_keys_and_certs(root: Path):
    _info("Looking for private keys, certificates, and SSH host keys...")
    findings = []

    # File-extension-based scan
    ext_patterns = [
        ("*.pem",  "PEM bundle"),
        ("*.key",  "Key file"),
        ("*.crt",  "Certificate"),
        ("*.cer",  "Certificate"),
        ("*.p12",  "PKCS#12 bundle"),
        ("*.pfx",  "PFX bundle"),
        ("*.der",  "DER certificate"),
        ("*.pub",  "Public key"),
    ]
    for glob_pat, label in ext_patterns:
        for p in root.rglob(glob_pat):
            _classify_key_or_cert(p, label, findings)

    # SSH host and user key names (often no extension)
    ssh_key_names = [
        "ssh_host_rsa_key",      "ssh_host_ecdsa_key",
        "ssh_host_ed25519_key",  "ssh_host_dsa_key",
        "id_rsa",  "id_ecdsa",  "id_ed25519", "id_dsa",
        "authorized_keys",
    ]
    for p in root.rglob("*"):
        if p.is_file() and p.name in ssh_key_names:
            label = f"SSH key — {p.name}"
            _classify_key_or_cert(p, label, findings)

    # Content-based scan: search for PEM headers in any file
    stdout, _, _ = run_cmd(
        f'grep -rln "BEGIN.*PRIVATE KEY\\|BEGIN.*CERTIFICATE\\|BEGIN.*PUBLIC KEY" '
        f'"{root}" 2>/dev/null | head -50'
    )
    for path_str in stdout.strip().splitlines():
        p = Path(path_str.strip())
        if not any(f.path == str(p) for f in findings):
            _classify_key_or_cert(p, "PEM content detected in file", findings)

    _ok(f"Keys/certs found: {len(findings)}")
    return findings


def _classify_key_or_cert(p: Path, label: str, findings: list):
    severity = HIGH
    detail = label
    try:
        content = p.read_text(errors="replace")
        if re.search(r'PRIVATE KEY', content):
            severity = CRITICAL
            detail = f"Private key — {label}"
        elif "authorized_keys" in p.name:
            severity = MEDIUM
            detail = f"SSH authorized_keys — review for unexpected entries"
    except (IOError, OSError):
        pass

    # Try openssl for cert expiry
    if p.suffix in (".pem", ".crt", ".cer") or "crt" in p.name:
        out, _, rc = run_cmd(f'openssl x509 -in "{p}" -noout -enddate 2>/dev/null')
        if rc == 0 and "notAfter" in out:
            expiry = out.strip().replace("notAfter=", "")
            detail += f" | Expires: {expiry}"
            # Flag certs whose notAfter is in the past. openssl prints dates like
            # "Jun  9 12:00:00 2025 GMT"; parse the full timestamp rather than the
            # year alone so a cert expiring earlier this year is still caught.
            try:
                exp_dt = datetime.strptime(
                    expiry.replace("GMT", "").strip(), "%b %d %H:%M:%S %Y"
                )
                if exp_dt < datetime.now():
                    severity = CRITICAL
                    detail += " ⚠️ EXPIRED"
            except (AttributeError, ValueError):
                pass

    findings.append(Finding("Certificate/Key", severity, p, detail))
