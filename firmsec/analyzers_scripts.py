"""Script-focused analyzers: CGI/shell script risk flagging and init/rc auditing."""

import re
from pathlib import Path

from constants import CRITICAL, HIGH, MEDIUM, LOW
from console import _info, _ok
from finding import Finding
from utils import run_cmd


def find_scripts(root: Path):
    _info("Finding CGI and shell scripts...")
    findings = []

    stdout, _, _ = run_cmd(
        f'find "{root}" \\( -name "*.cgi" -o -name "*.sh" -o -name "*.bash" -o -name "*.pl" \\) 2>/dev/null'
    )
    scripts = [Path(l.strip()) for l in stdout.splitlines() if l.strip()]

    for script in scripts:
        if script.suffix == ".cgi":
            cat, severity = "CGI Script", MEDIUM
        elif script.suffix in (".sh", ".bash"):
            cat, severity = "Shell Script", LOW
        else:
            cat, severity = "Script", LOW

        risk_flags = []
        try:
            content = script.read_text(errors="replace")
            if re.search(r'\$_(GET|POST|REQUEST|QUERY_STRING)', content):
                severity = HIGH
                risk_flags.append("user-input→shell")
            if re.search(r'\bsystem\s*\(|\bpopen\s*\(|\bexec\s*\(', content):
                severity = HIGH
                risk_flags.append("shell-exec")
            if re.search(r'QUERY_STRING|HTTP_POST', content) and re.search(r'`|\$\(', content):
                severity = CRITICAL
                risk_flags.append("backtick+CGI=RCE-risk")
            if re.search(r'password\s*=|passwd\s*=|secret\s*=', content, re.IGNORECASE):
                risk_flags.append("hardcoded-cred")
        except (IOError, OSError):
            pass

        detail = cat + (f" [{', '.join(risk_flags)}]" if risk_flags else "")
        findings.append(Finding(cat, severity, script, detail))

    _ok(f"Scripts found: {len(scripts)}")
    return findings


def find_init_scripts(root: Path):
    _info("Scanning init/rc scripts for embedded credentials and unsafe permissions...")
    findings = []

    init_dirs = ["etc/init.d", "etc/rc.d", "etc/rc.local", "etc/inittab"]
    candidates = []
    for d in init_dirs:
        p = root / d
        if p.is_dir():
            candidates += list(p.rglob("*"))
        elif p.is_file():
            candidates.append(p)

    for script in candidates:
        if not script.is_file():
            continue
        try:
            content = script.read_text(errors="replace")
        except (IOError, OSError):
            continue

        if re.search(r'password\s*=|passwd\s*=|--password\s+\S', content, re.IGNORECASE):
            findings.append(Finding(
                "Init Script", HIGH, script,
                "Hardcoded credential in init/rc script — rotates into every boot"
            ))
        if re.search(r'chmod\s+777|chmod\s+a\+w', content):
            findings.append(Finding(
                "Init Script", MEDIUM, script,
                "World-writable permission (chmod 777/a+w) set at boot"
            ))
        if re.search(r'telnetd|ftpd\b', content):
            findings.append(Finding(
                "Init Script", HIGH, script,
                "Plaintext network service (telnetd/ftpd) started at boot"
            ))
        if re.search(r'dropbear|sshd', content):
            findings.append(Finding(
                "Init Script", LOW, script,
                "SSH daemon started at boot — verify key-only auth is enforced"
            ))

    _ok(f"Init script scan: {len(findings)} findings")
    return findings
