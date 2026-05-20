#!/usr/bin/env python3
"""
FirmSec - Firmware Security Analysis Tool for Axis OS Devices
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.tree import Tree
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

# ── Severity constants ────────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

# ── Dangerous function definitions ────────────────────────────────────────────

DANGEROUS_FUNCTIONS = {
    "system":   (HIGH,   "Shell command execution; user input may reach shell"),
    "popen":    (HIGH,   "Pipe to shell; command injection risk"),
    "strcpy":   (HIGH,   "Unbounded copy; classic stack overflow vector"),
    "sprintf":  (MEDIUM, "Unbounded format write; potential buffer overflow"),
    "gets":     (CRITICAL,"Always unsafe; removed from C11"),
    "memcpy":   (LOW,    "Length must be validated by caller"),
    "strcat":   (HIGH,   "Unbounded concatenation; buffer overflow risk"),
    "scanf":    (MEDIUM, "Unbounded input; format string risk"),
    "vsprintf": (MEDIUM, "Unbounded variadic format write"),
    "bcopy":    (LOW,    "Deprecated; prefer memmove"),
}

# ── Credential patterns ───────────────────────────────────────────────────────

CRED_PATTERNS = [
    (r'password\s*=\s*\S+',  CRITICAL, "Hardcoded password"),
    (r'passwd\s*=\s*\S+',    CRITICAL, "Hardcoded passwd field"),
    (r'secret\s*=\s*\S+',    CRITICAL, "Hardcoded secret"),
    (r'admin\s*=\s*\S+',     HIGH,     "Hardcoded admin value"),
    (r'root\s*=\s*\S+',      HIGH,     "Hardcoded root value"),
    (r'api_key\s*=\s*\S+',   CRITICAL, "Hardcoded API key"),
    (r'token\s*=\s*\S+',     HIGH,     "Hardcoded token"),
    (r'private_key\s*=\s*\S+', CRITICAL, "Hardcoded private key reference"),
]

# ── Vulnerable library signatures ─────────────────────────────────────────────

VULNERABLE_LIBS = {
    "openssl":  {
        "pattern": r'openssl[\s/\-_]*([\d]+\.[\d]+\.[\d]+[a-z]?)',
        "cves": ["CVE-2014-0160 (Heartbleed, <1.0.1g)", "CVE-2022-0778 (<1.0.2zd,<1.1.1n,<3.0.2)"],
    },
    "libupnp":  {
        "pattern": r'libupnp[\s/\-_]*([\d]+\.[\d]+\.[\d]+)',
        "cves": ["CVE-2012-5958 (≤1.6.17 stack overflow)", "CVE-2016-8863 (≤1.6.20 heap overflow)"],
    },
    "boa":      {
        "pattern": r'boa[\s/\-_]*([\d]+\.[\d]+\.[\d]+)',
        "cves": ["CVE-2017-9833 (dir traversal)", "CVE-2021-33558 (info disclosure)"],
    },
    "thttpd":   {
        "pattern": r'thttpd[\s/\-_]*([\d]+\.[\d]+\.[\d]+)',
        "cves": ["CVE-2017-11549 (null ptr deref)", "CVE-2022-38723 (buffer overflow)"],
    },
    "busybox":  {
        "pattern": r'busybox[\s/\-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": ["CVE-2022-28391 (shell cmd injection in hush)", "CVE-2021-42374 (lzma OOB read)"],
    },
    "curl":     {
        "pattern": r'curl[\s/\-_]*([\d]+\.[\d]+\.[\d]+)',
        "cves": ["CVE-2023-38545 (SOCKS5 heap overflow, <8.4.0)"],
    },
}

# ── VAPIX unauthenticated endpoint patterns ───────────────────────────────────

VAPIX_UNAUTH_PATTERNS = [
    r'/axis-cgi/jpg/image\.cgi',
    r'/axis-cgi/mjpg/video\.cgi',
    r'/axis-cgi/operator/param\.cgi',
    r'/axis-cgi/admin/param\.cgi',
    r'/axis-cgi/io/port\.cgi',
    r'/axis-cgi/com/ptz\.cgi',
    r'/axis-cgi/record/.*\.cgi',
    r'/axis-cgi/usergroup\.cgi',
    r'/axis-cgi/pwdgrp\.cgi',
    r'/axis-cgi/firmwareupgrade\.cgi',
    r'/axis-cgi/restart\.cgi',
    r'/axis-cgi/factorydefault\.cgi',
]

VAPIX_SHELL_RISK_PATTERNS = [
    r'system\s*\([^)]*param',
    r'popen\s*\([^)]*param',
    r'exec\s*\([^)]*param',
    r'shell_exec.*param',
]

# ── Helper utilities ──────────────────────────────────────────────────────────

def _c(text, color):
    if HAS_COLORAMA:
        return f"{color}{text}{Style.RESET_ALL}"
    return text

def _ok(msg):    print(_c(f"[+] {msg}", Fore.GREEN if HAS_COLORAMA else ""))
def _info(msg):  print(_c(f"[*] {msg}", Fore.CYAN if HAS_COLORAMA else ""))
def _warn(msg):  print(_c(f"[!] {msg}", Fore.YELLOW if HAS_COLORAMA else ""))
def _err(msg):   print(_c(f"[-] {msg}", Fore.RED if HAS_COLORAMA else ""), file=sys.stderr)
def _sep():      print(_c("─" * 60, Fore.BLUE if HAS_COLORAMA else ""))

def severity_color(sev):
    if not HAS_COLORAMA:
        return sev
    colors = {CRITICAL: Fore.RED, HIGH: Fore.MAGENTA, MEDIUM: Fore.YELLOW, LOW: Fore.CYAN}
    return _c(sev, colors.get(sev, ""))

def check_tool(name, kali=False):
    """Return tool path or None; print install hint on miss."""
    result = subprocess.run(["which", name], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    _warn(f"Tool not found: {name}")
    if name == "binwalk":
        if kali:
            _warn("  Install: sudo apt install binwalk")
        else:
            _warn("  Install: brew install binwalk  OR  pip install binwalk")
    elif name == "file":
        _warn("  Install: built-in on most Unix systems")
    elif name == "strings":
        _warn("  Install: part of binutils (brew install binutils or apt install binutils)")
    elif name == "readelf":
        if kali:
            _warn("  Install: sudo apt install binutils")
        else:
            _warn("  Install: brew install binutils  (provides greadelf)")
    return None

def run_cmd(cmd, timeout=300):
    """Run a shell command, return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        _warn(f"Command timed out: {cmd[:80]}")
        return "", "timeout", 1
    except Exception as e:
        return "", str(e), 1

# ── Step 1: Extraction ────────────────────────────────────────────────────────

def step_extract(target: Path, kali: bool):
    _sep()
    _info("STEP 1 — EXTRACTION")
    _sep()

    binwalk = check_tool("binwalk", kali)
    if not binwalk:
        _err("binwalk is required for extraction. Aborting.")
        sys.exit(1)

    _info(f"Running binwalk -Me on: {target}")
    stdout, stderr, rc = run_cmd(f'binwalk -Me "{target}"', timeout=600)
    print(stdout[:4000] if stdout else "")

    # Locate extracted directory (binwalk naming convention)
    parent = target.parent
    candidates = sorted(parent.glob(f"_{target.name}.extracted"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        # also check current dir
        candidates = sorted(Path(".").glob(f"_{target.name}.extracted"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not candidates:
        _warn("Could not find binwalk extraction directory automatically.")
        _warn("Looking for any .extracted directory near the target...")
        candidates = sorted(parent.glob("*.extracted"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not candidates:
        _err("Extraction directory not found. Check binwalk output above.")
        sys.exit(1)

    extract_dir = candidates[0]
    _ok(f"Extracted to: {extract_dir}")

    # Detect filesystem type
    fs_type = detect_filesystem(extract_dir)
    _info(f"Detected filesystem type: {fs_type}")

    # Print directory tree summary (top 2 levels, max 40 entries)
    print_tree_summary(extract_dir)

    return extract_dir, fs_type

def detect_filesystem(extract_dir: Path):
    for marker in [
        ("squashfs-root", "SquashFS"),
        ("cramfs", "CramFS"),
        ("jffs2", "JFFS2"),
    ]:
        if any(extract_dir.rglob(f"*{marker[0]}*")):
            return marker[1]
    # check file sizes / structure heuristics
    subdirs = [d.name.lower() for d in extract_dir.iterdir() if d.is_dir()]
    if any("squash" in d for d in subdirs):
        return "SquashFS"
    return "Unknown"

def print_tree_summary(root: Path):
    _info("Extracted directory tree (top 3 levels):")
    if HAS_RICH:
        tree = Tree(f"[bold]{root.name}[/bold]")
        _build_rich_tree(tree, root, depth=0, max_depth=3, max_entries=50)
        console.print(tree)
    else:
        count = 0
        for item in sorted(root.rglob("*")):
            if count > 50:
                print("  ... (truncated)")
                break
            depth = len(item.relative_to(root).parts) - 1
            if depth > 2:
                continue
            prefix = "  " * depth + ("📁 " if item.is_dir() else "📄 ")
            print(f"  {prefix}{item.name}")
            count += 1

def _build_rich_tree(tree_node, path: Path, depth, max_depth, max_entries, _counter=None):
    if _counter is None:
        _counter = [0]
    if depth >= max_depth or _counter[0] > max_entries:
        return
    try:
        children = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name))
    except PermissionError:
        return
    for child in children:
        if _counter[0] > max_entries:
            tree_node.add("[dim]...[/dim]")
            break
        _counter[0] += 1
        label = f"[bold blue]{child.name}[/bold blue]" if child.is_dir() else child.name
        branch = tree_node.add(label)
        if child.is_dir():
            _build_rich_tree(branch, child, depth + 1, max_depth, max_entries, _counter)

# ── Step 2: Static Analysis ───────────────────────────────────────────────────

class Finding:
    def __init__(self, category, severity, path, detail, line=None):
        self.category = category
        self.severity = severity
        self.path = str(path)
        self.detail = detail
        self.line = line
        self.ts = datetime.now().isoformat(timespec="seconds")

    def sort_key(self):
        return SEVERITY_ORDER.get(self.severity, 99)


def step_analyze(extract_dir: Path, kali: bool):
    _sep()
    _info("STEP 2 — STATIC ANALYSIS")
    _sep()

    findings = []

    # 2a. ELF binaries + architecture
    findings += find_elf_binaries(extract_dir, kali)

    # 2b. Dangerous C functions
    findings += grep_dangerous_functions(extract_dir)

    # 2c. Hardcoded credentials
    findings += find_credentials(extract_dir)

    # 2d. CGI + shell scripts
    findings += find_scripts(extract_dir)

    # 2e. VAPIX endpoints
    findings += find_vapix_endpoints(extract_dir)

    # 2f. Private keys / certs
    findings += find_keys_and_certs(extract_dir)

    # 2g. Vulnerable library versions
    findings += detect_vulnerable_libraries(extract_dir)

    # 2h. Axis-specific surface
    findings += axis_specific_checks(extract_dir)

    _ok(f"Analysis complete. {len(findings)} findings.")
    return findings


def find_elf_binaries(root: Path, kali: bool):
    _info("Scanning for ELF binaries...")
    findings = []
    file_tool = check_tool("file", kali)
    readelf = check_tool("readelf", kali) or check_tool("greadelf", kali)

    elf_files = []
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            try:
                with open(p, "rb") as f:
                    magic = f.read(4)
                if magic == b'\x7fELF':
                    elf_files.append(p)
            except (IOError, OSError):
                continue

    archs = set()
    for p in elf_files:
        if file_tool:
            out, _, _ = run_cmd(f'file "{p}"')
            arch = "unknown"
            for kw in ["MIPS", "ARM", "x86", "x86-64", "PowerPC", "AArch64"]:
                if kw.lower() in out.lower():
                    arch = kw
                    break
            archs.add(arch)

    _ok(f"Found {len(elf_files)} ELF binaries. Architectures: {', '.join(archs) if archs else 'unknown'}")
    if elf_files:
        findings.append(Finding(
            "ELF Binaries", LOW,
            root,
            f"{len(elf_files)} ELF binaries found. Architectures: {', '.join(archs)}"
        ))
    return findings


def grep_dangerous_functions(root: Path):
    _info("Grepping for dangerous C function calls...")
    findings = []

    for func, (severity, explanation) in DANGEROUS_FUNCTIONS.items():
        pattern = rf'\b{func}\s*\('
        stdout, _, rc = run_cmd(
            f'grep -rn --include="*.c" --include="*.h" --include="*.cpp" '
            f'-E "{pattern}" "{root}" 2>/dev/null | head -100'
        )
        if stdout.strip():
            for line in stdout.strip().splitlines()[:20]:
                parts = line.split(":", 2)
                fpath = parts[0] if len(parts) >= 1 else "?"
                lineno = parts[1] if len(parts) >= 2 else "?"
                findings.append(Finding(
                    "Dangerous Function", severity,
                    fpath, f"{func}() — {explanation}", line=lineno
                ))

    # Also search compiled binaries via strings
    stdout, _, _ = run_cmd(
        f'find "{root}" -type f | xargs file 2>/dev/null | grep ELF | cut -d: -f1 | '
        f'xargs -I{{}} strings {{}} 2>/dev/null | grep -E "\\b(system|popen|gets)\\s*\\(" | head -50'
    )
    if stdout.strip():
        findings.append(Finding(
            "Dangerous Function (binary)", MEDIUM,
            root,
            f"Dangerous function strings found in ELF binaries (use a disassembler to confirm)"
        ))

    count = len([f for f in findings if f.category in ("Dangerous Function", "Dangerous Function (binary)")])
    _ok(f"Dangerous function scan: {count} matches")
    return findings


def find_credentials(root: Path):
    _info("Searching for hardcoded credentials...")
    findings = []

    config_exts = ["*.conf", "*.xml", "*.txt", "*.cfg", "*.ini", "*.json", "*.yaml", "*.yml", "*.env"]
    ext_glob = " ".join(f'--include="{e}"' for e in config_exts)

    for pattern, severity, label in CRED_PATTERNS:
        stdout, _, _ = run_cmd(
            f'grep -rni {ext_glob} -E "{pattern}" "{root}" 2>/dev/null | '
            f'grep -v "example\\|sample\\|template\\|placeholder\\|YOUR_" | head -50'
        )
        if stdout.strip():
            for line in stdout.strip().splitlines()[:15]:
                parts = line.split(":", 2)
                fpath = parts[0] if len(parts) >= 1 else "?"
                matched = parts[2].strip() if len(parts) >= 3 else line
                # Redact value for safety in output
                redacted = re.sub(r'(=\s*)(\S+)', r'\1[REDACTED]', matched)
                findings.append(Finding(
                    "Hardcoded Credential", severity, fpath, f"{label}: {redacted}"
                ))

    count = len([f for f in findings if f.category == "Hardcoded Credential"])
    _ok(f"Credential scan: {count} potential matches")
    return findings


def find_scripts(root: Path):
    _info("Finding CGI and shell scripts...")
    findings = []

    # CGI scripts
    stdout, _, _ = run_cmd(f'find "{root}" -name "*.cgi" -o -name "*.sh" -o -name "*.bash" 2>/dev/null')
    scripts = [Path(l.strip()) for l in stdout.splitlines() if l.strip()]

    for script in scripts:
        cat = "CGI Script" if script.suffix == ".cgi" else "Shell Script"
        severity = MEDIUM if script.suffix == ".cgi" else LOW
        # check for shell injection patterns inside the script
        risk_flag = ""
        try:
            content = script.read_text(errors="replace")
            if re.search(r'\$_(GET|POST|REQUEST|QUERY_STRING)', content):
                severity = HIGH
                risk_flag = " [user input → shell]"
            elif re.search(r'system\s*\(|popen\s*\(|exec\s*\(|\$\(', content):
                severity = HIGH
                risk_flag = " [shell execution]"
        except (IOError, OSError):
            pass
        findings.append(Finding(cat, severity, script, f"{cat}{risk_flag}"))

    _ok(f"Scripts found: {len(scripts)}")
    return findings


def find_vapix_endpoints(root: Path):
    _info("Scanning for VAPIX / axis-cgi endpoints...")
    findings = []

    stdout, _, _ = run_cmd(
        f'grep -rn --include="*.c" --include="*.h" --include="*.cgi" '
        f'--include="*.sh" --include="*.conf" --include="*.xml" '
        f'-E "axis-cgi|vapix|VAPIX" "{root}" 2>/dev/null | head -200'
    )

    seen_endpoints = set()
    for line in stdout.splitlines():
        match = re.search(r'(/axis-cgi/[^\s"\'<>&]+)', line)
        if match:
            ep = match.group(1).rstrip(".,;)")
            if ep in seen_endpoints:
                continue
            seen_endpoints.add(ep)

            # Check if it matches known unauthenticated patterns
            is_unauth = any(re.search(p, ep, re.IGNORECASE) for p in VAPIX_UNAUTH_PATTERNS)
            severity = CRITICAL if is_unauth else MEDIUM
            auth_status = "NO (potential unauthenticated access)" if is_unauth else "Unknown"

            findings.append(Finding(
                "VAPIX Endpoint", severity, ep,
                f"Authenticated: {auth_status}"
            ))

    # Also check for VAPIX parameter → shell command patterns
    stdout2, _, _ = run_cmd(
        f'grep -rn --include="*.c" --include="*.cgi" --include="*.sh" '
        f'-E "system|popen|exec" "{root}" 2>/dev/null | grep -i "param\\|cgi\\|query" | head -50'
    )
    if stdout2.strip():
        findings.append(Finding(
            "VAPIX Shell Risk", HIGH,
            root,
            "CGI parameter may reach shell command execution — manual review required"
        ))

    _ok(f"VAPIX endpoints found: {len([f for f in findings if f.category == 'VAPIX Endpoint'])}")
    return findings


def find_keys_and_certs(root: Path):
    _info("Looking for private keys and certificates...")
    findings = []

    patterns = [
        ("*.pem", "PEM file"),
        ("*.key", "Private key"),
        ("*.crt", "Certificate"),
        ("*.cer", "Certificate"),
        ("*.p12", "PKCS#12 bundle"),
        ("*.pfx", "PFX bundle"),
        ("*.der", "DER certificate"),
    ]

    for glob_pat, label in patterns:
        for p in root.rglob(glob_pat):
            severity = CRITICAL if "key" in p.suffix.lower() or "key" in p.name.lower() else HIGH
            detail = label

            # Try to read cert expiry with openssl
            if p.suffix in (".pem", ".crt", ".cer"):
                out, _, rc = run_cmd(f'openssl x509 -in "{p}" -noout -enddate 2>/dev/null')
                if rc == 0 and "notAfter" in out:
                    expiry = out.strip().replace("notAfter=", "Expires: ")
                    detail = f"{label} | {expiry}"
                    if "2020" in expiry or "2019" in expiry or "2018" in expiry:
                        severity = CRITICAL
                        detail += " [EXPIRED]"

            # Check if private key
            try:
                content = p.read_text(errors="replace")
                if "PRIVATE KEY" in content:
                    severity = CRITICAL
                    detail = f"Private key file — {label}"
            except (IOError, OSError):
                pass

            findings.append(Finding("Certificate/Key", severity, p, detail))

    _ok(f"Keys/certs found: {len(findings)}")
    return findings


def detect_vulnerable_libraries(root: Path):
    _info("Detecting vulnerable library versions via strings...")
    findings = []

    # Collect strings from all ELF binaries and shared libs
    stdout, _, _ = run_cmd(
        f'find "{root}" \\( -name "*.so" -o -name "*.so.*" \\) -o '
        f'\\( -type f -name "*" \\) | xargs file 2>/dev/null | grep ELF | '
        f'cut -d: -f1 | head -100 | xargs -I{{}} strings {{}} 2>/dev/null | head -5000'
    )
    # Also check version files and scripts
    stdout2, _, _ = run_cmd(
        f'find "{root}" -name "*.txt" -o -name "*.conf" -o -name "*.xml" | '
        f'xargs grep -h -i "version\\|openssl\\|upnp\\|boa\\|thttpd\\|busybox\\|curl" 2>/dev/null | head -500'
    )

    combined = stdout + "\n" + stdout2

    for lib_name, lib_info in VULNERABLE_LIBS.items():
        matches = re.findall(lib_info["pattern"], combined, re.IGNORECASE)
        if matches:
            version = matches[0] if matches else "detected (version unclear)"
            cve_list = ", ".join(lib_info["cves"])
            findings.append(Finding(
                "Vulnerable Library", HIGH,
                root,
                f"{lib_name} v{version} detected — Known CVEs: {cve_list}"
            ))
        else:
            # Pattern-free keyword detection
            if lib_name.lower() in combined.lower():
                findings.append(Finding(
                    "Vulnerable Library", MEDIUM,
                    root,
                    f"{lib_name} detected (version unclear) — check: {', '.join(lib_info['cves'][:1])}"
                ))

    _ok(f"Library scan complete: {len(findings)} findings")
    return findings


def axis_specific_checks(root: Path):
    _info("Running Axis-specific checks...")
    findings = []

    # 1. Boa / thttpd web server
    for server in ["boa", "thttpd"]:
        stdout, _, _ = run_cmd(
            f'find "{root}" -name "{server}" -o -name "{server}.conf" 2>/dev/null'
        )
        if stdout.strip():
            findings.append(Finding(
                "Web Server", HIGH, stdout.strip().splitlines()[0],
                f"{server} web server found — common in legacy Axis devices; check for path traversal / DoS CVEs"
            ))

    # 2. ONVIF service handlers
    stdout, _, _ = run_cmd(
        f'grep -rn --include="*.c" --include="*.h" --include="*.xml" --include="*.wsdl" '
        f'-i "onvif" "{root}" 2>/dev/null | head -30'
    )
    if stdout.strip():
        findings.append(Finding(
            "ONVIF Service", MEDIUM, root,
            "ONVIF service handlers found — review authentication enforcement on service endpoints"
        ))

    # 3. Strings: axis / AXIS / vapix attack surface mapping
    stdout, _, _ = run_cmd(
        f'grep -rn --include="*.c" --include="*.h" --include="*.cgi" --include="*.sh" '
        f'-i "axis\\|vapix" "{root}" 2>/dev/null | grep -v "Binary file" | wc -l'
    )
    count = stdout.strip()
    findings.append(Finding(
        "Axis Attack Surface", LOW, root,
        f"{count} source references to 'axis' or 'vapix' — use for attack surface mapping"
    ))

    # 4. VAPIX param → shell
    stdout, _, _ = run_cmd(
        f'grep -rn --include="*.cgi" --include="*.sh" --include="*.c" '
        f'-E "(system|popen|exec).*cgi_param|cgi_param.*(system|popen|exec)" "{root}" 2>/dev/null | head -20'
    )
    if stdout.strip():
        for line in stdout.strip().splitlines()[:5]:
            findings.append(Finding(
                "VAPIX Shell Injection", CRITICAL, line.split(":")[0],
                "CGI parameter passed directly to shell command — manual verification required"
            ))

    _ok(f"Axis-specific checks: {len(findings)} findings")
    return findings


# ── Diff mode ────────────────────────────────────────────────────────────────

def step_diff(dir_a: Path, dir_b: Path):
    _sep()
    _info("DIFF MODE — comparing two firmware versions")
    _sep()

    stdout, _, _ = run_cmd(f'diff -rq "{dir_a}" "{dir_b}" 2>/dev/null | head -200')
    lines = stdout.strip().splitlines()

    added   = [l for l in lines if l.startswith("Only in") and str(dir_b) in l]
    removed = [l for l in lines if l.startswith("Only in") and str(dir_a) in l]
    changed = [l for l in lines if l.startswith("Files")]

    _info(f"Added files:   {len(added)}")
    _info(f"Removed files: {len(removed)}")
    _info(f"Changed files: {len(changed)}")

    return {
        "added": added[:50],
        "removed": removed[:50],
        "changed": changed[:50],
    }


# ── Step 3: Report Generation ─────────────────────────────────────────────────

def count_by_severity(findings):
    counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def generate_report(findings, target: Path, output_dir: Path, fmt: str, diff_data=None, compare=None):
    _sep()
    _info("STEP 3 — REPORT GENERATION")
    _sep()

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "markdown":
        report_path = output_dir / f"firmsec_report_{ts}.md"
        content = build_markdown_report(findings, target, diff_data, compare)
    elif fmt == "json":
        report_path = output_dir / f"firmsec_report_{ts}.json"
        content = build_json_report(findings, target, diff_data, compare)
    else:
        report_path = output_dir / f"firmsec_report_{ts}.md"
        content = build_markdown_report(findings, target, diff_data, compare)

    report_path.write_text(content, encoding="utf-8")
    _ok(f"Report written: {report_path}")
    return report_path


def build_markdown_report(findings, target: Path, diff_data, compare):
    counts = count_by_severity(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def findings_of(category):
        return sorted([f for f in findings if f.category == category], key=lambda f: f.sort_key())

    def severity_badge(sev):
        badges = {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵"}
        return badges.get(sev, "⚪")

    lines = []
    lines += [
        f"# FirmSec Analysis Report",
        f"",
        f"> Generated: {now}  ",
        f"> Target: `{target}`  ",
        f"> Tool: FirmSec v1.0 (Axis OS Firmware Security Analyzer)",
        f"",
    ]

    # ── Executive Summary ──────────────────────────────────────────────────────
    lines += [
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {counts[CRITICAL]} |",
        f"| 🟠 High     | {counts[HIGH]} |",
        f"| 🟡 Medium   | {counts[MEDIUM]} |",
        f"| 🔵 Low      | {counts[LOW]} |",
        f"| **Total**   | **{sum(counts.values())}** |",
        "",
        f"**Firmware target:** `{target.name}`  ",
        f"**Target device:** Axis OS (camera / IoT device)  ",
        f"**Analysis date:** {now}  ",
        "",
    ]

    if counts[CRITICAL] > 0:
        lines.append(f"> ⚠️ **{counts[CRITICAL]} CRITICAL findings require immediate attention.**")
        lines.append("")

    # ── Dangerous Functions ────────────────────────────────────────────────────
    df = findings_of("Dangerous Function") + findings_of("Dangerous Function (binary)")
    lines += ["## Dangerous Functions", ""]
    if df:
        lines += [
            "| Severity | File | Line | Function | Notes |",
            "|----------|------|------|----------|-------|",
        ]
        for f in df:
            badge = severity_badge(f.severity)
            fname = Path(f.path).name
            lineno = f.line or "—"
            lines.append(f"| {badge} {f.severity} | `{fname}` | {lineno} | {f.detail} | |")
    else:
        lines.append("_No dangerous function calls found in source files._")
    lines.append("")

    # ── Hardcoded Credentials ──────────────────────────────────────────────────
    hc = findings_of("Hardcoded Credential")
    lines += ["## Hardcoded Credentials", ""]
    if hc:
        lines += [
            "| Severity | File | Match |",
            "|----------|------|-------|",
        ]
        for f in hc:
            badge = severity_badge(f.severity)
            fname = Path(f.path).name
            lines.append(f"| {badge} {f.severity} | `{fname}` | `{f.detail}` |")
    else:
        lines.append("_No hardcoded credentials detected._")
    lines.append("")

    # ── VAPIX Endpoints ────────────────────────────────────────────────────────
    ve = findings_of("VAPIX Endpoint") + findings_of("VAPIX Shell Risk") + findings_of("VAPIX Shell Injection")
    lines += ["## VAPIX Endpoints", ""]
    if ve:
        lines += [
            "| Severity | Endpoint / Path | Authentication | Risk |",
            "|----------|-----------------|----------------|------|",
        ]
        for f in ve:
            badge = severity_badge(f.severity)
            lines.append(f"| {badge} {f.severity} | `{f.path}` | {f.detail} | — |")
    else:
        lines.append("_No VAPIX endpoints detected._")
    lines.append("")

    # ── CGI Scripts ───────────────────────────────────────────────────────────
    cgi = findings_of("CGI Script") + findings_of("Shell Script")
    lines += ["## CGI and Shell Scripts", ""]
    if cgi:
        lines += [
            "| Severity | File | Type | Notes |",
            "|----------|------|------|-------|",
        ]
        for f in cgi:
            badge = severity_badge(f.severity)
            fname = Path(f.path).name
            lines.append(f"| {badge} {f.severity} | `{fname}` | {f.category} | {f.detail} |")
    else:
        lines.append("_No CGI or shell scripts found._")
    lines.append("")

    # ── Certificates and Keys ─────────────────────────────────────────────────
    ck = findings_of("Certificate/Key")
    lines += ["## Certificates and Keys", ""]
    if ck:
        lines += [
            "| Severity | File | Details |",
            "|----------|------|---------|",
        ]
        for f in ck:
            badge = severity_badge(f.severity)
            fname = Path(f.path).name
            lines.append(f"| {badge} {f.severity} | `{fname}` | {f.detail} |")
    else:
        lines.append("_No certificates or keys found._")
    lines.append("")

    # ── Vulnerable Libraries ──────────────────────────────────────────────────
    vl = findings_of("Vulnerable Library")
    lines += ["## Vulnerable Libraries", ""]
    if vl:
        lines += [
            "| Severity | Library | Details |",
            "|----------|---------|---------|",
        ]
        for f in vl:
            badge = severity_badge(f.severity)
            lines.append(f"| {badge} {f.severity} | — | {f.detail} |")
    else:
        lines.append("_No vulnerable library versions detected._")
    lines.append("")

    # ── Axis-Specific ─────────────────────────────────────────────────────────
    ax = (findings_of("Web Server") + findings_of("ONVIF Service") +
          findings_of("Axis Attack Surface") + findings_of("ELF Binaries"))
    lines += ["## Axis-Specific Findings", ""]
    if ax:
        lines += [
            "| Severity | Category | Details |",
            "|----------|----------|---------|",
        ]
        for f in ax:
            badge = severity_badge(f.severity)
            lines.append(f"| {badge} {f.severity} | {f.category} | {f.detail} |")
    else:
        lines.append("_No Axis-specific findings._")
    lines.append("")

    # ── Diff Section ──────────────────────────────────────────────────────────
    if diff_data:
        lines += ["## Firmware Diff", "", f"Comparing `{target}` vs `{compare}`", ""]
        lines += [f"- **Added files:** {len(diff_data['added'])}",
                  f"- **Removed files:** {len(diff_data['removed'])}",
                  f"- **Changed files:** {len(diff_data['changed'])}", ""]
        if diff_data["added"]:
            lines += ["### Added Files", "```"]
            lines += diff_data["added"][:20]
            lines += ["```", ""]
        if diff_data["removed"]:
            lines += ["### Removed Files", "```"]
            lines += diff_data["removed"][:20]
            lines += ["```", ""]
        if diff_data["changed"]:
            lines += ["### Changed Files", "```"]
            lines += diff_data["changed"][:20]
            lines += ["```", ""]

    # ── Recommended Next Steps ────────────────────────────────────────────────
    lines += ["## Recommended Next Steps", ""]
    steps = []
    if counts[CRITICAL] > 0:
        steps.append("1. 🔴 **[CRITICAL]** Remove or rotate all hardcoded credentials and private keys immediately.")
        steps.append("2. 🔴 **[CRITICAL]** Audit unauthenticated VAPIX endpoints — enforce digest/basic auth or mTLS.")
    if counts[HIGH] > 0:
        steps.append("3. 🟠 **[HIGH]** Review dangerous function usage (especially `system()`, `popen()`, `strcpy()`) for user-controlled input paths.")
        steps.append("4. 🟠 **[HIGH]** Update vulnerable libraries (OpenSSL, libupnp, Boa) to patched versions.")
    if counts[MEDIUM] > 0:
        steps.append("5. 🟡 **[MEDIUM]** Audit CGI scripts for parameter sanitization before shell execution.")
        steps.append("6. 🟡 **[MEDIUM]** Review ONVIF service endpoint authentication.")
    steps += [
        "7. 🔵 **[GENERAL]** Enable Axis firmware signing and secure boot if not already active.",
        "8. 🔵 **[GENERAL]** Cross-reference all `axis-cgi` endpoints against the VAPIX API reference for required auth levels.",
        "9. 🔵 **[GENERAL]** Run dynamic analysis / fuzzing on high-risk CGI endpoints in an isolated lab.",
        "10. 🔵 **[GENERAL]** Subscribe to Axis security advisories: https://www.axis.com/support/cybersecurity/security-advisories",
    ]
    lines += steps
    lines.append("")
    lines += [
        "---",
        f"_Report generated by FirmSec v1.0 — {now}_",
    ]

    return "\n".join(lines)


def build_json_report(findings, target, diff_data, compare):
    import json
    data = {
        "tool": "FirmSec v1.0",
        "generated": datetime.now().isoformat(),
        "target": str(target),
        "compare": str(compare) if compare else None,
        "summary": count_by_severity(findings),
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "path": f.path,
                "detail": f.detail,
                "line": f.line,
            }
            for f in sorted(findings, key=lambda x: x.sort_key())
        ],
        "diff": diff_data,
    }
    return json.dumps(data, indent=2)


# ── Print summary to terminal ─────────────────────────────────────────────────

def print_terminal_summary(findings):
    counts = count_by_severity(findings)
    _sep()
    _info("FINDINGS SUMMARY")
    _sep()

    if HAS_RICH:
        table = Table(title="FirmSec Results", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Top Finding")
        for sev in [CRITICAL, HIGH, MEDIUM, LOW]:
            sev_findings = [f for f in findings if f.severity == sev]
            top = sev_findings[0].detail[:60] if sev_findings else "—"
            colors = {CRITICAL: "red", HIGH: "magenta", MEDIUM: "yellow", LOW: "cyan"}
            table.add_row(f"[{colors[sev]}]{sev}[/{colors[sev]}]", str(counts[sev]), top)
        console.print(table)
    else:
        for sev in [CRITICAL, HIGH, MEDIUM, LOW]:
            print(f"  {severity_color(sev):10s}: {counts[sev]}")


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="firmsec",
        description="FirmSec — Axis OS Firmware Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  firmsec.py --target axis_firmware.bin
  firmsec.py --target axis_firmware.bin --output ./my_reports --format json
  firmsec.py --target axis_fw_v9.bin --compare axis_fw_v10.bin
  firmsec.py --target ./extracted_firmware/ --skip-extract
  firmsec.py --target axis_firmware.bin --kali
        """
    )
    parser.add_argument("--target",       required=True,      help="Path to firmware binary or extracted directory")
    parser.add_argument("--compare",      default=None,       help="Second firmware for diff comparison")
    parser.add_argument("--output",       default="./reports",help="Output directory for reports")
    parser.add_argument("--format",       default="markdown", choices=["markdown", "json", "html"],
                        help="Report format (default: markdown)")
    parser.add_argument("--skip-extract", action="store_true",help="Skip extraction (use if already extracted)")
    parser.add_argument("--kali",         action="store_true",help="Adjust tool paths for Kali Linux")
    return parser.parse_args()


def main():
    args = parse_args()
    target = Path(args.target).resolve()
    output_dir = Path(args.output).resolve()

    if HAS_RICH:
        console.print(Panel.fit(
            "[bold cyan]FirmSec v1.0[/bold cyan] — Axis OS Firmware Security Analyzer\n"
            "[dim]Optimized for Axis OS | Mac + Kali Linux[/dim]",
            border_style="cyan"
        ))
    else:
        print("=" * 60)
        print("  FirmSec v1.0 — Axis OS Firmware Security Analyzer")
        print("=" * 60)

    if not target.exists():
        _err(f"Target not found: {target}")
        sys.exit(1)

    diff_data = None
    compare_path = None

    # ── Extraction ────────────────────────────────────────────────────────────
    if target.is_file() and not args.skip_extract:
        extract_dir, fs_type = step_extract(target, args.kali)
    elif target.is_dir() or args.skip_extract:
        extract_dir = target
        fs_type = detect_filesystem(target)
        _info(f"Using pre-extracted directory: {extract_dir} (fs: {fs_type})")
        print_tree_summary(extract_dir)
    else:
        _err("Target must be a file (firmware) or directory (extracted).")
        sys.exit(1)

    # ── Diff ──────────────────────────────────────────────────────────────────
    if args.compare:
        compare_path = Path(args.compare).resolve()
        if compare_path.is_file():
            compare_extract, _ = step_extract(compare_path, args.kali)
        else:
            compare_extract = compare_path
        diff_data = step_diff(extract_dir, compare_extract)

    # ── Analysis ──────────────────────────────────────────────────────────────
    findings = step_analyze(extract_dir, args.kali)

    # ── Terminal summary ──────────────────────────────────────────────────────
    print_terminal_summary(findings)

    # ── Report ────────────────────────────────────────────────────────────────
    report_path = generate_report(
        findings, target, output_dir,
        args.format, diff_data, compare_path
    )

    _sep()
    _ok(f"Done! Report: {report_path}")
    if HAS_RICH:
        console.print(Panel(f"[green]Report saved:[/green] [bold]{report_path}[/bold]", border_style="green"))


if __name__ == "__main__":
    main()
