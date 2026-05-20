#!/usr/bin/env python3
"""
FirmSec - Firmware Security Analysis Tool for Axis OS Devices
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
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

# ── ELF machine type → architecture name ────────────────────────────────────

ELF_MACHINES = {
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}

# ── Dangerous function definitions ────────────────────────────────────────────

DANGEROUS_FUNCTIONS = {
    "system":   (HIGH,     "Shell command execution; user input may reach shell"),
    "popen":    (HIGH,     "Pipe to shell; command injection risk"),
    "strcpy":   (HIGH,     "Unbounded copy; classic stack overflow vector"),
    "strcat":   (HIGH,     "Unbounded concatenation; buffer overflow risk"),
    "sprintf":  (MEDIUM,   "Unbounded format write; potential buffer overflow"),
    "vsprintf": (MEDIUM,   "Unbounded variadic format write"),
    "gets":     (CRITICAL, "Always unsafe; removed from C11"),
    "scanf":    (MEDIUM,   "Unbounded input; format string risk"),
    "memcpy":   (LOW,      "Length must be validated by caller"),
    "bcopy":    (LOW,      "Deprecated; prefer memmove"),
    "printf":   (MEDIUM,   "Verify format string is not user-controlled"),
    "exec":     (HIGH,     "Process execution; argument injection risk"),
}

# ── Credential patterns ───────────────────────────────────────────────────────

CRED_PATTERNS = [
    (r'password\s*[=:]\s*\S+',     CRITICAL, "Hardcoded password"),
    (r'passwd\s*[=:]\s*\S+',       CRITICAL, "Hardcoded passwd field"),
    (r'secret\s*[=:]\s*\S+',       CRITICAL, "Hardcoded secret"),
    (r'api[_-]?key\s*[=:]\s*\S+',  CRITICAL, "Hardcoded API key"),
    (r'private[_-]?key\s*[=:]\s*\S+', CRITICAL, "Hardcoded private key reference"),
    (r'admin\s*[=:]\s*\S+',        HIGH,     "Hardcoded admin value"),
    (r'root\s*[=:]\s*\S+',         HIGH,     "Hardcoded root value"),
    (r'token\s*[=:]\s*\S+',        HIGH,     "Hardcoded token"),
    (r'auth\s*[=:]\s*\S+',         MEDIUM,   "Hardcoded auth value"),
    (r'username\s*[=:]\s*\S+',     MEDIUM,   "Hardcoded username"),
]

CRED_FILE_EXTS = [
    "*.conf", "*.xml", "*.txt", "*.cfg", "*.ini",
    "*.json", "*.yaml", "*.yml", "*.env",
    "*.js",   "*.html","*.php", "*.sh",  "*.py",
    "*.properties", "*.toml",
]

# ── Vulnerable library signatures ─────────────────────────────────────────────

VULNERABLE_LIBS = {
    "openssl":  {
        "pattern": r'(?:openssl|OpenSSL)[/ \-_v]*([\d]+\.[\d]+\.[\d]+[a-z]?)',
        "cves": [
            "CVE-2014-0160 (Heartbleed, <1.0.1g)",
            "CVE-2016-2107 (padding oracle, <1.0.1t/<1.0.2h)",
            "CVE-2022-0778 (<1.0.2zd,<1.1.1n,<3.0.2)",
        ],
    },
    "libupnp": {
        "pattern": r'libupnp[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            "CVE-2012-5958 (≤1.6.17 stack overflow)",
            "CVE-2016-8863 (≤1.6.20 heap overflow)",
        ],
    },
    "boa": {
        "pattern": r'boa[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            "CVE-2017-9833 (directory traversal)",
            "CVE-2021-33558 (information disclosure)",
        ],
    },
    "thttpd": {
        "pattern": r'thttpd[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            "CVE-2017-11549 (null pointer dereference)",
            "CVE-2022-38723 (buffer overflow)",
        ],
    },
    "busybox": {
        "pattern": r'[Bb]usyBox[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            "CVE-2021-42374 (lzma OOB read)",
            "CVE-2022-28391 (hush shell command injection)",
        ],
    },
    "curl": {
        "pattern": r'curl[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": ["CVE-2023-38545 (SOCKS5 heap overflow, <8.4.0)"],
    },
    "dropbear": {
        "pattern": r'[Dd]ropbear[/ \-_v]*([\d]+\.[\d]+)',
        "cves": [
            "CVE-2016-7406 (format string via username, <2016.74)",
            "CVE-2017-9078 (use-after-free, <2017.75)",
        ],
    },
    "zlib": {
        "pattern": r'zlib[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": ["CVE-2022-37434 (heap buffer overflow via inflateGetHeader, <1.2.13)"],
    },
}

# ── VAPIX / axis-cgi patterns ─────────────────────────────────────────────────

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
    r'/axis-cgi/basicdeviceinfo\.cgi',
]

# Known default Axis credentials
AXIS_DEFAULT_CREDS = [
    ("root",  "pass"),
    ("root",  "root"),
    ("admin", "admin"),
    ("admin", ""),
    ("root",  ""),
]

# ── Credential severity context ───────────────────────────────────────────────
#
# CRITICAL: credential is reachable without any authentication
#   • File lives in a web-served directory (var/www, cgi-bin, html …)
#     → a single unauthenticated HTTP request retrieves it
#   • Pattern type is always high-impact regardless of location:
#     API keys, private key references, secrets
#
# HIGH: credential requires firmware image extraction or local filesystem access
#   • /etc config files, source code, init scripts, binary strings
#   • Firmware images are often publicly downloadable, so this is still serious,
#     but the attacker needs the image rather than just an HTTP request
#
# Passwords/tokens in non-web paths are downgraded from their base severity
# to HIGH for this reason.

WEB_ACCESSIBLE_DIRS = {
    "www", "html", "htdocs", "webroot", "public_html",
    "cgi-bin", "cgi", "www-data", "web",
}

ALWAYS_CRITICAL_LABELS = {
    "Hardcoded API key",
    "Hardcoded private key reference",
    "Hardcoded secret",
}

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

# ── Credential false-positive suppression ────────────────────────────────────
#
# Each rule is (filename_regex, matched_content_regex).
# When BOTH match a finding it is silently dropped.
#
# Rationale for each rule:
#   par_*.conf        — "accessControl = admin" is a VAPIX parameter ACL schema
#                       field (admin/operator/viewer access level), not a secret.
#   nsswitch.conf     — "passwd: files systemd" is an NSS database-lookup directive.
#   com.axis.*.xml    — "@passwd" / "@clear_passwd" are D-Bus argument names in
#                       auto-generated interface documentation XML.
#   httpd.conf        — Apache ServerAdmin / ServerRoot / DocumentRoot directives
#                       contain the words "admin" / "root" as keywords, not values.
#   limited_access /  — _allow_root, _exec_as_root, _deprecated_access are shell
#   adp.sh              boolean flag variable names, not credential assignments.
#   *.min.js /        — Minified JS and known libraries produce too many substring
#   showdown*.js        hits on variable names like "secret", "token", "root".

FALSE_POSITIVE_RULES = [
    # VAPIX legacymappings XML — accessControl ACL values like "admin:3;operator:3;viewer:1"
    # are numeric permission levels, not credential values.
    # The match key is the content pattern; we apply this to all XML files.
    (r'\.xml$',                      r'name=["\']?accessControl["\']?'),
    # par_*.conf — VAPIX parameter schema files:
    #   "accessControl = admin"  → ACL level enum, not a secret
    #   "type = password:writeonly"  → parameter type annotation, not a value
    (r'^par_[^/]*\.conf$',          r'^\s*accessControl\s*=|^\s*type\s*=\s*"?password'),
    (r'^nsswitch\.conf$',           r'^\s*passwd\s*:'),
    # com.axis.*.xml — D-Bus interface documentation:
    #   "@passwd" / "@clear_passwd" / "@username" are argument names, not values
    #   "<arg … name=\"username\"" is XML schema, not a credential
    (r'^com\.axis\.[^/]*\.xml$',    r'@(passwd|clear_passwd|username)\b|name="(username|passwd)"'),
    (r'^httpd\.conf$',              r'#\s*(ServerAdmin|ServerRoot|DocumentRoot)\b'),
    (r'^(limited_access|adp)\.sh$', r'(_allow_root|_exec_as_root|_deprecated_access)\s*[=!]'),
    (r'\.min\.js$',                 r'.*'),
    (r'^showdown[^/]*\.js$',        r'.*'),
]

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


# ── Helper utilities ──────────────────────────────────────────────────────────

def _c(text, color):
    if HAS_COLORAMA:
        return f"{color}{text}{Style.RESET_ALL}"
    return text

def _ok(msg):   print(_c(f"[+] {msg}", Fore.GREEN if HAS_COLORAMA else ""))
def _info(msg): print(_c(f"[*] {msg}", Fore.CYAN if HAS_COLORAMA else ""))
def _warn(msg): print(_c(f"[!] {msg}", Fore.YELLOW if HAS_COLORAMA else ""))
def _err(msg):  print(_c(f"[-] {msg}", Fore.RED if HAS_COLORAMA else ""), file=sys.stderr)
def _sep():     print(_c("─" * 60, Fore.BLUE if HAS_COLORAMA else ""))

def severity_color(sev):
    if not HAS_COLORAMA:
        return sev
    colors = {CRITICAL: Fore.RED, HIGH: Fore.MAGENTA, MEDIUM: Fore.YELLOW, LOW: Fore.CYAN}
    return _c(sev, colors.get(sev, ""))

def check_tool(name, kali=False):
    result = subprocess.run(["which", name], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    _warn(f"Tool not found: {name}")
    hints = {
        "binwalk": ("sudo apt install binwalk", "brew install binwalk"),
        "file":    ("built-in", "built-in"),
        "strings": ("sudo apt install binutils", "brew install binutils"),
        "readelf": ("sudo apt install binutils", "brew install binutils  # provides greadelf"),
        "openssl": ("sudo apt install openssl", "brew install openssl"),
    }
    if name in hints:
        apt_h, brew_h = hints[name]
        _warn(f"  Kali: {apt_h}  |  Mac: {brew_h}")
    return None

def run_cmd(cmd, timeout=300):
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

def read_elf_arch(path: Path) -> str:
    """Decode CPU architecture directly from ELF header bytes."""
    try:
        with open(path, "rb") as f:
            header = f.read(20)
        if len(header) < 20 or header[:4] != b'\x7fELF':
            return "unknown"
        ei_data = header[5]  # 1=LE, 2=BE
        e_machine_bytes = header[18:20]
        if ei_data == 1:
            e_machine = struct.unpack_from("<H", e_machine_bytes)[0]
        else:
            e_machine = struct.unpack_from(">H", e_machine_bytes)[0]
        return ELF_MACHINES.get(e_machine, f"e_machine=0x{e_machine:02x}")
    except (IOError, OSError, struct.error):
        return "unknown"

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

    parent = target.parent
    candidates = sorted(parent.glob(f"_{target.name}.extracted"),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        candidates = sorted(Path(".").glob(f"_{target.name}.extracted"),
                            key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        _warn("Scanning for any .extracted directory near the target...")
        candidates = sorted(parent.glob("*.extracted"),
                            key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        _err("Extraction directory not found. Check binwalk output above.")
        sys.exit(1)

    extract_dir = candidates[0]
    _ok(f"Extracted to: {extract_dir}")
    fs_type = detect_filesystem(extract_dir)
    _info(f"Detected filesystem type: {fs_type}")
    print_tree_summary(extract_dir)
    return extract_dir, fs_type

def detect_filesystem(extract_dir: Path) -> str:
    for marker, label in [("squashfs-root", "SquashFS"), ("cramfs", "CramFS"), ("jffs2", "JFFS2")]:
        if any(extract_dir.rglob(f"*{marker}*")):
            return label
    subdirs = [d.name.lower() for d in extract_dir.iterdir() if d.is_dir()]
    if any("squash" in d for d in subdirs):
        return "SquashFS"
    return "Unknown"

def print_tree_summary(root: Path):
    _info("Extracted directory tree (top 3 levels):")
    if HAS_RICH:
        tree = Tree(f"[bold]{root.name}[/bold]")
        _build_rich_tree(tree, root, depth=0, max_depth=3, max_entries=60)
        console.print(tree)
    else:
        count = 0
        for item in sorted(root.rglob("*")):
            if count > 60:
                print("  ... (truncated)")
                break
            depth = len(item.relative_to(root).parts) - 1
            if depth > 2:
                continue
            prefix = "  " * depth + ("📁 " if item.is_dir() else "📄 ")
            print(f"  {prefix}{item.name}")
            count += 1

def _build_rich_tree(node, path, depth, max_depth, max_entries, _c=[0]):
    if depth >= max_depth or _c[0] > max_entries:
        return
    try:
        children = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name))
    except PermissionError:
        return
    for child in children:
        if _c[0] > max_entries:
            node.add("[dim]...[/dim]")
            break
        _c[0] += 1
        label = f"[bold blue]{child.name}[/bold blue]" if child.is_dir() else child.name
        branch = node.add(label)
        if child.is_dir():
            _build_rich_tree(branch, child, depth + 1, max_depth, max_entries, _c)

# ── Finding class ─────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, category, severity, path, detail, line=None, evidence=None):
        self.category = category
        self.severity = severity
        self.path = str(path)
        self.detail = detail
        self.line = line
        self.evidence = evidence

    def sort_key(self):
        return SEVERITY_ORDER.get(self.severity, 99)

# ── Step 2: Static Analysis ───────────────────────────────────────────────────

def step_analyze(extract_dir: Path, kali: bool):
    _sep()
    _info("STEP 2 — STATIC ANALYSIS")
    _sep()

    findings = []
    findings += find_elf_binaries(extract_dir, kali)
    findings += grep_dangerous_functions(extract_dir)
    findings += find_credentials(extract_dir)
    findings += find_passwd_shadow(extract_dir)
    findings += find_scripts(extract_dir)
    findings += find_init_scripts(extract_dir)
    findings += find_vapix_endpoints(extract_dir)
    findings += find_keys_and_certs(extract_dir)
    findings += detect_vulnerable_libraries(extract_dir)
    findings += analyze_webserver_configs(extract_dir)
    findings += find_network_services(extract_dir)
    findings += axis_specific_checks(extract_dir)
    findings += cross_reference_unauth_rce(findings)

    _ok(f"Analysis complete. {len(findings)} findings.")
    return findings


def find_elf_binaries(root: Path, kali: bool):
    _info("Scanning for ELF binaries and detecting architecture...")
    findings = []
    elf_files = []

    for p in root.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        try:
            with open(p, "rb") as f:
                magic = f.read(4)
            if magic == b'\x7fELF':
                elf_files.append(p)
        except (IOError, OSError):
            continue

    arch_map: dict[str, list] = {}
    for p in elf_files:
        arch = read_elf_arch(p)
        arch_map.setdefault(arch, []).append(p)

    arch_summary = ", ".join(f"{a}×{len(v)}" for a, v in sorted(arch_map.items()))
    _ok(f"Found {len(elf_files)} ELF binaries — {arch_summary or 'none'}")

    if elf_files:
        findings.append(Finding(
            "ELF Binaries", LOW, root,
            f"{len(elf_files)} ELF binaries. Architectures: {arch_summary}"
        ))

    # Flag SUID binaries — privilege escalation vector
    stdout, _, _ = run_cmd(f'find "{root}" -perm -4000 -type f 2>/dev/null')
    for suid in stdout.strip().splitlines():
        if suid.strip():
            findings.append(Finding(
                "SUID Binary", HIGH, suid.strip(),
                "SUID bit set — potential privilege escalation; review if necessary"
            ))

    return findings


def grep_dangerous_functions(root: Path):
    _info("Grepping for dangerous C function calls in source files...")
    findings = []

    src_exts = '--include="*.c" --include="*.h" --include="*.cpp" --include="*.cc"'

    for func, (severity, explanation) in DANGEROUS_FUNCTIONS.items():
        pattern = rf'\b{func}\s*\('
        stdout, _, _ = run_cmd(
            f'grep -rn {src_exts} -E "{pattern}" "{root}" 2>/dev/null | head -100'
        )
        if stdout.strip():
            for line in stdout.strip().splitlines()[:20]:
                parts = line.split(":", 2)
                fpath = parts[0] if len(parts) >= 1 else "?"
                lineno = parts[1] if len(parts) >= 2 else "?"
                findings.append(Finding(
                    "Dangerous Function", severity, fpath,
                    f"{func}() — {explanation}", line=lineno
                ))

    # Scan ELF strings for dangerous calls imported from PLT
    stdout, _, _ = run_cmd(
        f'find "{root}" -type f | xargs file 2>/dev/null | grep ELF | cut -d: -f1 | '
        f'xargs -I{{}} strings {{}} 2>/dev/null | '
        f'grep -E "^(system|popen|gets|strcpy|strcat)$" | sort -u | head -20'
    )
    if stdout.strip():
        funcs_found = stdout.strip().replace("\n", ", ")
        findings.append(Finding(
            "Dangerous Function (binary)", MEDIUM, root,
            f"PLT imports in ELF binaries: {funcs_found} — disassemble to trace call sites"
        ))

    count = len([f for f in findings if "Dangerous Function" in f.category])
    _ok(f"Dangerous function scan: {count} matches")
    return findings


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

                redacted  = re.sub(r'([=:]\s*)(\S+)', r'\1[REDACTED]', matched)

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
        if p.name not in ("passwd", "shadow", "group"):
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


def get_vapix_auth_evidence(ep: str, ref_fpath: str, ref_lineno: str, root: Path) -> tuple:
    """
    Return (snippet, auth_label, hint) for a VAPIX endpoint reference.

    hint is one of 'auth', 'unauth', or 'unknown'.

    Strategy:
      1. Scan Apache2 conf files for <Location>/<LocationMatch> blocks covering the
         endpoint path. Most-specific (longest) matching block wins.
         - AuthType + Require (valid-user OR axis-group) → hint='auth'
         - Require all denied                            → hint='auth'
         - Location block with no auth directives        → hint='unauth'
      2. If no Location block matches, check for a global AuthType directive in
         any Apache conf file (outside a Location block) — Axis OS 11.x sets
         AuthType Digest globally in httpd-digest.conf; endpoints that don't
         have their own Location block inherit this.
      3. Fall back to VAPIX_UNAUTH_PATTERNS pattern matching.
      4. Always return surrounding source lines as additional context.
    """
    hint       = "unknown"
    auth_label = "Unknown — verify with live device or Apache2 config"
    snippet    = ""

    # --- source context window ---
    if ref_fpath and ref_fpath != "?" and ref_lineno and ref_lineno.isdigit():
        ln    = int(ref_lineno)
        start = max(1, ln - 2)
        end   = ln + 2
        out, _, _ = run_cmd(f'sed -n "{start},{end}p" "{ref_fpath}" 2>/dev/null')
        if out.strip():
            snippet = out.strip()[:300]

    # --- Apache2 config scan ---
    apache_dirs = [root / "etc" / "apache2", root / "etc" / "httpd"]
    ep_base     = ep.split("?")[0].rstrip("/") or "/"

    best_match_len = -1
    best_hint      = None
    best_label     = None
    best_conf_snip = None
    global_auth_conf = None   # file that carries a bare AuthType directive

    for apache_dir in apache_dirs:
        if not apache_dir.is_dir():
            continue
        for conf_file in sorted(apache_dir.rglob("*.conf")):
            try:
                conf_content = conf_file.read_text(errors="replace")
            except (IOError, OSError):
                continue

            # Detect bare (non-Location-wrapped) global AuthType
            # Axis OS uses httpd-digest.conf / httpd-basic.conf at the top level.
            bare_auth = re.search(r'(?m)^AuthType\s+\S+', conf_content)
            if bare_auth and not re.search(r'<Location', conf_content, re.IGNORECASE):
                global_auth_conf = conf_file.name

            # Scan <Location> and <LocationMatch> blocks
            for loc_m in re.finditer(
                r'<Location(?:Match)?\s+([^>]+)>(.*?)</Location(?:Match)?>',
                conf_content, re.IGNORECASE | re.DOTALL
            ):
                loc_path  = loc_m.group(1).strip().strip('"').rstrip("/") or "/"
                block     = loc_m.group(2)
                if not (ep_base.startswith(loc_path) or loc_path == "/"):
                    continue
                if len(loc_path) <= best_match_len:
                    continue
                best_match_len = len(loc_path)
                has_auth   = bool(re.search(r'AuthType\s+\S+', block, re.IGNORECASE))
                # Axis OS uses "Require axis-group <group>" instead of "Require valid-user"
                has_req    = bool(re.search(
                    r'Require\s+(valid-user|axis-group\s+\S+)', block, re.IGNORECASE
                ))
                all_denied = bool(re.search(r'Require\s+all\s+denied', block, re.IGNORECASE))
                conf_lines = block.strip().splitlines()[:6]
                conf_snip  = "\n".join(
                    [f"# {conf_file.name}  <Location {loc_path}>"] + conf_lines
                )
                if all_denied:
                    best_hint      = "auth"
                    best_label     = f"Blocked (Require all denied — {conf_file.name}:{loc_path})"
                    best_conf_snip = conf_snip
                elif has_auth and has_req:
                    best_hint      = "auth"
                    best_label     = f"Authenticated (AuthType+Require in {conf_file.name}:{loc_path})"
                    best_conf_snip = conf_snip
                elif has_req and not has_auth:
                    # Require axis-group without inline AuthType → inherits global AuthType
                    best_hint      = "auth"
                    best_label     = (
                        f"Authenticated (Require axis-group in {conf_file.name}:{loc_path}"
                        + (f"; AuthType from {global_auth_conf}" if global_auth_conf else "")
                        + ")"
                    )
                    best_conf_snip = conf_snip
                else:
                    best_hint      = "unauth"
                    best_label     = (
                        f"NO auth directives in <Location {loc_path}> ({conf_file.name})"
                    )
                    best_conf_snip = conf_snip

    if best_hint is not None:
        hint       = best_hint
        auth_label = best_label
        snippet    = best_conf_snip or snippet
    elif global_auth_conf:
        # No Location block matched, but a global AuthType is present — endpoint
        # inherits authentication from the server-wide setting (Axis OS pattern).
        hint       = "auth"
        auth_label = f"Authenticated (inherits global AuthType from {global_auth_conf})"
        snippet    = snippet or f"# Global auth configured in {global_auth_conf}"
    elif any(re.search(pat, ep, re.IGNORECASE) for pat in VAPIX_UNAUTH_PATTERNS):
        hint       = "unauth"
        auth_label = "NO — historically unauthenticated (pattern match; verify with live device)"

    return snippet, auth_label, hint


def find_vapix_endpoints(root: Path):
    _info("Scanning for VAPIX / axis-cgi endpoints...")
    findings = []

    grep_exts = ('--include="*.c" --include="*.h" --include="*.cgi" '
                 '--include="*.sh" --include="*.conf" --include="*.xml" '
                 '--include="*.html" --include="*.js" --include="*.php" '
                 '--include="*.wsdl"')

    stdout, _, _ = run_cmd(
        f'grep -rn {grep_exts} -E "axis-cgi|vapix|VAPIX" "{root}" 2>/dev/null | head -300'
    )

    # endpoint → (first_fpath, first_lineno) — keep the first reference found
    endpoint_refs: dict = {}
    for line in stdout.splitlines():
        m_ref = re.match(r'^(.+?):(\d+):(.*)', line)
        if not m_ref:
            continue
        fpath, lineno, content = m_ref.group(1), m_ref.group(2), m_ref.group(3)
        m_ep = re.search(r'(/axis-cgi/[^\s"\'<>&,;)]+)', content)
        if not m_ep:
            continue
        ep = m_ep.group(1).rstrip(".,;)")
        if ep not in endpoint_refs:
            endpoint_refs[ep] = (fpath, lineno)

    for ep, (ref_fpath, ref_lineno) in endpoint_refs.items():
        evidence_snip, auth_label, hint = get_vapix_auth_evidence(
            ep, ref_fpath, ref_lineno, root
        )
        if hint == "auth":
            severity = LOW
        elif hint == "unauth":
            severity = CRITICAL
        else:
            severity = MEDIUM

        ref_str = f"{Path(ref_fpath).name}:{ref_lineno}" if ref_fpath != "?" else "?"
        findings.append(Finding(
            "VAPIX Endpoint", severity, ep,
            auth_label,
            line=ref_str,
            evidence=evidence_snip or None,
        ))

    # Check for param → shell patterns near VAPIX handler code
    stdout2, _, _ = run_cmd(
        f'grep -rn --include="*.c" --include="*.cgi" --include="*.sh" '
        f'-E "system|popen|exec" "{root}" 2>/dev/null | '
        f'grep -iE "param|cgi|query|QUERY_STRING" | head -50'
    )
    if stdout2.strip():
        findings.append(Finding(
            "VAPIX Shell Risk", HIGH, root,
            "CGI parameter value may flow into shell command — trace input path manually"
        ))

    _ok(f"VAPIX endpoints found: {len([f for f in findings if f.category == 'VAPIX Endpoint'])}")
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
            # Flag clearly expired certs
            try:
                exp_year = int(re.search(r'\d{4}', expiry).group())
                if exp_year < 2025:
                    severity = CRITICAL
                    detail += " ⚠️ EXPIRED"
            except (AttributeError, ValueError):
                pass

    findings.append(Finding("Certificate/Key", severity, p, detail))


def detect_vulnerable_libraries(root: Path):
    _info("Detecting vulnerable library versions via strings and filenames...")
    findings = []

    # Collect all strings from ELF binaries
    elf_strings, _, _ = run_cmd(
        f'find "{root}" -type f | xargs file 2>/dev/null | grep ELF | cut -d: -f1 | '
        f'head -150 | xargs -I{{}} strings -n 6 {{}} 2>/dev/null | head -8000'
    )
    # Collect from shared lib filenames
    lib_filenames, _, _ = run_cmd(f'find "{root}" -name "*.so*" 2>/dev/null')
    # Collect from text config/version files
    text_content, _, _ = run_cmd(
        f'find "{root}" \\( -name "*.txt" -o -name "*.conf" -o -name "*.xml" -o -name "*.ini" \\) | '
        f'xargs grep -hi "version\\|openssl\\|upnp\\|boa\\|thttpd\\|busybox\\|curl\\|dropbear\\|zlib" '
        f'2>/dev/null | head -800'
    )

    combined = "\n".join([elf_strings, lib_filenames, text_content])

    for lib_name, info in VULNERABLE_LIBS.items():
        matches = re.findall(info["pattern"], combined, re.IGNORECASE)
        if matches:
            version = matches[0]
            cve_list = "; ".join(info["cves"])
            findings.append(Finding(
                "Vulnerable Library", HIGH, root,
                f"{lib_name} v{version} — CVEs: {cve_list}"
            ))
        elif re.search(rf'\b{re.escape(lib_name)}\b', combined, re.IGNORECASE):
            findings.append(Finding(
                "Vulnerable Library", MEDIUM, root,
                f"{lib_name} detected (version unclear) — check: {info['cves'][0]}"
            ))

    _ok(f"Library scan: {len(findings)} findings")
    return findings


def analyze_webserver_configs(root: Path):
    _info("Analyzing web server configuration files...")
    findings = []

    config_names = ["boa.conf", "thttpd.conf", "httpd.conf", "lighttpd.conf", "nginx.conf"]
    for conf_name in config_names:
        for p in root.rglob(conf_name):
            try:
                content = p.read_text(errors="replace")
            except (IOError, OSError):
                continue

            # Directory listing
            if re.search(r'DirectoryIndex\s+on|dirlist\s*=\s*yes|autoindex\s+on', content, re.IGNORECASE):
                findings.append(Finding("Web Server Config", MEDIUM, p,
                    f"{conf_name}: Directory listing enabled — information disclosure"))

            # Authentication disabled
            if re.search(r'auth\s*=\s*no|NoAuth|AuthRequired\s+no', content, re.IGNORECASE):
                findings.append(Finding("Web Server Config", CRITICAL, p,
                    f"{conf_name}: Authentication explicitly disabled"))

            # No TLS/SSL configuration
            if not re.search(r'ssl|https|tls|certfile|keyfile', content, re.IGNORECASE):
                findings.append(Finding("Web Server Config", HIGH, p,
                    f"{conf_name}: No SSL/TLS configuration — HTTP only; credentials sent in plaintext"))

            # CGI execution
            if re.search(r'cgi-bin|CGIPath|cgi_path|cgibindir', content, re.IGNORECASE):
                findings.append(Finding("Web Server Config", LOW, p,
                    f"{conf_name}: CGI execution configured — ensure CGI scripts sanitize input"))

            # Verbose errors / server tokens
            if re.search(r'ServerTokens\s+Full|verbose_errors\s*=\s*(yes|1)|servertokens', content, re.IGNORECASE):
                findings.append(Finding("Web Server Config", LOW, p,
                    f"{conf_name}: Full server version disclosed in headers (info disclosure)"))

            # Weak/deprecated SSL ciphers
            if re.search(r'SSLv2|SSLv3|RC4|DES\b|NULL', content):
                findings.append(Finding("Web Server Config", HIGH, p,
                    f"{conf_name}: Deprecated/weak SSL cipher or protocol configured"))

            # Listening on all interfaces
            if re.search(r'bind\s*=?\s*0\.0\.0\.0|listen\s+0\.0\.0\.0', content):
                findings.append(Finding("Web Server Config", MEDIUM, p,
                    f"{conf_name}: Web server bound to 0.0.0.0 (all interfaces)"))

    _ok(f"Web server config scan: {len(findings)} findings")
    return findings


def find_network_services(root: Path):
    _info("Detecting insecure network services and debug interfaces...")
    findings = []

    # Telnet daemon — plaintext
    stdout, _, _ = run_cmd(
        f'find "{root}" \\( -name "telnetd" -o -name "in.telnetd" \\) 2>/dev/null'
    )
    for p in stdout.strip().splitlines():
        if p.strip():
            findings.append(Finding("Network Service", CRITICAL, p.strip(),
                "telnetd binary found — plaintext remote access; attacker can capture credentials"))

    # FTP daemon
    stdout, _, _ = run_cmd(
        f'find "{root}" \\( -name "ftpd" -o -name "vsftpd" -o -name "proftpd" \\) 2>/dev/null'
    )
    for p in stdout.strip().splitlines():
        if p.strip():
            findings.append(Finding("Network Service", HIGH, p.strip(),
                "FTP daemon binary found — plaintext file transfer; use SFTP instead"))

    # Dropbear / SSH
    stdout, _, _ = run_cmd(f'find "{root}" -name "dropbear" -o -name "sshd" 2>/dev/null')
    for p in stdout.strip().splitlines():
        if p.strip():
            findings.append(Finding("Network Service", LOW, p.strip(),
                "SSH daemon found — verify password auth disabled, key-only access enforced"))

    # SNMP config
    stdout, _, _ = run_cmd(f'find "{root}" -name "snmpd.conf" 2>/dev/null')
    for p in stdout.strip().splitlines():
        if p.strip():
            try:
                content = Path(p.strip()).read_text(errors="replace")
                if re.search(r'community\s+public|community\s+private', content, re.IGNORECASE):
                    findings.append(Finding("Network Service", CRITICAL, p.strip(),
                        "SNMP using default community strings 'public'/'private'"))
                else:
                    findings.append(Finding("Network Service", MEDIUM, p.strip(),
                        "SNMP configuration found — verify community strings are not default"))
            except (IOError, OSError):
                pass

    # Identify any listening port configs
    stdout, _, _ = run_cmd(
        f'grep -rn --include="*.conf" --include="*.xml" --include="*.ini" '
        f'-iE "port\\s*=\\s*(21|23|69|161|512|513|514)\\b" "{root}" 2>/dev/null | head -20'
    )
    PORT_NAMES = {"21": "FTP", "23": "Telnet", "69": "TFTP", "161": "SNMP",
                  "512": "rexec", "513": "rlogin", "514": "rsh/syslog"}
    for line in stdout.strip().splitlines():
        m = re.search(r'port\s*=\s*(\d+)', line, re.IGNORECASE)
        if m:
            port = m.group(1)
            svc = PORT_NAMES.get(port, f"port {port}")
            fpath = line.split(":")[0]
            sev = CRITICAL if port in ("23", "512", "513", "514") else HIGH
            findings.append(Finding("Network Service", sev, fpath,
                f"Insecure service port {port} ({svc}) configured"))

    _ok(f"Network service scan: {len(findings)} findings")
    return findings


def axis_specific_checks(root: Path):
    _info("Running Axis-specific checks...")
    findings = []

    # Boa / thttpd server binary presence
    for server in ["boa", "thttpd"]:
        stdout, _, _ = run_cmd(f'find "{root}" -name "{server}" 2>/dev/null')
        if stdout.strip():
            p = stdout.strip().splitlines()[0]
            findings.append(Finding("Web Server", HIGH, p,
                f"{server} web server binary — review path traversal (CVE-2017-9833) and DoS CVEs"))

    # ONVIF WSDL / handlers
    stdout, _, _ = run_cmd(
        f'grep -rln --include="*.c" --include="*.h" --include="*.xml" '
        f'--include="*.wsdl" -i "onvif" "{root}" 2>/dev/null | head -10'
    )
    if stdout.strip():
        file_list = stdout.strip().replace("\n", ", ")
        findings.append(Finding("ONVIF Service", MEDIUM, root,
            f"ONVIF handlers found in: {file_list[:120]} — audit auth on each operation"))

    # VAPIX param → direct shell
    stdout, _, _ = run_cmd(
        f'grep -rn --include="*.cgi" --include="*.sh" --include="*.c" '
        f'-E "(system|popen|exec).*cgi_param|cgi_param.*(system|popen|exec)" "{root}" 2>/dev/null | head -20'
    )
    for line in stdout.strip().splitlines()[:5]:
        fpath = line.split(":")[0]
        findings.append(Finding("VAPIX Shell Injection", CRITICAL, fpath,
            "CGI parameter passed directly to shell command — high confidence RCE path"))

    # Attack surface: count axis/vapix references
    stdout, _, _ = run_cmd(
        f'grep -rn --include="*.c" --include="*.h" --include="*.cgi" '
        f'--include="*.sh" --include="*.xml" -i "axis\\|vapix" '
        f'"{root}" 2>/dev/null | grep -v "Binary file" | wc -l'
    )
    count = stdout.strip() or "0"
    findings.append(Finding("Axis Attack Surface", LOW, root,
        f"{count} references to 'axis'/'vapix' in source — map endpoints before testing"))

    # Check for factory-default reset handler
    stdout, _, _ = run_cmd(
        f'grep -rn --include="*.c" --include="*.cgi" '
        f'-i "factorydefault\\|factory_default\\|factory_reset" "{root}" 2>/dev/null | head -10'
    )
    if stdout.strip():
        findings.append(Finding("VAPIX Endpoint", HIGH, root,
            "Factory-default/reset handler present — verify auth requirement"))

    _ok(f"Axis-specific checks: {len(findings)} findings")
    return findings


# ── Cross-reference: unauthenticated endpoints × RCE-risky scripts ────────────

def cross_reference_unauth_rce(findings: list) -> list:
    """
    Surface confirmed attack paths: CRITICAL (unauthenticated) VAPIX endpoints
    that map to CGI/shell scripts with RCE-class risk flags.

    Matching is attempted at three confidence levels:
      HIGH   — filesystem path of script ends with the endpoint URL tail
               e.g. .../axis-cgi/foo.cgi matches /axis-cgi/foo.cgi
      MEDIUM — script filename matches the last path segment of the endpoint
               e.g. foo.cgi matches /axis-cgi/subdir/foo.cgi
      LOW    — the endpoint URL string appears literally inside the script source

    Returns new Finding("Unauthenticated RCE Path", CRITICAL, ...) entries.
    These are intentionally additive — the individual VAPIX and script findings
    are left unchanged with their own severities.
    """
    _info("Cross-referencing unauthenticated endpoints with RCE-risky scripts...")

    unauth_eps = [
        f for f in findings
        if f.category == "VAPIX Endpoint" and f.severity == CRITICAL
    ]
    risky_scripts = [
        f for f in findings
        if f.category in ("CGI Script", "Shell Script")
        and f.severity in (CRITICAL, HIGH)
        and any(flag in (f.detail or "")
                for flag in ["backtick+CGI", "shell-exec", "user-input→shell"])
    ]

    results = []
    seen = set()   # (ep_url, script_path) — avoid duplicates

    for ep in unauth_eps:
        ep_url  = ep.path                            # /axis-cgi/foo/bar.cgi
        ep_tail = ep_url.lstrip("/")                 # axis-cgi/foo/bar.cgi
        ep_name = Path(ep_url).name                  # bar.cgi

        for script in risky_scripts:
            sp = script.path
            key = (ep_url, sp)
            if key in seen:
                continue

            confidence = None
            if sp.endswith(ep_tail):
                confidence = "HIGH"
            elif Path(sp).name == ep_name:
                confidence = "MEDIUM"
            else:
                try:
                    if ep_url in Path(sp).read_text(errors="replace"):
                        confidence = "LOW"
                except (IOError, OSError):
                    pass

            if not confidence:
                continue
            seen.add(key)

            # Extract risk flags from script detail string
            flags_raw = re.search(r'\[([^\]]+)\]', script.detail or "")
            risk_flags = flags_raw.group(1) if flags_raw else script.detail[:60]

            auth_short = (ep.detail or "")[:80]

            # Combine evidence: auth config snippet + script risk detail
            ev_parts = []
            if ep.evidence:
                ev_parts.append(f"[Auth evidence — {ep.line or ep_url}]\n{ep.evidence}")
            ev_parts.append(f"[Script risk flags]\n{risk_flags}\nScript: {sp}")
            combined_evidence = "\n\n".join(ev_parts)

            results.append(Finding(
                "Unauthenticated RCE Path", CRITICAL, sp,
                f"[{confidence}] {ep_url} is unauthenticated ({auth_short}) "
                f"and script has RCE-class flags: {risk_flags}",
                line=ep_url,
                evidence=combined_evidence,
            ))

    _ok(f"Cross-reference: {len(results)} critical attack path(s) found")
    return results


# ── Diff mode ─────────────────────────────────────────────────────────────────

def step_diff(dir_a: Path, dir_b: Path):
    _sep()
    _info("DIFF MODE — comparing two firmware versions")
    _sep()

    stdout, _, _ = run_cmd(f'diff -rq "{dir_a}" "{dir_b}" 2>/dev/null | head -300')
    lines = stdout.strip().splitlines()

    added   = [l for l in lines if l.startswith("Only in") and str(dir_b) in l]
    removed = [l for l in lines if l.startswith("Only in") and str(dir_a) in l]
    changed = [l for l in lines if l.startswith("Files")]

    _info(f"Added:   {len(added)} files")
    _info(f"Removed: {len(removed)} files")
    _info(f"Changed: {len(changed)} files")

    return {"added": added[:50], "removed": removed[:50], "changed": changed[:50]}


# ── Step 3: Report Generation ─────────────────────────────────────────────────

def count_by_severity(findings):
    counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def generate_report(findings, target, output_dir, fmt, diff_data=None, compare=None):
    _sep()
    _info("STEP 3 — REPORT GENERATION")
    _sep()

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        report_path = output_dir / f"firmsec_report_{ts}.json"
        content = build_json_report(findings, target, diff_data, compare)
    else:
        report_path = output_dir / f"firmsec_report_{ts}.md"
        content = build_markdown_report(findings, target, diff_data, compare)

    report_path.write_text(content, encoding="utf-8")
    _ok(f"Report written: {report_path}")
    return report_path


def build_markdown_report(findings, target, diff_data, compare):
    counts = count_by_severity(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def findings_of(*categories):
        return sorted(
            [f for f in findings if f.category in categories],
            key=lambda f: f.sort_key()
        )

    def badge(sev):
        return {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵"}.get(sev, "⚪")

    L = []
    L += [
        "# FirmSec Analysis Report",
        "",
        f"> Generated: {now}  ",
        f"> Target: `{target}`  ",
        f"> Tool: FirmSec v1.3 (Axis OS Firmware Security Analyzer)",
        "",
    ]

    # ── Executive Summary ──────────────────────────────────────────────────────
    L += [
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
        f"**Firmware target:** `{Path(str(target)).name}`  ",
        f"**Target device:** Axis OS (camera / IoT device)  ",
        f"**Analysis date:** {now}  ",
        "",
    ]
    if counts[CRITICAL] > 0:
        L.append(f"> ⚠️ **{counts[CRITICAL]} CRITICAL findings require immediate attention.**")
        L.append("")

    # ── Critical Attack Paths (cross-reference) ────────────────────────────────
    rce_paths = findings_of("Unauthenticated RCE Path")
    if rce_paths:
        L += [
            "## 🔴 Critical Attack Paths Found",
            "",
            "> **These endpoints are reachable without authentication AND the backing script",
            "> contains code execution patterns. Treat as highest-priority for immediate",
            "> remediation or network-level firewall isolation.**",
            "",
            "| Confidence | Unauthenticated Endpoint | Script | RCE Risk Flags |",
            "|------------|--------------------------|--------|----------------|",
        ]
        for f in rce_paths:
            ep_url     = f.line or "?"
            script_name = Path(f.path).name
            conf_m     = re.search(r'^\[(\w+)\]', f.detail)
            confidence = conf_m.group(1) if conf_m else "?"
            flags_m    = re.search(r'RCE-class flags: (.+)$', f.detail)
            risk_flags = flags_m.group(1) if flags_m else "?"
            L.append(
                f"| **{confidence}** | `{ep_url}` | `{script_name}` | {risk_flags} |"
            )
        L += [""]
        # Evidence sub-section (capped at 5)
        L += ["### Evidence", ""]
        for f in rce_paths[:5]:
            ep_url = f.line or "?"
            L += [
                f"#### `{ep_url}` → `{Path(f.path).name}`",
                "```",
                (f.evidence or "")[:700],
                "```",
                "",
            ]
    L.append("")

    # ── Dangerous Functions ────────────────────────────────────────────────────
    df = findings_of("Dangerous Function", "Dangerous Function (binary)")
    L += ["## Dangerous Functions", ""]
    if df:
        L += ["| Severity | File | Line | Detail |",
              "|----------|------|------|--------|"]
        for f in df:
            fname = Path(f.path).name
            L.append(f"| {badge(f.severity)} {f.severity} | `{fname}` | {f.line or '—'} | {f.detail} |")
    else:
        L.append("_No dangerous function calls found._")
    L.append("")

    # ── Hardcoded Credentials ──────────────────────────────────────────────────
    hc = findings_of("Hardcoded Credential")
    L += ["## Hardcoded Credentials", ""]
    if hc:
        L += ["| Severity | File | Match |",
              "|----------|------|-------|"]
        for f in hc:
            L.append(f"| {badge(f.severity)} {f.severity} | `{Path(f.path).name}` | `{f.detail}` |")
    else:
        L.append("_No hardcoded credentials detected._")
    L.append("")

    # ── System Accounts ────────────────────────────────────────────────────────
    sa = findings_of("System Account")
    L += ["## System Accounts (passwd / shadow)", ""]
    if sa:
        L += ["| Severity | File | Line | Detail |",
              "|----------|------|------|--------|"]
        for f in sa:
            L.append(f"| {badge(f.severity)} {f.severity} | `{Path(f.path).name}` | {f.line or '—'} | {f.detail} |")
    else:
        L.append("_No passwd/shadow issues found._")
    L.append("")

    # ── VAPIX Endpoints ────────────────────────────────────────────────────────
    ve = findings_of("VAPIX Endpoint", "VAPIX Shell Risk", "VAPIX Shell Injection")
    L += ["## VAPIX Endpoints", ""]
    if ve:
        L += ["| Severity | Endpoint / Location | Auth Status | Source Ref |",
              "|----------|---------------------|-------------|------------|"]
        for f in ve:
            ref = f.line or "—"
            L.append(f"| {badge(f.severity)} {f.severity} | `{f.path}` | {f.detail} | `{ref}` |")
        # Evidence snippets for unauthenticated / unknown endpoints
        evidence_items = [
            f for f in ve
            if getattr(f, "evidence", None) and f.severity in (CRITICAL, MEDIUM)
        ]
        if evidence_items:
            L += ["", "### Evidence", ""]
            for f in evidence_items[:10]:
                L += [
                    f"**`{f.path}`** — {f.detail}",
                    "```",
                    (f.evidence or "")[:500],
                    "```",
                    "",
                ]
    else:
        L.append("_No VAPIX endpoints detected._")
    L.append("")

    # ── CGI and Shell Scripts ──────────────────────────────────────────────────
    sc = findings_of("CGI Script", "Shell Script", "Script")
    L += ["## CGI and Shell Scripts", ""]
    if sc:
        L += ["| Severity | File | Type | Detail |",
              "|----------|------|------|--------|"]
        for f in sc:
            L.append(f"| {badge(f.severity)} {f.severity} | `{Path(f.path).name}` | {f.category} | {f.detail} |")
    else:
        L.append("_No scripts found._")
    L.append("")

    # ── Init Scripts ───────────────────────────────────────────────────────────
    init = findings_of("Init Script")
    L += ["## Init / RC Scripts", ""]
    if init:
        L += ["| Severity | File | Detail |",
              "|----------|------|--------|"]
        for f in init:
            L.append(f"| {badge(f.severity)} {f.severity} | `{Path(f.path).name}` | {f.detail} |")
    else:
        L.append("_No init script issues found._")
    L.append("")

    # ── Certificates and Keys ─────────────────────────────────────────────────
    ck = findings_of("Certificate/Key")
    L += ["## Certificates and Keys", ""]
    if ck:
        L += ["| Severity | File | Detail |",
              "|----------|------|--------|"]
        for f in ck:
            L.append(f"| {badge(f.severity)} {f.severity} | `{Path(f.path).name}` | {f.detail} |")
    else:
        L.append("_No certificates or keys found._")
    L.append("")

    # ── Vulnerable Libraries ──────────────────────────────────────────────────
    vl = findings_of("Vulnerable Library")
    L += ["## Vulnerable Libraries", ""]
    if vl:
        L += ["| Severity | Detail |",
              "|----------|--------|"]
        for f in vl:
            L.append(f"| {badge(f.severity)} {f.severity} | {f.detail} |")
    else:
        L.append("_No vulnerable library versions detected._")
    L.append("")

    # ── Web Server Configuration ───────────────────────────────────────────────
    wc = findings_of("Web Server Config", "Web Server")
    L += ["## Web Server Configuration", ""]
    if wc:
        L += ["| Severity | File | Detail |",
              "|----------|------|--------|"]
        for f in wc:
            L.append(f"| {badge(f.severity)} {f.severity} | `{Path(f.path).name}` | {f.detail} |")
    else:
        L.append("_No web server config issues found._")
    L.append("")

    # ── Network Services ──────────────────────────────────────────────────────
    ns = findings_of("Network Service")
    L += ["## Network Services", ""]
    if ns:
        L += ["| Severity | Path / Config | Detail |",
              "|----------|---------------|--------|"]
        for f in ns:
            L.append(f"| {badge(f.severity)} {f.severity} | `{Path(f.path).name}` | {f.detail} |")
    else:
        L.append("_No insecure network service findings._")
    L.append("")

    # ── SUID Binaries ─────────────────────────────────────────────────────────
    suid = findings_of("SUID Binary")
    L += ["## SUID Binaries", ""]
    if suid:
        L += ["| Severity | Path | Detail |",
              "|----------|------|--------|"]
        for f in suid:
            L.append(f"| {badge(f.severity)} {f.severity} | `{f.path}` | {f.detail} |")
    else:
        L.append("_No SUID binaries found._")
    L.append("")

    # ── Axis-Specific Findings ─────────────────────────────────────────────────
    ax = findings_of("ONVIF Service", "Axis Attack Surface", "ELF Binaries")
    L += ["## Axis-Specific Findings", ""]
    if ax:
        L += ["| Severity | Category | Detail |",
              "|----------|----------|--------|"]
        for f in ax:
            L.append(f"| {badge(f.severity)} {f.severity} | {f.category} | {f.detail} |")
    else:
        L.append("_No Axis-specific findings._")
    L.append("")

    # ── Firmware Diff ─────────────────────────────────────────────────────────
    if diff_data:
        L += ["## Firmware Diff", "",
              f"Comparing `{target}` vs `{compare}`", "",
              f"- **Added:** {len(diff_data['added'])} files",
              f"- **Removed:** {len(diff_data['removed'])} files",
              f"- **Changed:** {len(diff_data['changed'])} files", ""]
        for section, key in [("Added", "added"), ("Removed", "removed"), ("Changed", "changed")]:
            if diff_data[key]:
                L += [f"### {section} Files", "```"] + diff_data[key][:25] + ["```", ""]

    # ── Recommended Next Steps ────────────────────────────────────────────────
    L += ["## Recommended Next Steps", ""]
    steps = []
    n = 1
    if counts[CRITICAL] > 0:
        steps.append(f"{n}. 🔴 **[CRITICAL]** Remove or rotate all hardcoded credentials, private keys, and default passwords."); n+=1
        steps.append(f"{n}. 🔴 **[CRITICAL]** Enforce authentication on all VAPIX endpoints — use digest auth or mTLS."); n+=1
        steps.append(f"{n}. 🔴 **[CRITICAL]** Disable or firewall telnetd; replace with SSH (key-only)."); n+=1
    if counts[HIGH] > 0:
        steps.append(f"{n}. 🟠 **[HIGH]** Audit dangerous functions (`system()`, `popen()`, `strcpy()`) for user-controlled input."); n+=1
        steps.append(f"{n}. 🟠 **[HIGH]** Patch/replace vulnerable libraries: OpenSSL, libupnp, Boa, thttpd."); n+=1
        steps.append(f"{n}. 🟠 **[HIGH]** Enable HTTPS-only for the web server; disable HTTP on port 80."); n+=1
    if counts[MEDIUM] > 0:
        steps.append(f"{n}. 🟡 **[MEDIUM]** Sanitize all CGI script parameters before use in shell commands."); n+=1
        steps.append(f"{n}. 🟡 **[MEDIUM]** Audit ONVIF service operations for authentication requirements."); n+=1
    steps += [
        f"{n}. 🔵 Enable Axis firmware signing and Secure Boot if supported by device generation.",
        f"{n+1}. 🔵 Cross-reference axis-cgi endpoints against the VAPIX API library for required auth levels.",
        f"{n+2}. 🔵 Run dynamic fuzzing on high-risk CGI endpoints in an isolated test lab.",
        f"{n+3}. 🔵 Subscribe to Axis security advisories: https://www.axis.com/support/cybersecurity/security-advisories",
    ]
    L += steps
    L += ["", "---", f"_Report generated by FirmSec v1.3 — {now}_"]

    return "\n".join(L)


def build_json_report(findings, target, diff_data, compare):
    data = {
        "tool": "FirmSec v1.3",
        "generated": datetime.now().isoformat(),
        "target": str(target),
        "compare": str(compare) if compare else None,
        "summary": count_by_severity(findings),
        "findings": [
            {"category": f.category, "severity": f.severity,
             "path": f.path, "detail": f.detail, "line": f.line,
             "evidence": getattr(f, "evidence", None)}
            for f in sorted(findings, key=lambda x: x.sort_key())
        ],
        "diff": diff_data,
    }
    return json.dumps(data, indent=2)


# ── Terminal summary ──────────────────────────────────────────────────────────

def print_terminal_summary(findings):
    counts = count_by_severity(findings)
    _sep()
    _info("FINDINGS SUMMARY")
    _sep()

    # Category breakdown
    categories: dict[str, int] = {}
    for f in findings:
        categories[f.category] = categories.get(f.category, 0) + 1

    if HAS_RICH:
        sev_table = Table(title="Severity Breakdown", header_style="bold magenta", show_header=True)
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        sev_table.add_column("Sample Finding")
        colors = {CRITICAL: "red", HIGH: "magenta", MEDIUM: "yellow", LOW: "cyan"}
        for sev in [CRITICAL, HIGH, MEDIUM, LOW]:
            sev_f = [f for f in findings if f.severity == sev]
            top = sev_f[0].detail[:65] if sev_f else "—"
            sev_table.add_row(f"[{colors[sev]}]{sev}[/{colors[sev]}]", str(counts[sev]), top)
        console.print(sev_table)

        cat_table = Table(title="Category Breakdown", header_style="bold blue", show_header=True)
        cat_table.add_column("Category")
        cat_table.add_column("Count", justify="right")
        for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
            cat_table.add_row(cat, str(cnt))
        console.print(cat_table)
    else:
        for sev in [CRITICAL, HIGH, MEDIUM, LOW]:
            print(f"  {severity_color(sev):10s}: {counts[sev]}")
        print()
        for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
            print(f"  {cat:<35s}: {cnt}")


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="firmsec",
        description="FirmSec v1.3 — Axis OS Firmware Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  firmsec.py --target axis_firmware.bin
  firmsec.py --target axis_firmware.bin --output ./reports --format json
  firmsec.py --target axis_fw_v9.bin --compare axis_fw_v10.bin
  firmsec.py --target ./extracted/ --skip-extract
  firmsec.py --target axis_firmware.bin --kali
        """
    )
    parser.add_argument("--target",       required=True,       help="Firmware binary or pre-extracted directory")
    parser.add_argument("--compare",      default=None,        help="Second firmware for diff comparison")
    default_reports = str(Path(__file__).parent / "reports")
    parser.add_argument("--output",       default=default_reports,
                        help=f"Output directory (default: {default_reports})")
    parser.add_argument("--format",       default="markdown",  choices=["markdown", "json"],
                        help="Report format (default: markdown)")
    parser.add_argument("--skip-extract", action="store_true", help="Skip binwalk; target is a directory")
    parser.add_argument("--kali",         action="store_true", help="Kali Linux tool path hints")
    return parser.parse_args()


def main():
    args = parse_args()
    target = Path(args.target).resolve()
    output_dir = Path(args.output).resolve()

    if HAS_RICH:
        console.print(Panel.fit(
            "[bold cyan]FirmSec v1.3[/bold cyan] — Axis OS Firmware Security Analyzer\n"
            "[dim]Optimized for Axis OS | Mac + Kali Linux[/dim]",
            border_style="cyan"
        ))
    else:
        print("=" * 60)
        print("  FirmSec v1.3 — Axis OS Firmware Security Analyzer")
        print("=" * 60)

    if not target.exists():
        _err(f"Target not found: {target}")
        sys.exit(1)

    diff_data = None
    compare_path = None

    if target.is_file() and not args.skip_extract:
        extract_dir, fs_type = step_extract(target, args.kali)
    elif target.is_dir() or args.skip_extract:
        extract_dir = target
        fs_type = detect_filesystem(target)
        _info(f"Pre-extracted directory: {extract_dir} (fs: {fs_type})")
        print_tree_summary(extract_dir)
    else:
        _err("Target must be a firmware file or extracted directory.")
        sys.exit(1)

    if args.compare:
        compare_path = Path(args.compare).resolve()
        compare_extract = compare_path if compare_path.is_dir() else step_extract(compare_path, args.kali)[0]
        diff_data = step_diff(extract_dir, compare_extract)

    findings = step_analyze(extract_dir, args.kali)
    print_terminal_summary(findings)

    report_path = generate_report(findings, target, output_dir, args.format, diff_data, compare_path)

    _sep()
    _ok(f"Done! Report → {report_path}")
    if HAS_RICH:
        console.print(Panel(f"[green]Report saved:[/green] [bold]{report_path}[/bold]", border_style="green"))


if __name__ == "__main__":
    main()
