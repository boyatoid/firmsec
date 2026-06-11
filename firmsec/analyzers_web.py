"""Web / network-facing analyzers: VAPIX endpoint auth mapping, web-server config
auditing, insecure network services, Axis-specific checks, and the
unauthenticated-endpoint × RCE-script cross-reference."""

import re
from pathlib import Path

from constants import (
    CRITICAL, HIGH, MEDIUM, LOW,
    AXIS_PUBLIC_ENDPOINTS, VAPIX_UNAUTH_PATTERNS, AXIS_AUTH_MODULES,
)
from console import _info, _ok
from finding import Finding
from utils import run_cmd


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

            # Detect bare (non-Location-wrapped) global AuthType, or Axis custom auth
            # module references (mod_authn_axisbasic, mod_authz_urlaccess, etc.).
            bare_auth        = re.search(r'(?m)^AuthType\s+\S+', conf_content)
            has_axis_module  = any(mod in conf_content for mod in AXIS_AUTH_MODULES)
            if (bare_auth or has_axis_module) and not re.search(r'<Location', conf_content, re.IGNORECASE):
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
        # Skip endpoints that are intentionally public on Axis devices
        ep_base = ep.split("?")[0].rstrip("/")
        if ep_base in AXIS_PUBLIC_ENDPOINTS:
            continue

        evidence_snip, auth_label, hint = get_vapix_auth_evidence(
            ep, ref_fpath, ref_lineno, root
        )
        if hint == "auth":
            severity   = LOW
            confidence = "High"
        elif hint == "unauth":
            # Downgraded from CRITICAL — Axis custom auth modules may enforce auth at runtime
            severity   = MEDIUM
            confidence = "Medium"
            auth_label += (
                " — Requires live verification"
                " (Axis custom auth modules may enforce authentication at runtime)"
            )
        else:
            severity   = MEDIUM
            confidence = "Medium"

        ref_str = f"{Path(ref_fpath).name}:{ref_lineno}" if ref_fpath != "?" else "?"
        findings.append(Finding(
            "VAPIX Endpoint", severity, ep,
            auth_label,
            line=ref_str,
            evidence=evidence_snip or None,
            confidence=confidence,
            auth_hint=hint,
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
        f'-iE "port[[:space:]]*=[[:space:]]*(21|23|69|161|512|513|514)([^0-9]|$)" "{root}" 2>/dev/null | head -20'
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
    Surface confirmed attack paths: unauthenticated VAPIX endpoints (auth_hint
    == "unauth") that map to CGI/shell scripts with RCE-class risk flags.

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

    # Unauthenticated endpoints are flagged via auth_hint, not severity:
    # find_vapix_endpoints caps them at MEDIUM (Axis custom auth modules may
    # enforce auth at runtime), so filtering on severity == CRITICAL would
    # never match.
    unauth_eps = [
        f for f in findings
        if f.category == "VAPIX Endpoint" and f.auth_hint == "unauth"
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
