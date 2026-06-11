"""Static signature data and severity constants for FirmSec.

Pure data only — no logic, no imports beyond the standard library. Every other
module imports its tables from here.
"""

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

# NOTE: these patterns are passed to shell `grep -E`, so they must use POSIX
# bracket classes ([[:space:]], [^[:space:]]) rather than the GNU-only \s / \S
# escapes — BSD grep (the macOS default) treats \s as a literal "s".
CRED_PATTERNS = [
    (r'password[[:space:]]*[=:][[:space:]]*[^[:space:]]+',     CRITICAL, "Hardcoded password"),
    (r'passwd[[:space:]]*[=:][[:space:]]*[^[:space:]]+',       CRITICAL, "Hardcoded passwd field"),
    (r'secret[[:space:]]*[=:][[:space:]]*[^[:space:]]+',       CRITICAL, "Hardcoded secret"),
    (r'api[_-]?key[[:space:]]*[=:][[:space:]]*[^[:space:]]+',  CRITICAL, "Hardcoded API key"),
    (r'private[_-]?key[[:space:]]*[=:][[:space:]]*[^[:space:]]+', CRITICAL, "Hardcoded private key reference"),
    (r'admin[[:space:]]*[=:][[:space:]]*[^[:space:]]+',        HIGH,     "Hardcoded admin value"),
    (r'root[[:space:]]*[=:][[:space:]]*[^[:space:]]+',         HIGH,     "Hardcoded root value"),
    (r'token[[:space:]]*[=:][[:space:]]*[^[:space:]]+',        HIGH,     "Hardcoded token"),
    (r'auth[[:space:]]*[=:][[:space:]]*[^[:space:]]+',         MEDIUM,   "Hardcoded auth value"),
    (r'username[[:space:]]*[=:][[:space:]]*[^[:space:]]+',     MEDIUM,   "Hardcoded username"),
]

CRED_FILE_EXTS = [
    "*.conf", "*.xml", "*.txt", "*.cfg", "*.ini",
    "*.json", "*.yaml", "*.yml", "*.env",
    "*.js",   "*.html","*.php", "*.sh",  "*.py",
    "*.properties", "*.toml",
]

# ── Vulnerable library signatures ─────────────────────────────────────────────
#
# Each CVE entry is a dict with:
#   id       — CVE identifier
#   desc     — short description
#   fixed_in — first version where the vulnerability is fixed;
#              None means the library is unmaintained and always vulnerable.
#
# Version comparison is done with _semver_lt() so that e.g. curl 8.19.0 is
# correctly recognised as >= 8.4.0 and NOT flagged for CVE-2023-38545.

VULNERABLE_LIBS = {
    "openssl": {
        "pattern": r'(?:openssl|OpenSSL)[/ \-_v]*([\d]+\.[\d]+\.[\d]+[a-z]?)',
        "cves": [
            {"id": "CVE-2014-0160", "desc": "Heartbleed",              "fixed_in": "1.0.1g"},
            {"id": "CVE-2016-2107", "desc": "padding oracle",          "fixed_in": "1.0.2h"},
            {"id": "CVE-2022-0778", "desc": "infinite loop BN_mod_sqrt","fixed_in": "3.0.2"},
        ],
    },
    "libupnp": {
        "pattern": r'libupnp[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            {"id": "CVE-2012-5958", "desc": "stack overflow",  "fixed_in": "1.6.18"},
            {"id": "CVE-2016-8863", "desc": "heap overflow",   "fixed_in": "1.6.21"},
        ],
    },
    "boa": {
        "pattern": r'boa[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            {"id": "CVE-2017-9833", "desc": "directory traversal",   "fixed_in": None},
            {"id": "CVE-2021-33558","desc": "information disclosure", "fixed_in": None},
        ],
    },
    "thttpd": {
        "pattern": r'thttpd[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            {"id": "CVE-2017-11549","desc": "null pointer dereference","fixed_in": None},
            {"id": "CVE-2022-38723","desc": "buffer overflow",         "fixed_in": None},
        ],
    },
    "busybox": {
        "pattern": r'[Bb]usyBox[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            {"id": "CVE-2021-42374","desc": "lzma OOB read",             "fixed_in": "1.34.0"},
            {"id": "CVE-2022-28391","desc": "hush shell command injection","fixed_in": "1.35.1"},
        ],
    },
    "curl": {
        "pattern": r'curl[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            {"id": "CVE-2023-38545","desc": "SOCKS5 heap overflow","fixed_in": "8.4.0"},
        ],
    },
    "dropbear": {
        "pattern": r'[Dd]ropbear[/ \-_v]*([\d]+\.[\d]+)',
        "cves": [
            {"id": "CVE-2016-7406","desc": "format string via username","fixed_in": "2016.74"},
            {"id": "CVE-2017-9078","desc": "use-after-free",            "fixed_in": "2017.75"},
        ],
    },
    "zlib": {
        "pattern": r'zlib[/ \-_v]*([\d]+\.[\d]+\.[\d]+)',
        "cves": [
            {"id": "CVE-2022-37434","desc": "heap buffer overflow via inflateGetHeader","fixed_in": "1.2.13"},
        ],
    },
}

# ── VAPIX / axis-cgi patterns ─────────────────────────────────────────────────

# Endpoints that are intentionally public by Axis design — not a vulnerability.
# These are excluded from unauthenticated-endpoint findings entirely.
AXIS_PUBLIC_ENDPOINTS = {
    "/axis-cgi/jpg/image.cgi",
    "/axis-cgi/mjpg/video.cgi",
    "/axis-cgi/media.cgi",
    "/axis-cgi/audio/transmit.cgi",
}

# Historical patterns for endpoints that have been unauthenticated in older
# Axis OS versions.  Used only as a fallback when no Apache config is found.
# Severity is MEDIUM (requires live verification), not CRITICAL.
VAPIX_UNAUTH_PATTERNS = [
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

# Custom Axis Apache auth modules — when present, auth is enforced at the
# module level even if no AuthType/Require appears in a Location block.
AXIS_AUTH_MODULES = [
    "mod_authn_axisbasic",
    "mod_authz_urlaccess",
    "mod_authz_axisgroupfile",
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
