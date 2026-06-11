"""Binary-focused analyzers: ELF/SUID discovery, dangerous C functions,
and vulnerable-library version detection."""

import re
import stat
from collections import Counter
from pathlib import Path

from constants import (
    CRITICAL, HIGH, MEDIUM, LOW,
    DANGEROUS_FUNCTIONS, VULNERABLE_LIBS,
)
from console import _info, _ok, _warn
from finding import Finding
from utils import run_cmd, read_elf_arch, _semver_lt


def find_elf_binaries(root: Path, kali: bool, extracted: bool = False):
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
            f"{len(elf_files)} ELF binaries. Architectures: {arch_summary}",
            confidence="High",
        ))

    # SUID detection requires a properly extracted filesystem with preserved
    # permissions.  Without --extracted the results are unreliable because
    # binwalk without root drops setuid bits.
    if extracted:
        suid_found = []
        for p in root.rglob("*"):
            if not p.is_file() or p.is_symlink():
                continue
            try:
                st = p.stat()
                if st.st_mode & stat.S_ISUID:
                    suid_found.append(p)
            except (IOError, OSError):
                continue
        if suid_found:
            for p in suid_found:
                findings.append(Finding(
                    "SUID Binary", HIGH, p,
                    "SUID bit confirmed via stat() — potential privilege escalation; review if necessary",
                    confidence="High",
                ))
        else:
            _ok("SUID scan: no SUID binaries found (filesystem permissions preserved)")
    else:
        _warn("SUID detection skipped — run with --extracted for reliable SUID analysis")
        findings.append(Finding(
            "SUID Binary", LOW, root,
            "SUID detection skipped. For accurate results extract the firmware filesystem "
            "with preserved permissions, then re-run with --extracted:\n"
            "  sudo unsquashfs -d ./squashfs-root <squashfs-image>\n"
            "  python3 firmsec.py --target ./squashfs-root --extracted",
            confidence="Low",
        ))

    return findings


def grep_dangerous_functions(root: Path):
    _info("Grepping for dangerous C function calls in source files...")
    findings = []

    src_exts = '--include="*.c" --include="*.h" --include="*.cpp" --include="*.cc"'

    for func, (severity, explanation) in DANGEROUS_FUNCTIONS.items():
        # POSIX ERE (works on BSD + GNU grep): emulate the \b left word boundary
        # with (^|[^[:alnum:]_]) and \s with [[:space:]].
        pattern = rf'(^|[^[:alnum:]_]){func}[[:space:]]*\('
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
        pattern = info.get("pattern") or (
            rf'(?:{re.escape(lib_name)})[/ \-_v]*([\d]+\.[\d]+\.[\d]+[a-zA-Z]?)'
        )
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            # matches may contain stray version numbers that happen to sit near
            # the library name in the concatenated blob. Pick the most frequently
            # seen version rather than the first arbitrary hit.
            version = Counter(matches).most_common(1)[0][0]
            applicable_cves = []
            for cve in info["cves"]:
                fixed_in = cve.get("fixed_in")
                if fixed_in is None:
                    applicable_cves.append(cve)   # no fix known → always flag
                elif _semver_lt(version, fixed_in):
                    applicable_cves.append(cve)   # version < fixed_in → affected

            if applicable_cves:
                cve_strs = "; ".join(
                    cve["id"]
                    + (f" ({cve['desc']})" if cve.get("desc") else "")
                    + (f" [fixed in {cve['fixed_in']}]" if cve.get("fixed_in") else "")
                    for cve in applicable_cves
                )
                findings.append(Finding(
                    "Vulnerable Library", HIGH, root,
                    f"{lib_name} v{version} — CVEs: {cve_strs}",
                    confidence="High",
                ))
            # else: version detected and is >= fixed_in for all CVEs → not flagged
        elif re.search(rf'\b{re.escape(lib_name)}\b', combined, re.IGNORECASE):
            first_cve = info["cves"][0]["id"]
            findings.append(Finding(
                "Vulnerable Library", MEDIUM, root,
                f"{lib_name} detected (version unclear) — check: {first_cve}."
                " Manual verification recommended.",
                confidence="Low",
            ))

    _ok(f"Library scan: {len(findings)} findings")
    return findings
