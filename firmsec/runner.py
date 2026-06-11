"""Orchestration: run every analyzer (step 2) and the firmware diff (diff mode)."""

from pathlib import Path

from console import _ok, _info, _sep
from utils import run_cmd
from analyzers_binary import (
    find_elf_binaries, grep_dangerous_functions, detect_vulnerable_libraries,
)
from analyzers_creds import (
    find_credentials, find_passwd_shadow, find_keys_and_certs,
)
from analyzers_scripts import find_scripts, find_init_scripts
from analyzers_web import (
    find_vapix_endpoints, analyze_webserver_configs, find_network_services,
    axis_specific_checks, cross_reference_unauth_rce,
)


def step_analyze(extract_dir: Path, kali: bool, extracted: bool = False):
    _sep()
    _info("STEP 2 — STATIC ANALYSIS")
    _sep()

    findings = []
    findings += find_elf_binaries(extract_dir, kali, extracted=extracted)
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
