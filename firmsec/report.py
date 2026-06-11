"""Step 3 — report generation (markdown + JSON) and terminal summary."""

from datetime import datetime
import json
import re
from pathlib import Path

from constants import CRITICAL, HIGH, MEDIUM, LOW
from console import HAS_RICH, console, Table, severity_color, _ok, _info, _sep

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
    confirmed_f  = [f for f in findings if getattr(f, "confidence", "Medium") == "High"]
    verify_f     = [f for f in findings if getattr(f, "confidence", "Medium") == "Medium"]
    info_f       = [f for f in findings if getattr(f, "confidence", "Medium") == "Low"]
    conf_crit    = sum(1 for f in confirmed_f if f.severity == CRITICAL)
    conf_high    = sum(1 for f in confirmed_f if f.severity == HIGH)

    L += [
        "## Executive Summary",
        "",
        "### Severity Breakdown",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {counts[CRITICAL]} |",
        f"| 🟠 High     | {counts[HIGH]} |",
        f"| 🟡 Medium   | {counts[MEDIUM]} |",
        f"| 🔵 Low      | {counts[LOW]} |",
        f"| **Total**   | **{sum(counts.values())}** |",
        "",
        "### Confidence Tiers",
        "",
        "| Tier | Count | Description |",
        "|------|-------|-------------|",
        f"| ✅ Confirmed Findings   | {len(confirmed_f)} | High-confidence — statically verified |",
        f"| ⚠️ Requires Verification | {len(verify_f)} | Medium-confidence — needs live device check |",
        f"| ℹ️ Informational         | {len(info_f)} | Low-confidence — advisory / unclear version |",
        "",
        "> **Evidence Quality:** `High` = version or auth status verified from static analysis; "
        "`Medium` = pattern-matched or requires runtime confirmation; "
        "`Low` = library present but version ambiguous.",
        "",
        f"**Firmware target:** `{Path(str(target)).name}`  ",
        f"**Target device:** Axis OS (camera / IoT device)  ",
        f"**Analysis date:** {now}  ",
        "",
    ]
    if conf_crit > 0:
        L.append(f"> ⚠️ **{conf_crit} CONFIRMED CRITICAL findings require immediate attention.**")
        L.append("")
    elif conf_high > 0:
        L.append(f"> 🟠 **{conf_high} confirmed HIGH-severity findings detected.**")
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
        L += ["| Severity | Confidence | Endpoint / Location | Auth Status | Source Ref |",
              "|----------|------------|---------------------|-------------|------------|"]
        for f in ve:
            ref  = f.line or "—"
            conf = getattr(f, "confidence", "Medium")
            L.append(f"| {badge(f.severity)} {f.severity} | {conf} | `{f.path}` | {f.detail} | `{ref}` |")
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
        L += ["| Severity | Confidence | Detail |",
              "|----------|------------|--------|"]
        for f in vl:
            conf = getattr(f, "confidence", "Medium")
            L.append(f"| {badge(f.severity)} {f.severity} | {conf} | {f.detail} |")
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

