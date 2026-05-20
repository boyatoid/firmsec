# FirmSec — Axis OS Firmware Security Analyzer

Static firmware security analysis tool optimized for **Axis OS** (cameras, encoders, IoT devices).
Extracts, scans, and reports on security findings including hardcoded credentials, dangerous
functions, unauthenticated VAPIX endpoints, vulnerable libraries, and more.

---

## Features

- Automated extraction via `binwalk`
- Architecture detection (MIPS / ARM / x86)
- Dangerous C function grepping (`system`, `popen`, `strcpy`, `gets`, …)
- Hardcoded credential detection in config/XML/text files
- VAPIX / axis-cgi endpoint mapping with auth status
- Private key and certificate discovery (with expiry check)
- Vulnerable library version detection (OpenSSL, libupnp, Boa, thttpd, BusyBox, curl)
- Axis-specific checks: Boa/thttpd web server, ONVIF handlers, VAPIX param → shell
- Firmware diff mode (`--compare`) to highlight changes between versions
- Colored terminal output + rich tables
- Markdown and JSON report generation

---

## Requirements

- Python 3.8+
- `binwalk` (extraction)
- `file`, `strings`, `readelf` / `greadelf` (binary analysis)
- `openssl` (certificate expiry, optional)

---

## Setup

### macOS (Homebrew)

```bash
# System tools
brew install binwalk
brew install binutils        # provides greadelf, strings
brew install openssl         # for cert expiry checks

# Python deps
pip3 install -r requirements.txt
```

> **Note:** If `binwalk` extraction requires `sasquatch` for non-standard SquashFS:
> ```bash
> brew install sasquatch
> ```

### Kali Linux (apt)

```bash
# System tools
sudo apt update
sudo apt install binwalk binutils openssl

# Python deps
pip3 install -r requirements.txt
```

> **Note:** When running on Kali, pass the `--kali` flag for adjusted tool paths.

---

## Usage

### Basic scan

```bash
python3 firmsec.py --target axis_firmware.bin
```

### Custom output directory

```bash
python3 firmsec.py --target axis_firmware.bin --output /tmp/reports
```

### JSON report

```bash
python3 firmsec.py --target axis_firmware.bin --format json
```

### Skip extraction (already extracted)

```bash
python3 firmsec.py --target ./extracted_firmware/ --skip-extract
```

### Kali Linux mode

```bash
python3 firmsec.py --target axis_firmware.bin --kali
```

### Diff two firmware versions

```bash
python3 firmsec.py --target axis_fw_v9.bin --compare axis_fw_v10.bin
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | _(required)_ | Path to firmware binary or pre-extracted directory |
| `--compare` | — | Second firmware for diff comparison |
| `--output` | `./reports/` | Output directory for reports |
| `--format` | `markdown` | Report format: `markdown`, `json` |
| `--skip-extract` | false | Skip binwalk extraction (use pre-extracted dir) |
| `--kali` | false | Adjust tool paths for Kali Linux |

---

## Example Workflow — Axis Camera Firmware

### 1. Download firmware

Visit [https://www.axis.com/support/firmware](https://www.axis.com/support/firmware) and download
the firmware for your Axis device (e.g., `AXIS_P3245_9.80.3.1.bin`).

### 2. Set up environment (Mac)

```bash
brew install binwalk binutils openssl
pip3 install -r requirements.txt
```

### 3. Run analysis

```bash
python3 firmsec.py --target AXIS_P3245_9.80.3.1.bin --output ./reports
```

### 4. Review report

```
cat reports/firmsec_report_<timestamp>.md
```

### 5. Compare with a newer version

```bash
# Download AXIS_P3245_10.0.0.1.bin
python3 firmsec.py \
  --target AXIS_P3245_9.80.3.1.bin \
  --compare AXIS_P3245_10.0.0.1.bin \
  --output ./reports/diff
```

---

## Kali in Parallels — Workflow

When testing on Kali Linux inside Parallels on a Mac:

1. Share the Mac `Downloads` folder into Parallels (Parallels → Devices → Shared Folders)
2. Copy firmware into the Kali home directory:
   ```bash
   cp /media/psf/Downloads/AXIS_*.bin ~/firmware/
   ```
3. Run with `--kali`:
   ```bash
   python3 firmsec.py --target ~/firmware/AXIS_P3245_9.80.3.1.bin --kali
   ```
4. Open the report from Mac by mounting the Kali home share, or:
   ```bash
   # On Kali, serve the report
   python3 -m http.server 8080 --directory ./reports
   # On Mac, visit http://localhost:8080 in a browser (via Parallels NAT)
   ```

---

## Report Structure

Generated at `./reports/firmsec_report_<timestamp>.md`:

| Section | Content |
|---------|---------|
| Executive Summary | Severity counts, firmware info, target device |
| Dangerous Functions | File, line, severity, one-line explanation |
| Hardcoded Credentials | File, matched string (value redacted), severity |
| VAPIX Endpoints | Path, authenticated yes/no, risk level |
| CGI Scripts | List with risk flags |
| Certificates and Keys | File, type, expiry if readable |
| Vulnerable Libraries | Name, version found, known CVEs |
| Axis-Specific Findings | Web server, ONVIF, attack surface |
| Firmware Diff | Added/removed/changed files (if --compare used) |
| Recommended Next Steps | Prioritized action list |

---

## Severity Ratings

| Level | Meaning |
|-------|---------|
| 🔴 Critical | Hardcoded creds, private keys, unauthenticated RCE-class endpoints |
| 🟠 High | Dangerous functions with likely user-controlled input, outdated libs |
| 🟡 Medium | Dangerous functions with unclear input source, CGI shell risks |
| 🔵 Low | Informational: binary count, attack surface mapping |

---

## Axis Security Resources

- Firmware downloads: https://www.axis.com/support/firmware
- Security advisories: https://www.axis.com/support/cybersecurity/security-advisories
- VAPIX API reference: https://www.axis.com/vapix-library/
- Axis Hardening Guide: https://www.axis.com/support/cybersecurity/hardening-guide

---

## Legal Notice

This tool is intended for **authorized security testing** of devices you own or have
explicit written permission to test. Unauthorized use against third-party systems may
violate the Computer Fraud and Abuse Act (CFAA), GDPR, and other laws.
