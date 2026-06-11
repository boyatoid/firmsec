"""Command-line entry point: argument parsing and the top-level workflow."""

import argparse
import sys
from pathlib import Path

from console import HAS_RICH, console, Panel, _ok, _info, _err, _sep
from extract import step_extract, detect_filesystem, print_tree_summary
from runner import step_analyze, step_diff
from report import generate_report, print_terminal_summary


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
    parser.add_argument("--skip-extract",            action="store_true",
                        help="Skip binwalk; target is a directory")
    parser.add_argument("--extracted",               action="store_true",
                        help="Target is extracted filesystem with preserved permissions"
                             " (enables accurate SUID detection via stat())")
    parser.add_argument("--skip-extraction-warning", action="store_true",
                        help="Suppress the extraction guidance printed for raw firmware binaries")
    parser.add_argument("--kali",                    action="store_true",
                        help="Kali Linux tool path hints")
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
        if not args.skip_extraction_warning:
            print()
            _info("Raw firmware binary detected. For full analysis (including SUID detection),")
            _info("extract the SquashFS filesystem with preserved permissions first:")
            print("  sudo apt install binwalk squashfs-tools")
            print("  binwalk -e " + str(target))
            print("  sudo unsquashfs -d ./squashfs-root <squashfs-image>")
            print("  firmsec.py --target ./squashfs-root --skip-extract --extracted")
            print("  (Use --skip-extraction-warning to suppress this message)")
            print()
        extract_dir, fs_type = step_extract(target, args.kali)
        # After extraction, report the deepest squashfs-root for user to target next time
        sq_roots = sorted(extract_dir.rglob("squashfs-root"), key=lambda p: len(p.parts))
        if sq_roots:
            _info(f"Extracted SquashFS root: {sq_roots[-1]}")
            _info("Re-run with --target <above path> --skip-extract --extracted for SUID detection")
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

    findings = step_analyze(extract_dir, args.kali, extracted=getattr(args, "extracted", False))
    print_terminal_summary(findings)

    report_path = generate_report(findings, target, output_dir, args.format, diff_data, compare_path)

    _sep()
    _ok(f"Done! Report → {report_path}")
    if HAS_RICH:
        console.print(Panel(f"[green]Report saved:[/green] [bold]{report_path}[/bold]", border_style="green"))
