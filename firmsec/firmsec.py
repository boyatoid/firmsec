#!/usr/bin/env python3
"""
FirmSec - Firmware Security Analysis Tool for Axis OS Devices

Entry-point shim. The implementation lives in flat sibling modules in this same
directory (constants, console, utils, finding, filters, extract, analyzers_*,
report, runner, cli). Running this file directly keeps working because the
script's own directory is on sys.path, so those modules import cleanly.
"""

from cli import main

if __name__ == "__main__":
    main()
