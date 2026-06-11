#!/usr/bin/env python3
"""
FirmSec - Firmware Security Analysis Tool for Axis OS Devices

Entry-point shim. The implementation lives in the `core` package alongside this
file (core/constants, core/console, core/cli, …). Running this file directly
keeps working because the script's own directory is on sys.path, so `core` is
importable.
"""

from core.cli import main

if __name__ == "__main__":
    main()
