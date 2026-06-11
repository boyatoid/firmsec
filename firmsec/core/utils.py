"""Shared low-level utilities: shell execution, tool discovery, ELF/version parsing."""

import re
import struct
import subprocess
from pathlib import Path

from .constants import ELF_MACHINES
from .console import _warn


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


def _semver_lt(version: str, fixed_in: str) -> bool:
    """
    Return True if version < fixed_in using numeric tuple comparison.
    Strips trailing letters (e.g. "1.0.1g" → (1,0,1)) before comparing.
    Returns False if either string cannot be parsed, erring on the side of
    not raising a false-positive.
    """
    def _parse(v: str) -> tuple:
        v = re.sub(r'[a-zA-Z]+$', '', v.strip())
        parts = re.split(r'[.\-]', v)
        nums = []
        for p in parts:
            if p.isdigit():
                nums.append(int(p))
            else:
                break
        return tuple(nums)
    try:
        v = _parse(version)
        f = _parse(fixed_in)
        return bool(v and f and v < f)
    except Exception:
        return False
