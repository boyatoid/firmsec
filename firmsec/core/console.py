"""Terminal output helpers and optional colorama/rich integration.

The colorama / rich import fallbacks live here only; every other module imports
the print helpers (and the `console` / `HAS_RICH` handles) from this module.
"""

import sys

from .constants import CRITICAL, HIGH, MEDIUM, LOW

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None
    # Define the names so importers can reference them unconditionally; they are
    # only ever used inside `if HAS_RICH:` guards.
    Console = Table = Panel = Tree = None


def _c(text, color):
    if HAS_COLORAMA:
        return f"{color}{text}{Style.RESET_ALL}"
    return text

def _ok(msg):   print(_c(f"[+] {msg}", Fore.GREEN if HAS_COLORAMA else ""))
def _info(msg): print(_c(f"[*] {msg}", Fore.CYAN if HAS_COLORAMA else ""))
def _warn(msg): print(_c(f"[!] {msg}", Fore.YELLOW if HAS_COLORAMA else ""))
def _err(msg):  print(_c(f"[-] {msg}", Fore.RED if HAS_COLORAMA else ""), file=sys.stderr)
def _sep():     print(_c("─" * 60, Fore.BLUE if HAS_COLORAMA else ""))

def severity_color(sev):
    if not HAS_COLORAMA:
        return sev
    colors = {CRITICAL: Fore.RED, HIGH: Fore.MAGENTA, MEDIUM: Fore.YELLOW, LOW: Fore.CYAN}
    return _c(sev, colors.get(sev, ""))
