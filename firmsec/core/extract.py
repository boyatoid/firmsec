"""Step 1 — firmware extraction (binwalk) and extracted-tree summarisation."""

import sys
from pathlib import Path

from .console import HAS_RICH, console, Tree, _ok, _info, _warn, _err, _sep
from .utils import check_tool, run_cmd


def step_extract(target: Path, kali: bool):
    _sep()
    _info("STEP 1 — EXTRACTION")
    _sep()

    binwalk = check_tool("binwalk", kali)
    if not binwalk:
        _err("binwalk is required for extraction. Aborting.")
        sys.exit(1)

    _info(f"Running binwalk -Me on: {target}")
    stdout, stderr, rc = run_cmd(f'binwalk -Me "{target}"', timeout=600)
    print(stdout[:4000] if stdout else "")

    parent = target.parent
    candidates = sorted(parent.glob(f"_{target.name}.extracted"),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        candidates = sorted(Path(".").glob(f"_{target.name}.extracted"),
                            key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        _warn("Scanning for any .extracted directory near the target...")
        candidates = sorted(parent.glob("*.extracted"),
                            key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        _err("Extraction directory not found. Check binwalk output above.")
        sys.exit(1)

    extract_dir = candidates[0]
    _ok(f"Extracted to: {extract_dir}")
    fs_type = detect_filesystem(extract_dir)
    _info(f"Detected filesystem type: {fs_type}")
    print_tree_summary(extract_dir)
    return extract_dir, fs_type


def detect_filesystem(extract_dir: Path) -> str:
    for marker, label in [("squashfs-root", "SquashFS"), ("cramfs", "CramFS"), ("jffs2", "JFFS2")]:
        if any(extract_dir.rglob(f"*{marker}*")):
            return label
    subdirs = [d.name.lower() for d in extract_dir.iterdir() if d.is_dir()]
    if any("squash" in d for d in subdirs):
        return "SquashFS"
    return "Unknown"


def print_tree_summary(root: Path):
    _info("Extracted directory tree (top 3 levels):")
    if HAS_RICH:
        tree = Tree(f"[bold]{root.name}[/bold]")
        _build_rich_tree(tree, root, depth=0, max_depth=3, max_entries=60)
        console.print(tree)
    else:
        count = 0
        for item in sorted(root.rglob("*")):
            if count > 60:
                print("  ... (truncated)")
                break
            depth = len(item.relative_to(root).parts) - 1
            if depth > 2:
                continue
            prefix = "  " * depth + ("📁 " if item.is_dir() else "📄 ")
            print(f"  {prefix}{item.name}")
            count += 1


def _build_rich_tree(node, path, depth, max_depth, max_entries, _c=None):
    if _c is None:
        _c = [0]
    if depth >= max_depth or _c[0] > max_entries:
        return
    try:
        children = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name))
    except PermissionError:
        return
    for child in children:
        if _c[0] > max_entries:
            node.add("[dim]...[/dim]")
            break
        _c[0] += 1
        label = f"[bold blue]{child.name}[/bold blue]" if child.is_dir() else child.name
        branch = node.add(label)
        if child.is_dir():
            _build_rich_tree(branch, child, depth + 1, max_depth, max_entries, _c)
