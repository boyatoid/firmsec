#!/bin/bash
# FirmSec Codespaces Bootstrap
# Run: bash bootstrap.sh

set -e

echo "===================================="
echo " FirmSec Environment Bootstrap"
echo "===================================="

# ── System packages ──────────────────────────────────────
echo "[1/6] Installing system packages..."
sudo apt update -qq
sudo apt install -y \
  binwalk \
  git \
  python3 \
  python3-pip \
  qemu-system-arm \
  qemu-user-static \
  busybox-static \
  fakeroot \
  curl \
  wget \
  file \
  binutils \
  nmap \
  net-tools

# ── Python dependencies ───────────────────────────────────
echo "[2/6] Installing Python dependencies..."
pip install --quiet colorama rich

# ── FirmAE ────────────────────────────────────────────────
echo "[3/6] Installing FirmAE..."
if [ ! -d "$HOME/FirmAE" ]; then
  git clone https://github.com/pr0v3rbs/FirmAE "$HOME/FirmAE"
  cd "$HOME/FirmAE" && sudo ./setup.sh
  cd ~
else
  echo "  FirmAE already installed, skipping."
fi

# ── Pull FirmSec tool from your private repo ─────────────
echo "[4/6] Pulling FirmSec from GitHub..."
if [ ! -d "$HOME/firmsec" ]; then
  gh repo clone boyatoid/firmsec "$HOME/firmsec"
else
  cd "$HOME/firmsec" && git pull && cd ~
  echo "  FirmSec already cloned, pulled latest."
fi

# ── Download firmware from release v1.0 ──────────────────
echo "[5/6] Downloading firmware from release v1.0..."
mkdir -p "$HOME/firmsec/firmware"
cd "$HOME/firmsec/firmware"

gh release download v1.0 \
  --repo boyatoid/firmsec \
  --dir . \
  --clobber

echo "  Firmware files downloaded:"
ls -lh .
cd ~

# ── Create reports directory ──────────────────────────────
mkdir -p "$HOME/firmsec/reports"

# ── Run FirmSec ───────────────────────────────────────────
echo "[6/6] Running FirmSec analysis..."
FIRMWARE=$(ls "$HOME/firmsec/firmware"/*.bin 2>/dev/null | head -1)

if [ -z "$FIRMWARE" ]; then
  echo "  WARNING: No .bin file found in firmware folder."
  echo "  Check your release assets and re-run:"
  echo "  gh release download v1.0 --repo boyatoid/firmsec --dir ~/firmsec/firmware"
else
  echo "  Analyzing: $FIRMWARE"
  python3 "$HOME/firmsec/firmsec.py" \
    --target "$FIRMWARE" \
    --output "$HOME/firmsec/reports/" \
    --kali
fi

# ── Done ──────────────────────────────────────────────────
echo ""
echo "===================================="
echo " Bootstrap complete!"
echo " Reports: ~/firmsec/reports/"
echo " Firmware: ~/firmsec/firmware/"
echo " FirmAE:   ~/FirmAE/"
echo "===================================="
