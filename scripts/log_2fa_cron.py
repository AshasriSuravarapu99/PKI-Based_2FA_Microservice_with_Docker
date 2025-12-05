#!/usr/bin/env python3
# scripts/log_2fa_cron.py
# Cron script: read /data/seed.txt, generate TOTP, print timestamp + code to stdout

import base64
import re
import hashlib
from datetime import datetime, timezone
import pyotp
import sys
import os

HEX64_RE = re.compile(r'^[0-9a-fA-F]{64}$')
SEED_PATH = "/data/seed.txt"

def hex_to_base32_no_padding(hex_seed: str) -> str:
    """Convert 64-character hex seed to Base32 without '=' padding."""
    seed_bytes = bytes.fromhex(hex_seed)
    b32 = base64.b32encode(seed_bytes).decode("ascii")
    return b32.rstrip("=")

def generate_totp_from_hex(hex_seed: str) -> str:
    base32_seed = hex_to_base32_no_padding(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)
    return totp.now()

def utc_now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def main():
    try:
        with open(SEED_PATH, "r") as f:
            hex_seed = f.read().strip()
    except FileNotFoundError:
        # Graceful message when seed isn't present yet
        print(f"{utc_now_str()} - 2FA Code: SEED_MISSING")
        return 0
    except Exception as e:
        print(f"{utc_now_str()} - 2FA Code: ERROR reading seed: {e}")
        return 0

    if not HEX64_RE.fullmatch(hex_seed):
        print(f"{utc_now_str()} - 2FA Code: INVALID_SEED")
        return 0

    try:
        code = generate_totp_from_hex(hex_seed)
    except Exception as e:
        print(f"{utc_now_str()} - 2FA Code: ERROR generating TOTP: {e}")
        return 0

    # Print one formatted line (cron will append to /cron/last_code.txt)
    print(f"{utc_now_str()} - 2FA Code: {code}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
