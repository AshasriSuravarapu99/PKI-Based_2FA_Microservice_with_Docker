# app.py
import os
import time
import base64
import re
import hashlib
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp

# -----------------------
# Config / constants
# -----------------------
PRIVATE_KEY_PATH = "student_private.pem"   # private key file in repo root
ASSIGNMENT_DATA_PATH = "/data/seed.txt"    # path required by grader in container
LOCAL_DATA_FALLBACK = "data/seed.txt"      # use for local Windows dev/testing

HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

app = FastAPI(title="PKI-2FA Microservice")


# -----------------------
# Helpers
# -----------------------
def _get_seed_path_for_runtime() -> str:
    """
    Return the path to store/read the seed.
    Prefer the grader path '/data/seed.txt' if it exists or if running in container.
    For local development (no /data folder) fall back to 'data/seed.txt'.
    """
    # if '/data' exists or is writable prefer assignment path
    try:
        if os.path.isdir("/data") or os.access("/data", os.W_OK):
            return ASSIGNMENT_DATA_PATH
    except Exception:
        pass

    # fallback - ensure local data directory exists
    os.makedirs(os.path.dirname(LOCAL_DATA_FALLBACK), exist_ok=True)
    return LOCAL_DATA_FALLBACK


def _load_private_key(path: str = PRIVATE_KEY_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key file not found: {path}")
    with open(path, "rb") as f:
        key_data = f.read()
    private_key = serialization.load_pem_private_key(key_data, password=None)
    return private_key


def _save_seed_hex(seed_hex: str, seed_path: str):
    # ensure parent exists
    os.makedirs(os.path.dirname(seed_path), exist_ok=True)
    with open(seed_path, "w") as f:
        f.write(seed_hex)


def _read_seed_hex(seed_path: str) -> str:
    if not os.path.exists(seed_path):
        raise FileNotFoundError("Seed file not found")
    with open(seed_path, "r") as f:
        return f.read().strip()


def _hex_to_base32_no_padding(hex_seed: str) -> str:
    # hex -> bytes -> base32 -> strip '=' padding
    seed_bytes = bytes.fromhex(hex_seed)
    b32 = base64.b32encode(seed_bytes).decode("ascii")
    return b32.rstrip("=")


# -----------------------
# Request/Response models
# -----------------------
class DecryptRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: Optional[str] = None


# -----------------------
# Endpoint 1: POST /decrypt-seed
# -----------------------
@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(req: DecryptRequest):
    """
    Accepts {"encrypted_seed": "<base64>"}.
    Decrypts with student_private.pem, validates 64-hex, writes seed file, returns {"status":"ok"}.
    """
    seed_path = _get_seed_path_for_runtime()

    # 1. Load private key
    try:
        private_key = _load_private_key()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})

    # 2. Base64 decode
    try:
        ciphertext = base64.b64decode(req.encrypted_seed, validate=True)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": "Invalid base64 encrypted_seed"})

    # 3. RSA/OAEP-SHA256 decrypt
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        # decryption failed
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    # 4. Decode UTF-8 and validate hex
    try:
        seed_hex = plaintext_bytes.decode("utf-8").strip()
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Decrypted seed not valid UTF-8"})

    if not HEX64_RE.fullmatch(seed_hex):
        raise HTTPException(status_code=500, detail={"error": "Decrypted seed validation failed"})

    # 5. Save to /data/seed.txt (or fallback)
    try:
        _save_seed_hex(seed_hex, seed_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": f"Failed to save seed file: {e}"})

    return {"status": "ok"}


# -----------------------
# Endpoint 2: GET /generate-2fa
# -----------------------
@app.get("/generate-2fa")
async def generate_2fa():
    """
    Read seed from disk, generate TOTP code and remaining valid seconds.
    Returns {"code":"123456","valid_for":30}
    """
    seed_path = _get_seed_path_for_runtime()
    try:
        seed_hex = _read_seed_hex(seed_path)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    if not HEX64_RE.fullmatch(seed_hex):
        raise HTTPException(status_code=500, detail={"error": "Stored seed invalid"})

    # Convert hex to base32 and generate TOTP
    base32_seed = _hex_to_base32_no_padding(seed_hex)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)
    code = totp.now()

    # compute remaining seconds in current 30s period
    epoch = int(time.time())
    seconds_into_period = epoch % 30
    valid_for = 30 - seconds_into_period

    return {"code": code, "valid_for": valid_for}


# -----------------------
# Endpoint 3: POST /verify-2fa
# -----------------------
@app.post("/verify-2fa")
async def verify_2fa(req: VerifyRequest):
    """
    Accept {"code":"123456"} and verify against seed in file.
    Returns {"valid": true} or {"valid": false} or 400/500 errors.
    """
    if not req.code:
        raise HTTPException(status_code=400, detail={"error": "Missing code"})

    if not re.fullmatch(r"\d{6}", req.code):
        # invalid format
        return {"valid": False}

    seed_path = _get_seed_path_for_runtime()
    try:
        seed_hex = _read_seed_hex(seed_path)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    base32_seed = _hex_to_base32_no_padding(seed_hex)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)

    # verify with ±1 period tolerance
    is_valid = bool(totp.verify(req.code, valid_window=1))

    return {"valid": is_valid}


# -----------------------
# Optional: run with uvicorn for local testing
# -----------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
