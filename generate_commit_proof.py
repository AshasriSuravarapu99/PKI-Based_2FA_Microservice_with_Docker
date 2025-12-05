#!/usr/bin/env python3
"""
generate_commit_proof.py

Usage:
  python generate_commit_proof.py \
    --private student_private.pem \
    --instructor instructor_public.pem \
    --out proof.txt

Output (printed):
  Commit Hash: <40-hex>
  Encrypted Signature (base64): <single-line-base64>

It also writes the base64 string to the file given by --out if provided.
"""
import subprocess
import argparse
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import sys
from pathlib import Path

def get_latest_commit_hash() -> str:
    # Returns the 40-character hex commit hash (ASCII string)
    proc = subprocess.run(["git", "log", "-1", "--format=%H"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git failed: {proc.stderr.strip()}")
    h = proc.stdout.strip()
    if len(h) != 40:
        raise RuntimeError(f"Unexpected commit hash length: '{h}'")
    # Validate hex characters:
    int(h, 16)  # will raise ValueError if not hex
    return h

def load_private_key(path: str):
    data = Path(path).read_bytes()
    # No password assumed. If your key is encrypted, you must adjust for password.
    return serialization.load_pem_private_key(data, password=None, backend=default_backend())

def load_public_key(path: str):
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data, backend=default_backend())

def sign_message(message: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign ASCII message using RSA-PSS with SHA-256, MGF1(SHA-256), salt_length=Max.
    message: ASCII/UTF-8 string (commit hash)
    Returns signature bytes.
    """
    msg_bytes = message.encode("utf-8")   # CRITICAL: sign ASCII bytes
    signature = private_key.sign(
        msg_bytes,
        asympadding.PSS(
            mgf=asympadding.MGF1(hashes.SHA256()),
            salt_length=asympadding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def encrypt_with_public_key(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt bytes using RSA/OAEP with SHA-256 and MGF1(SHA-256). Returns ciphertext bytes.
    """
    ciphertext = public_key.encrypt(
        data,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def generate_proof(private_pem: str, instructor_pub_pem: str, out_file: str = None):
    commit_hash = get_latest_commit_hash()
    priv = load_private_key(private_pem)
    instr_pub = load_public_key(instructor_pub_pem)

    # 1) Sign
    sig_bytes = sign_message(commit_hash, priv)

    # 2) Encrypt signature with instructor public key
    encrypted_sig = encrypt_with_public_key(sig_bytes, instr_pub)

    # 3) Base64 encode the encrypted signature and produce single-line string
    b64 = base64.b64encode(encrypted_sig).decode("ascii")

    # Output results
    print("Commit Hash:", commit_hash)
    print("Encrypted Signature (base64):")
    print(b64)

    if out_file:
        Path(out_file).write_text(b64, encoding="utf-8")
        print(f"Wrote base64 encrypted signature to: {out_file}")

    # Return values for programmatic usage
    return commit_hash, b64

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--private", required=True, help="Path to student_private.pem (PEM RSA private key)")
    parser.add_argument("--instructor", required=True, help="Path to instructor_public.pem (PEM RSA public key)")
    parser.add_argument("--out", required=False, help="Optional output file to save base64 encrypted signature")
    args = parser.parse_args()

    try:
        generate_proof(args.private, args.instructor, args.out)
    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
