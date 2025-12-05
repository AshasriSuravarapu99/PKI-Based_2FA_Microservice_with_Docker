import base64
import re
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext
        private_key: RSA private key object

    Returns:
        Decrypted hex seed (64-character string)

    Implementation:
    1. Base64 decode the encrypted seed string

    2. RSA/OAEP decrypt with SHA-256
       - Padding: OAEP
       - MGF: MGF1(SHA-256)
       - Hash: SHA-256
       - Label: None

    3. Decode bytes to UTF-8 string

    4. Validate: must be 64-character hex string
       - Check length is 64
       - Check all characters are in '0123456789abcdef'

    5. Return hex seed
    """
    # 1. Base64 decode
    ciphertext = base64.b64decode(encrypted_seed_b64)

    # 2. RSA OAEP decrypt
    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 3. Convert bytes to UTF-8 string
    seed_hex = plaintext_bytes.decode('utf-8')

    # 4. Validate hex seed
    if len(seed_hex) != 64:
        raise ValueError("Decrypted seed is not 64 characters long.")

    if not re.fullmatch(r"[0-9a-fA-F]{64}", seed_hex):
        raise ValueError("Decrypted seed contains non-hex characters.")

    # 5. Return hex seed
    return seed_hex
def run_decryption():
    # Read encrypted seed
    with open("encrypted_seed.txt", "r") as f:
        encrypted_b64 = f.read().strip()

    # Load private key
    with open("student_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    # Decrypt
    seed_hex = decrypt_seed(encrypted_b64, private_key)

    # Save to /data/seed.txt
    with open("data/seed.txt", "w") as f:
        f.write(seed_hex)

    print("✅ Seed successfully decrypted and stored at /data/seed.txt")
    print("Seed:", seed_hex)
    
run_decryption()
