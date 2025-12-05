import base64
import re
import hashlib
import pyotp

HEX64_REGEX = re.compile(r'^[0-9a-fA-F]{64}$')

# Hex to Base32
def _hex_to_base32(hex_seed: str) -> str:
    """
    Convert 64-character hex seed to Base32 (no padding)
    """
    if not HEX64_REGEX.fullmatch(hex_seed):
        raise ValueError("hex_seed must be a 64-character hexadecimal string")

    seed_bytes = bytes.fromhex(hex_seed)       # hex → bytes
    b32 = base64.b32encode(seed_bytes).decode()  # bytes → base32
    return b32.rstrip("=")                    # remove '=' padding

# Implementation of totp:

def generate_totp_from_file(hex_seed:str) -> str:
    """
    Read hex seed from data/seed.txt and generate TOTP code.
    """

    # 1. Convert to base32
    base32_seed = _hex_to_base32(hex_seed)

    # 2. Create TOTP generator
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)

    # 3. Generate current code
    return totp.now()

# Verification
def verify_totp_from_file(hex_seed:str,code: str, valid_window: int = 1) -> bool:
    """
    Verify given TOTP code using seed from data/seed.txt file.
    """
    if not re.fullmatch(r"\d{6}", code):
        return False

    base32_seed = _hex_to_base32(hex_seed)

    totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)

    return totp.verify(code, valid_window=valid_window)




with open("data/seed.txt","r") as f:
    hex_seed =f.read().strip()
#print(hex_seed)


code = generate_totp_from_file(hex_seed)
print("Current TOTP Code:", code)

user_input = input("Enter 6-digit TOTP code: ")
print("Valid?", verify_totp_from_file(hex_seed,user_input))



