import requests

# ---------------------------
# STEP 1: CALL INSTRUCTOR API
# ---------------------------
print("🔹 Calling Instructor API...")

instructor_response = requests.post(
    "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws",
    json={
        "student_id": "<YOUR_STUDENT_ID>",
        "github_url": "<YOUR_GITHUB_REPO_URL>"
    }
)

#encrypted_seed = instructor_response.json().get("encrypted_seed")
encrypted_seed = "NbITsl2f0mRN1ivZVj2ODvA1egTee2ae3M6itOI/LHmct5mcSueJOaspa878gqsd1TU0gGjbYW2es2c3K/jKisuMRGmtKJy0PqUTBuzvPijjeLsAfw6n+eMhWdPjzH7nC/xoAatZdrC9b/GwbmcDEjRK2Grb5SeDi878IM0GLTwbyp+VS9k3vIkaCAngFHLYp3oWIFeBx9ebDIbtvzthUH2Pr1c8iCy/mAzylTmy0WlMh5QZtYWRUK0NQJLU8kThkz2bnIebgh9Bha4maJmT1R/1HSKgAlgqeoj1mgtKGdeYRwA49+kDMrYKBZ+LaTPtu/8O0jlILIxjIlmzv+75WikxK4g2diHrRZPkNM9bbCGLJggfk0NbTQmnI/rCmOXQNr75Wym2deuPfVCRvKLiC7RCod2nnVGNQdHuA08jm7HR5zRpH1Ul6G6cMNgu6FNuhP2CWpTHJ6+b4sOyKDUIU7DQGBjq4LaRHrkDbU3M7izdX9Wv+K1tM4zPJyRzXS9R+v7mMTxpuV4GwTfzScBfYaSFBn+74iGbtjuDKXUgjROCbI1DMu8R/We7koA1TBD4oJ7SZlDa+hS9a6dv5i9tVofRG6zdFKAgof1TUe+CF7b5HIQywjydO3Mq5lWo+vivJ4EHcdVXIDn2QggidbZaxOE98nB0Xaz2k2vLuCFnrtI="
print("Encrypted Seed Received:", encrypted_seed)

# ---------------------------
# STEP 2: SEND ENCRYPTED SEED TO /decrypt-seed
# ---------------------------
print("\n🔹 Sending encrypted seed to your FastAPI service...")

decrypt_response = requests.post(
    "http://127.0.0.1:8000/decrypt-seed",
    json={"encrypted_seed": encrypted_seed}
)

print("Decryption Response:", decrypt_response.json())


# ---------------------------
# STEP 3: GENERATE 2FA CODE
# ---------------------------
print("\n🔹 Requesting FastAPI to generate 2FA...")

generate_response = requests.get("http://127.0.0.1:8000/generate-2fa")
generated_code = generate_response.json().get("code")

print("Generated 2FA Code:", generated_code)


# ---------------------------
# STEP 4: VERIFY 2FA CODE
# ---------------------------
print("\n🔹 Verifying the generated 2FA code...")

verify_response = requests.post(
    "http://127.0.0.1:8000/verify-2fa",
    json={"code": generated_code}
)

print("Verification Response:", verify_response.json())
