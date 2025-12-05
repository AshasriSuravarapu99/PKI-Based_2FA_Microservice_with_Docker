import json
import requests

def request_seed(student_id: str, github_repo_url: str, api_url: str):
    
    # Step 1: Read public key and convert to single-line with \n
    #with open("student_public.pem", "r") as f:
        #public_key = f.read().replace("\n", "\\n")
    
    # Step 2: Prepare JSON payload
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAng0CbV/aXOOEj75RyL/n\nkgrd7Bjmlf/rTWvvg8y0GFufwze/zt3XGeUat6PIHpkY5ynVyWJKI4bZVHIGkh8t\noFMnSLGuwDJhAwQunbGH6LE83Kg5/Za2sKD7UKlNUz1t+Lo30SDVzq1UXgyVDc/F\nWs6sxDe24BAQNqL2FXQRQ9Flrc5IoeWJwtGqBw7ldxvUYnwQuqUonS7+60KbLFsd\nwXzp9zOL0B8CoLI7l6b3GPRBvxPshInlIDZPsV0W3U89vfeaYk+9lcjLYoKJmlzH\ncepNk8cIv82rErO+GvuvEGZmfcv4Hc9HNpCgxZaMw8/11wjneJSgEAZEEEw48NyM\nFAcMvX3nRsJbqMOYfdG3SlPOU036Fceeu+YCTEYsIYUO1xKteS4+KGXUgSAtGTXe\nYYfE6478D8pMf4b5LTZfOL4hIyKp0kWX/1L5Kjmy5qxZ85t46jLS9r/l6o/i/cwY\ngrfIUe1yawB1VmuK8dX/UxltjihXPXKvTNokA9MecxtWf4+76RTbXyP/5JcASjc/\nNrHw4y7OfG8+Jj8ybT9yGvT7C3aSFpXq0IBV1GHcI2jWz/YW//jenYVozxqwubgF\nRxyOBnUHpL1/5kw4/pSJMyV4CIy1rAtwvC1YdsKYvqvU++ZPXNA5JJR3dNPkFT2j\nFvcsNIGcyNnyeU9H9elyxX8CAwEAAQ==\n-----END PUBLIC KEY-----\n"
    }
    
    try:
        # Step 3: Send POST request
        headers = {"Content-Type": "application/json"}
        response = requests.post(api_url, headers=headers, data=json.dumps(payload), timeout=10)
        
        # Step 4: Parse JSON response
        response.raise_for_status()  # raise error for HTTP errors
        data = response.json()
        
        if data.get("status") == "success" and "encrypted_seed" in data:
            encrypted_seed = data["encrypted_seed"]
            
            # Step 5: Save encrypted seed to file
            with open("encrypted_seed.txt", "w") as f:
                f.write(encrypted_seed)
            
            print("Encrypted seed saved to encrypted_seed.txt")
            return encrypted_seed
        else:
            print("Error: Unexpected response:", data)
            return None

    except requests.RequestException as e:
        print("HTTP Request failed:", e)
        return None
request_seed(
    student_id="24A95A0511",
    github_repo_url="https://github.com/AshasriSuravarapu99/PKI-Based_2FA_Microservice_with_Docker",
    api_url="https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
)
