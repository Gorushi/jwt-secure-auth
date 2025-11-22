import requests
import sys

BASE_URL = "http://127.0.0.1:8000/api/auth"

def run_security_test():
    print("--- [Security Test] Token Rotation & Replay Attack ---")
    
    username = "security_test_user@example.com"
    password = "password123"
    s = requests.Session()

    # 0. 회원가입 (User Missing 에러 방지)
    print(f"[0] Signup user: {username}")
    try:
        signup_res = s.post(f"{BASE_URL}/signup", json={"email": username, "password": password})
        if signup_res.status_code == 201:
            print(" -> Signup success")
        elif signup_res.status_code == 400:
            print(" -> User already exists, proceeding to login")
        else:
            print(f" -> Signup failed: {signup_res.text}")
            # 서버가 안 켜져있거나 경로가 틀렸을 경우
            if signup_res.status_code == 404:
                print("Error: 404 Not Found. BASE_URL을 확인하세요.")
            return
    except Exception as e:
        print(f" -> Server connection failed: {e}")
        return

    # 1. Login (Step 1)
    print("\n[1] Login Step 1...")
    # OAuth2Form은 data로 전송
    r = s.post(f"{BASE_URL}/login", data={"username": username, "password": password})
    
    if r.status_code != 200:
        print(f" -> Login failed: {r.status_code} {r.text}")
        return
    
    data = r.json()
    if "mfa_token" not in data:
        print(" -> Error: No mfa_token received. Check server logs.")
        return

    mfa_token = data["mfa_token"]
    print(" -> Login Step 1 Success. MFA Token received.")

    # 2. MFA Verify (Step 2)
    print("\n⚠️  Check server terminal for OTP!")
    otp = input(f"Enter OTP for {username}: ").strip()
    
    print(f"\n[2] Verifying OTP: {otp}...")
    r = s.post(f"{BASE_URL}/mfa/verify", json={"mfa_token": mfa_token, "otp": otp})
    
    if r.status_code != 200:
        print(f" -> MFA failed: {r.text}")
        return

    tokens = r.json()
    print(" -> MFA Success. Access/Refresh Tokens received.")
    
    # 쿠키 확인
    refresh_cookie = s.cookies.get("refresh_token")
    if not refresh_cookie:
         print(" -> Note: Refresh token cookie not found in session (using fallback?)")
    
    # 3. Token Replay Scenario
    print(f"\n[3] Attacker steals refresh token...")
    
    # 쿠키가 있으면 쿠키값, 없으면(실패시) 예제 진행 불가하므로 체크
    if not refresh_cookie:
        print(" -> Error: Cannot steal cookie (not found). Test aborted.")
        return

    stolen_token = refresh_cookie
    print(f" -> Stolen Token: {stolen_token[:10]}...")

    # 4. Legitimate User Refreshes Token
    print("\n[4] Legitimate user refreshes token (Token Rotation occurs)...")
    
    refresh_payload = {"access_token": stolen_token, "token_type": "bearer"}
    
    r = s.post(f"{BASE_URL}/refresh", json=refresh_payload)
    
    if r.status_code == 200:
        print(" -> User refresh success (New tokens issued)")
    else:
        print(f" -> User refresh failed: {r.text}")
        return

    # 5. Attacker tries to use OLD refresh token
    print("\n[5] Attacker tries to use STOLEN (Revoked) token...")
    
    attacker_session = requests.Session()
    # 공격자는 훔친 토큰(stolen_token)을 사용하여 갱신 시도
    r = attacker_session.post(f"{BASE_URL}/refresh", json=refresh_payload)
    
    print(f" -> Attack Response Status: {r.status_code}")
    
    if r.status_code == 401: # Unauthorized
        print(" -> [PASS] Attack blocked! Server rejected the revoked token. ✅")
    else:
        print(f" -> [FAIL] Attack succeeded? (Status: {r.status_code}) ❌")

if __name__ == "__main__":
    run_security_test()
