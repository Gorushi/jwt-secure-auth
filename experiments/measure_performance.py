import requests
import time
import statistics

BASE_URL = "http://127.0.0.1:8000/api/auth"
USER_URL = "http://127.0.0.1:8000/api/users"

def measure_endpoint_performance():
    print("--- [Performance Test] Response Times ---")
    
    username = "perf_test_user@example.com"
    password = "password123"
    
    # 1. 회원가입 (준비 단계)
    try:
        requests.post(f"{BASE_URL}/signup", json={"email": username, "password": password})
    except Exception:
        print("Server not running?")
        return

    # 2. Login (1단계) 성능 측정
    print("\n[Measuring POST /login (MFA Step 1)] - 30 iterations")
    timings = []
    for _ in range(30):
        start = time.perf_counter()
        requests.post(f"{BASE_URL}/login", data={"username": username, "password": password})
        end = time.perf_counter()
        timings.append((end - start) * 1000) # ms 변환
    
    print(f" -> Avg: {statistics.mean(timings):.2f} ms")
    print(f" -> Min: {min(timings):.2f} ms")
    print(f" -> Max: {max(timings):.2f} ms")

    # 3. Protected API 성능 측정
    # 이를 위해선 유효한 Access Token이 하나 필요합니다.
    print("\n[Preparing Access Token for Protected API test...]")
    
    # 로그인 -> MFA 토큰 획득
    resp = requests.post(f"{BASE_URL}/login", data={"username": username, "password": password})
    if resp.status_code != 200:
        print("Login failed during preparation.")
        return
    mfa_token = resp.json().get("mfa_token")
    
    print("⚠️  Enter OTP from server terminal to proceed with performance test:")
    otp = input("OTP: ").strip()
    
    # MFA 검증 -> Access Token 획득
    resp = requests.post(f"{BASE_URL}/mfa/verify", json={"mfa_token": mfa_token, "otp": otp})
    if resp.status_code != 200:
        print("MFA Verify failed.")
        return
    
    access_token = resp.json().get("access_token")
    headers = {"Authorization": f"Bearer {access_token}"}

    print("\n[Measuring GET /api/users/me (Protected)] - 30 iterations")
    timings_prot = []
    for _ in range(30):
        start = time.perf_counter()
        requests.get(f"{USER_URL}/me", headers=headers)
        end = time.perf_counter()
        timings_prot.append((end - start) * 1000)
        
    print(f" -> Avg: {statistics.mean(timings_prot):.2f} ms")
    print(f" -> Min: {min(timings_prot):.2f} ms")
    print(f" -> Max: {max(timings_prot):.2f} ms")

if __name__ == "__main__":
    measure_endpoint_performance()
