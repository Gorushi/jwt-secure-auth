import requests
import time

# --- 설정 ---
BASE_URL = "http://127.0.0.1:8000"
# API 라우터에 설정된 prefix 경로
AUTH_PREFIX = "/auth"
USERS_PREFIX = "/users"

# 'username' 키를 'email'로 변경하고, 값도 유효한 이메일 형식으로 수정.
TEST_USER = {
    "email": f"attacker_{int(time.time())}@test.com",
    "password": "strongpassword"
}

def scenario_description():
    """공격 시나리오를 터미널에 출력"""
    print("="*50)
    print("⚔️ 공격 시나리오: 토큰 재사용 (Token Replay Attack)")
    print("="*50)
    print("1. 공격자는 정상적인 방법으로 사용자 계정을 생성하고 로그인합니다.")
    print("2. 네트워크 트래픽 감청, 클라이언트 저장소(LocalStorage) 해킹 등의 방법으로")
    print("   피해자의 Access Token을 탈취했다고 가정합니다.")
    print("3. 공격자는 탈취한 토큰을 그대로 사용하여 보호된 API에 접근을 시도합니다.")
    print("4. 현재 시스템은 토큰의 유효기간과 서명만 검증하므로, 이 공격은 성공합니다.")
    print("-" * 50)

def run_attack():
    """공격 시나리오를 순서대로 실행."""
    session = requests.Session()

    # 1. 공격자 계정 생성
    signup_url = f"{BASE_URL}{AUTH_PREFIX}/signup"
    print(f"[INFO] 1. Creating attacker account via: {signup_url}")
    try:
        # 수정된 TEST_USER 딕셔너리를 json으로 전송.
        response = session.post(signup_url, json=TEST_USER)
        response.raise_for_status()
        print(f"[SUCCESS] Account created. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[FAIL] Account creation failed: {e}")
        return

    # 2. 공격자 로그인 및 토큰 획득
    login_url = f"{BASE_URL}{AUTH_PREFIX}/login"
    print(f"\n[INFO] 2. Logging in to get a valid token via: {login_url}")
    try:
        # 로그인 form의 'username' 필드에는 방금 생성한 사용자의 'email'을 값으로 사용.
        login_data = {"username": TEST_USER["email"], "password": TEST_USER["password"]}
        response = session.post(login_url, data=login_data)
        response.raise_for_status()
        tokens = response.json()
        stolen_access_token = tokens.get("access_token")
        print(f"[SUCCESS] Token stolen: {stolen_access_token[:30]}...")
    except requests.exceptions.RequestException as e:
        print(f"[FAIL] Login failed: {e}")
        return

    # 3. 탈취한 토큰으로 보호된 API 접근 시도
    protected_url = f"{BASE_URL}{USERS_PREFIX}/me"
    print(f"\n[INFO] 3. Attacking protected endpoint with the stolen token via: {protected_url}")
    headers = {"Authorization": f"Bearer {stolen_access_token}"}
    try:
        response = session.get(protected_url, headers=headers)
        response.raise_for_status()
        print("[SUCCESS] Attack successful! We accessed the protected data:")
        print(f"   Response Status: {response.status_code}")
        print(f"   Response Body: {response.json()}")
    except requests.exceptions.RequestException as e:
        print(f"[FAIL] Attack failed: {e}")
    
    print("\n[CONCLUSION] 토큰이 유효하기만 하다면 누구든, 어디서든 사용할 수 있는 상태입니다.")
    print("   -> 5주차에서 '로그아웃 시 토큰 무효화(Blacklist)'로 이를 방어할 것입니다.")

if __name__ == "__main__":
    scenario_description()
    run_attack()
