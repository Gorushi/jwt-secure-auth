# 🛡️ JWT Secure Auth System (FastAPI + MFA)

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.118.2-009688?style=flat-square&logo=fastapi&logoColor=white)
![Security](https://img.shields.io/badge/Security-MFA_&_Rotation-red?style=flat-square)

<br>

이 프로젝트는 **FastAPI**를 기반으로 구축된 **고보안 인증 시스템**입니다.

단순한 JWT 발급을 넘어, 다음과 같은 실무 수준의 강력한 보안 기능을 구현하고 검증했습니다:
* **MFA (다단계 인증)**
* **Token Rotation (토큰 회전)**
* **Token Blacklisting (토큰 폐기)**
* **실제 공격 시나리오 방어 실험**

<br>

## ✨ 주요 기능 (Key Features)

| 기능 | 설명 |
| :--- | :--- |
| **MFA (2-Factor Auth)** | 아이디/비밀번호 인증 후 **OTP(One-Time Password)**를 통한 2차 인증 강제 |
| **Token Rotation** | Refresh Token 사용 시마다 새로운 토큰을 발급하고, 이전 토큰은 즉시 폐기하여 **탈취 위협 최소화** |
| **Blacklisting** | 로그아웃하거나 회전된 토큰의 재사용을 막기 위해 DB 기반의 블랙리스트 관리 |
| **Algorithm Agility** | 설정에 따라 `HS256`(대칭키) 또는 `RS256`(비대칭키) 알고리즘 선택 가능 |
| **Secure Hashing** | `Bcrypt`를 사용하여 비밀번호를 안전하게 해싱 및 저장 |

<br>

## 🏗️ 아키텍처 및 인증 흐름 (Architecture)

사용자 인증은 **2단계(2FA)**로 진행되며, 토큰 갱신 시 **Rotation** 기법이 적용됩니다.

```mermaid
sequenceDiagram
    participant User
    participant Server
    participant DB

    Note over User, Server: 1단계: 자격 증명 확인 (Login Step 1)
    User->>Server: POST /api/auth/login (ID/PW)
    Server->>DB: 사용자 및 비밀번호 검증
    Server->>User: 200 OK (MFA Temporary Token)
    Note right of Server: 서버 콘솔에 OTP 출력 (Email 전송 시뮬레이션)

    Note over User, Server: 2단계: OTP 인증 (Login Step 2)
    User->>Server: POST /api/auth/mfa/verify (MFA Token + OTP)
    Server->>DB: OTP 유효성 검증
    Server->>User: 200 OK (Access + Refresh Token 발급)

    Note over User, Server: 토큰 갱신 (Token Rotation)
    User->>Server: POST /api/auth/refresh (Old Refresh Token)
    Server->>DB: Blacklist 확인 (재사용 감지 시 차단)
    Server->>DB: Old Token -> Blacklist 추가
    Server->>User: 200 OK (New Access + New Refresh Token)
````

<br>

## 🧪 검증 및 실험 결과 (Experiments)

이 프로젝트는 `experiments/` 폴더 내의 스크립트를 통해 보안성과 성능을 정량적으로 검증했습니다.

### 1\. 보안성 검증 (Replay Attack 방어)

공격자가 탈취한(이미 갱신되어 폐기된) Refresh Token을 재사용하려고 시도하는 시나리오를 테스트했습니다.

  * **테스트 스크립트:** `python experiments/measure_security.py`
  * **결과:** 서버는 구버전 토큰의 `jti`가 블랙리스트에 있음을 감지하고 **401 Unauthorized**를 반환하여 공격을 차단함.

### 2\. 성능 측정 (Performance)

보안 로직(DB 조회, 해싱, 암호화)이 추가되었음에도, 주요 엔드포인트는 목적에 맞는 최적의 성능을 보였습니다.

| 엔드포인트 | 평균 응답 시간 | 분석 |
| :--- | :--- | :--- |
| `POST /login` (1단계) | **554.78 ms** | `Bcrypt` 해싱 비용으로 인한 의도된 지연 (Brute-force 방어 적합) |
| `GET /protected` | **0.79 ms** | JWT 검증 최적화로 인해 **1ms 미만**의 매우 빠른 응답 속도 달성 |

*(측정 환경: Localhost, Python 3.11)*

<br>

## 🛠️ 기술 스택 (Tech Stack)

  * **Language:** Python 3.11
  * **Framework:** FastAPI
  * **Database:** SQLite (SQLAlchemy ORM)
  * **Security Libs:**
      * `python-jose`: JWT 생성 및 검증 (RS256/HS256)
      * `passlib[bcrypt]`: 비밀번호 해싱
      * `cryptography`: 키 관리

<br>

## 🚀 실행 방법 (Getting Started)

### 1\. 환경 설정 및 설치

```bash
# 가상환경 생성 (선택)
python -m venv .venv

# Mac/Linux
source .venv/bin/activate

# Windows
# .venv\Scripts\activate

# 라이브러리 설치
pip install -r requirements.txt
```

### 2\. 키 생성 (RS256 사용 시)

프로젝트 루트에서 비대칭키(Private/Public)를 생성합니다. (HS256 사용 시 생략 가능)

```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### 3\. 서버 실행

```bash
uvicorn app.main:app --reload
```

### 4\. API 테스트

  * **Swagger UI:** [http://127.0.0.1:8000/docs](https://www.google.com/search?q=http://127.0.0.1:8000/docs) 접속
  * **실험 스크립트 실행:**
    ```bash
    # 보안성 검증
    python experiments/measure_security.py

    # 성능 측정
    python experiments/measure_performance.py
    ```

<br>

## 📂 프로젝트 구조

```text
jwt-secure-auth/
├── app/
│   ├── api/endpoints/
│   │   └── auth.py                # MFA, Login, Refresh, Logout 핵심 로직
│   ├── crud/
│   │   └── crud_token.py          # Token Blacklist DB 작업
│   ├── routes/
│   │   └── users.py               # 사용자 정보 조회 (Protected Endpoint)
│   ├── config.py                  # 환경 설정 (Secret Key, Algorithm 등)
│   ├── dependencies.py            # DB 세션 및 의존성 주입
│   ├── main.py                    # FastAPI 앱 진입점 & 라우터 등록
│   ├── models.py                  # SQLAlchemy DB 모델 (User, TokenBlacklist)
│   ├── schemas.py                 # Pydantic 데이터 검증 스키마
│   └── security.py                # JWT 생성/검증, OTP 생성, 패스워드 해싱 유틸
├── experiments/             
│   ├── measure_performance.py     # 보안성 검증용 스크립트
│   └── measure_security.py        # 성능 측정용 스크립트
├── keys/                          # 비대칭키(RS256) 저장 폴더
├── requirements.txt               # 프로젝트 의존성 목록
└── README.md                      # 프로젝트 설명서
```
