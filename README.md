# jwt-secure-auth
JWT 기반 인증 시스템 보안 강화 및 공격/방어 실습용 FastAPI 프로젝트

## 개요
FastAPI로 구현한 JWT 인증 예제(Access/Refresh 토큰) + 공격 재현(토큰 탈취, 알고리즘 혼동) 및 방어(Blacklist, RS256, MFA 데모).
   
## 주요 기능
- 회원가입/로그인 (bcrypt 해시)
- Access / Refresh Token 발급 및 검증
- Refresh 토큰 DB 저장 및 회전(Token Rotation)
- 로그아웃 시 토큰 무효화(Blacklist)
- RS256(비대칭) 지원 전환 예제
- 공격 재현 스크립트 및 방어 실험 기록

## 빠른 시작 (개발)
1. 환경 준비
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
   
2. 환경변수 복사
```bash
cp .env.example .env
# .env 파일에서 SECRET_KEY, DB URL, PRIVATE_KEY_PATH 등을 설정
```
   
3. 실행
```bash
uvicorn app.main:app --reload
```

## 기술 스택
- Python 3.10+
- FastAPI, Uvicorn
- python-jose (JWT)
- passlib (bcrypt)
- SQLAlchemy (데이터 저장)
