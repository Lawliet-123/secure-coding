# Tiny Second-hand Shopping Platform

시큐어 코딩을 적용한 중고거래 플랫폼입니다. Flask + Flask-SocketIO + SQLite 기반으로 구현했습니다.

## 구현 기능

### 유저 관리
- 회원 가입 / 로그인 / 로그아웃
- 사용자 조회 (프로필 페이지)
- 마이페이지 (소개글 수정, 비밀번호 변경)

### 상품 관리
- 상품 등록 (이미지 업로드 포함)
- 등록 상품 관리 (수정 / 삭제)
- 상품 조회 및 상세 페이지
- **상품 검색** (상품명·설명 대상)

### 유저 소통
- 실시간 전체 채팅 (WebSocket)
- **1:1 채팅** (대화 이력 DB 저장)

### 악성 유저 필터링
- 유저 / 상품 신고 기능 (사유 필수)
- 신고 3회 누적 시 상품 자동 차단, 유저 자동 휴면 전환

### 송금
- **유저 간 송금** (비밀번호 재확인, 잔액 검증, 거래 내역 조회)

### 관리자
- **관리자 페이지** (사용자 휴면/활성 전환, 상품 차단/삭제, 신고 내역 조회)

## 환경 설정

### 요구 사항
- Ubuntu 20.04+ (WSL / VMware / VirtualBox)
- Python 3.10+
- miniconda 또는 venv

### 설치

```bash
git clone https://github.com/<본인계정>/secure-coding.git
cd secure-coding

conda create -n secure-coding python=3.10 -y
conda activate secure-coding

pip install -r requirements.txt
```

### 환경변수 설정 (권장)

`SECRET_KEY`를 지정하지 않으면 실행할 때마다 무작위로 생성되어 기존 세션이 무효화됩니다.

```bash
export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export ADMIN_PASSWORD="원하는관리자비밀번호"
export HTTPS_ONLY=1     # HTTPS 환경에서만 설정 (Secure 쿠키 활성화)
```

## 실행 방법

```bash
python app.py
```

브라우저에서 `http://localhost:5000` 접속.

### 외부 공개 (ngrok)

```bash
ngrok http 5000
```

출력된 HTTPS 주소로 접속합니다. ngrok 사용 시 `export HTTPS_ONLY=1`을 함께 설정하세요.

### 관리자 계정

최초 실행 시 `admin` 계정이 자동 생성됩니다. 비밀번호는 `ADMIN_PASSWORD` 환경변수 값이며, 미지정 시 기본값 `Admin!2345`입니다. **운영 시 반드시 변경하세요.**

## 데이터베이스 스키마

| 테이블 | 주요 컬럼 |
|---|---|
| `user` | id, username(UNIQUE), password(해시), bio, balance, is_admin, status, failed_login |
| `product` | id, title, description, price, seller_id(FK), image, status |
| `report` | id, reporter_id, target_id, target_type, reason (reporter_id+target_id UNIQUE) |
| `transfer` | id, sender_id, receiver_id, amount, memo |
| `dm` | id, room, sender_id, receiver_id, content |

## 적용한 보안 조치 요약

| 위협 | 대응 |
|---|---|
| SQL Injection | 전 쿼리 파라미터 바인딩, LIKE 와일드카드 이스케이프 |
| XSS | Jinja2 자동 이스케이프, 클라이언트 `textContent` 사용, CSP 헤더 |
| CSRF | Flask-WTF 전역 CSRF 토큰, SameSite=Lax |
| 인증 우회 / 권한 상승 | 관리자 여부 DB 재조회, `login_required`/`admin_required` |
| IDOR | 상품 수정·삭제 시 소유자 검증 |
| 브루트포스 | Flask-Limiter 요청 제한, 실패 횟수 기록 |
| 세션 탈취 | HttpOnly / Secure / SameSite 쿠키, 세션 만료, 로그인 시 세션 재생성 |
| 비밀번호 유출 | Werkzeug PBKDF2 해시(솔트 포함) 저장 |
| 파일 업로드 | 확장자 화이트리스트, UUID 파일명 재생성, 3MB 크기 제한 |
| 송금 조작 | 트랜잭션 + 조건부 UPDATE로 경쟁 조건 차단, 음수·비정수 입력 거부 |
| 정보 노출 | `debug=False`, 커스텀 에러 페이지, 계정 열거 방지 메시지 |
| WebSocket 위조 | 소켓 인증 검증, 발신자명 서버 결정, DM 방 이름 서버 계산 |

상세 내용은 제출 보고서를 참고하세요.

## 라이선스

교육 목적 과제 프로젝트입니다.
