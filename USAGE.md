# gx-security 사용 가이드

SQIsoft 사업부 웹앱 보안 점검 툴킷 **gx-security**의 실전 사용법.
개요·정체성은 [README.md](README.md), 안전 수칙은 [ATTACK_SAFETY.md](ATTACK_SAFETY.md) 참고.

---

## 0. 두 가지 사용 방식

gx-security는 **CLI 독립 실행**과 **Claude Code AI 운전** 두 가지로 쓸 수 있다.

| 방식 | 언제 | 결과 |
|---|---|---|
| **AI 운전 (권장)** | 평소 점검, 오탐까지 걸러진 리포트가 필요할 때 | 정적+동적+오탐제거+4요소 리포트 자동 |
| **CLI 독립** | 빠른 후보 확인, CI 연동, 스크립트 자동화 | 후보 목록(오탐 포함, AI 검증 전) |

---

## 1. 설치 / 활성화

### 방식 A — 설치 없이 바로 (가장 간단)
Claude Code 세션에서 자연어로 호출:
> "gx-security로 `D:\SQ\sqisoft-sef-2026` 점검해줘"

### 방식 B — 플러그인으로 정식 설치 (재사용·팀 배포)
```
/plugin marketplace add bs-koo/gx-security
/plugin install gx-security@gx-security
```

### 방식 C — CLI만 (Python)
```bash
cd D:\SQ\security-plugin
python scan_all.py <소스경로>          # 정적 통합
python skills/auditing-web-application-security/scripts/audit.py <소스> --target <URL>
```
> (선택) `pip install semgrep` 하면 정적 정밀도가 올라간다. 없으면 grep 폴백으로 동작.

---

## 2. 빠른 시작 — 통합 점검 한 방

가장 쉬운 경로는 **통합 오케스트레이터** 하나다.

```bash
# 정적만 (앱 안 띄워도 됨)
python skills/auditing-web-application-security/scripts/audit.py "D:\SQ\sqisoft-sef-2026"

# 정적 + 동적 (실행 중인 로컬/스테이징 필요)
python skills/auditing-web-application-security/scripts/audit.py \
    "D:\SQ\sqisoft-sef-2026" --target "http://localhost:8080" --params id,q,search
```

또는 Claude에게:
> "gx-security로 sef-2026 전체 점검해줘 (로컬 http://localhost:8080)"
→ 스택 자동감지 → 정적 9종 → AI 오탐 제거 → 동적 발사 → **통합 4요소 리포트** (`reports/`에 저장)

---

## 3. 표준 점검 사이클 (펜테스트 흐름)

```
0. 준비    로컬 기동(./gradlew bootRun 등) + 테스트 데이터
1. 정적    audit.py / scan_all.py        → 후보 "지도"
2. 검증    AI가 코드 읽고 오탐 제거        → 확정 후보 + URL/파라미터
3. 동적    exploiting-* 실제 발사          → 악용 확정 + 증거
4. 리포트  reports/*.md (4요소 + Evidence)
5. 수정 → 6. 재점검(같은 스킬 다시) → 안 뚫리면 종료
```

---

## 4. 시나리오별 사용

| 시점 | 명령 / 한 마디 |
|---|---|
| **코드 짜는 중 / 커밋 전** | "방금 바꾼 게시판 코드 XSS·SQLi만 봐줘" (특정 스킬) |
| **PR 올리기 전** | `audit.py <소스> --target http://localhost:8080 --params ...` (해당 도메인 전체) |
| **릴리스 전** | `scan_all.py <소스>` 전체 스윕 → High 이상만 동적 검증 |
| **신규 프로젝트 온보딩** | `scan_all.py <소스>` 로 보안 부채 전체 파악 |

### 특정 취약점만 보기
```bash
# 정적 단일
python skills/detecting-sql-injection/scripts/scan_sqli.py "D:\SQ\sqisoft-sef-2026"
# 동적 단일 (실행 중 대상)
python skills/exploiting-sql-injection/scripts/attack_sqli.py "http://localhost:8080/board?id=1" --param id
```

### 일부만 통합 실행
```bash
python scan_all.py "D:\SQ\sqisoft-sef-2026" --only csrf,sqli,xss
```

### 인증·세션·JWT 동적 점검
JWT 변조·토큰 재사용·쿠키 속성을 실제로 확정하려면, 통합 오케스트레이터에 테스트 계정과 보호 엔드포인트(`--probe`)를 함께 넘긴다.
```bash
python skills/auditing-web-application-security/scripts/audit.py "D:\SQ\sqisoft-sef-2026" \
    --target http://localhost:8080 \
    --user-a-id <id> --user-a-pw <pw> \
    --probe /api/v1/users/me --json
```
- **판정 3단계** (계정/probe 조합에 따라 갈린다):
  - **`dynamic`(전체 발사)** — 로그인 계정(`--user-a-id/pw`)과 `--probe`가 모두 있을 때. JWT 변조·토큰 재사용·쿠키 속성을 실제 발사한다.
  - **`partial`(쿠키만)** — **로그인 계정(`--user-a-id/pw`)만 있고 `--probe`가 없을 때**. 로그인 응답의 Set-Cookie로 쿠키 속성만 발사하고, JWT·재사용은 정적 추정에 머문다.
  - **`static-only`(정적 추정)** — 계정이 전무하거나, **`--token-a`로 토큰만 넘길 때**. `--token-a`는 로그인 단계를 생략해 Set-Cookie가 없으므로 쿠키 검사도 건너뛴다 → `--probe`가 없으면 발사 0건으로 `static-only`다(`--probe`가 함께 있으면 JWT·재사용은 발사되어 `dynamic`). 즉 "계정만 있으면 무조건 partial"이 아니라, **partial은 실제 로그인(`--user-a-id/pw`)일 때만** 성립한다.
- **한계**: `audit.py` 경유 인증 동적은 `--probe`로 보호 엔드포인트를 **직접 지정**해야 한다(`--scan` 자동 추출은 `attack_auth.py` 단독 실행 전용). 또한 **sef-2026 로그인 프리셋**(`/api/v1/auth/login`, 토큰 경로 `data.accessToken`)을 전제로 한다. 비표준 로그인 API는 `skills/exploiting-auth-session/scripts/attack_auth.py`를 단독 실행하고 `--login-path`·`--body-template`·`--token-path`로 로그인 형식을 지정한다.
- **병렬 실행 주의(로그아웃)**: 토큰 재사용 검사는 대상 계정을 로그아웃시켜 세션을 무효화한다. 서버가 전체 세션 로그아웃(모든 기기 무효화)·refresh 회전 방식이면 같은 계정을 쓰는 다른 세션이 끊긴다. **동일 테스트 계정을 여러 프로세스(병렬 audit 등)가 동시에 사용하지 않는다.**

### SSRF/오픈 리다이렉트 동적 점검
서버측 요청 위조(SSRF)와 미검증 리다이렉트를 실제로 확정하려면, 통합 오케스트레이터에 **주입 표적**과 **테스트 계정**을 함께 넘긴다.
```bash
python skills/auditing-web-application-security/scripts/audit.py "D:\SQ\sqisoft-sef-2026" \
    --target http://localhost:8080 \
    --redirect-target "/go?u=" \
    --ssrf-target "/api/fetch?url=" \
    --user-a-id <id> --user-a-pw <pw> --json
```
- **발사 조건(표적+계정 모두 필요)**: `--redirect-target`(오픈 리다이렉트 주입점)·`--ssrf-target`(SSRF 주입점) 같은 **표적**과 계정(`--user-a-id/pw` 또는 `--token-a`)이 **모두** 있어야 실제 발사(`dynamic`)한다. 표적이나 계정이 하나라도 없으면 발사 없이 `static-only`(정적 추정)에 머문다(표적을 우선 판정). 종류를 하나만 지정하면(예: `--redirect-target`만) 지정한 종류만 발사하고 나머지는 "표적 미지정"으로 표기한다.
- **판정 방식**: `Location` 응답 헤더가 외부 호스트로 향하면 오픈 리다이렉트 취약, OOB canary URL을 주입해 콜백을 수신하면 블라인드 SSRF까지 확정한다. 모두 비파괴 GET 주입이다.
- **canary 자동 기동·종료**: SSRF 콜백용 리스너는 발사마다 **자동으로 뜨고 닫히며 127.0.0.1 루프백에만 바인딩**된다(외부 미노출). audit 경유 실행에서는 canary 호스트/포트 옵션을 노출하지 않고 기본 루프백을 그대로 쓴다.
- **원격 대상은 콜백 미수신(한계)**: canary가 127.0.0.1이므로 **대상이 audit 실행기와 동일 호스트(로컬)일 때만 콜백을 수신**한다. 원격 스테이징의 블라인드 SSRF를 확정하려면 `skills/exploiting-ssrf-and-open-redirect/scripts/attack_ssrf.py`를 단독 실행하고 `--canary-host`로 대상이 도달할 수 있는 광고 호스트를 지정한다(오픈 리다이렉트는 인밴드 Location 판정이라 이 제약과 무관하다).
- **원격 콜백 미수신 ≠ 안전(부작용 주의)**: 원격 대상에서 콜백을 못 받았다고 곧 '안전'을 뜻하지는 않는다. 주입된 `127.0.0.1` URL은 **대상 서버 자신의 loopback**을 가리키므로, 대상이 자기 로컬 전용 서비스(actuator·관리 콘솔·디버그 포트 등)로 실제 아웃바운드 요청을 시도했으나 그 결과가 audit 실행기로 돌아오지 않았을 뿐일 수 있다(대상 IDS/방화벽 로그에 SSRF 시그니처로 남을 수 있음). 도구는 대상 서버 자체가 만드는 아웃바운드 요청의 부작용까지는 통제하지 못한다.

### 경로조작·파일 업로드 동적 점검
경로조작(임의 파일 읽기)과 위험 확장자 업로드(웹쉘 발판)를 실제로 확정하려면, 통합 오케스트레이터에 **주입 표적**과 **테스트 계정**을 함께 넘긴다. 업로드는 서버에 파일을 기록하는 **파괴적** 동작이라 `--allow-destructive`를 추가로 명시해야 발사된다.
```bash
python skills/auditing-web-application-security/scripts/audit.py "D:\SQ\sqisoft-sef-2026" \
    --target http://localhost:8080 \
    --traversal-target "/download?filePath=" \
    --upload-target "/api/v1/files" --allow-destructive \
    --retrieve-base "http://localhost:8080/files" \
    --user-a-id <id> --user-a-pw <pw> --json
```
- **발사 조건(표적+계정 모두 필요)**: `--traversal-target`(경로조작 주입점)·`--upload-target`(업로드 엔드포인트) 같은 **표적**과 계정(`--user-a-id/pw` 또는 `--token-a`)이 **모두** 있어야 발사(`dynamic`)한다. 표적이나 계정이 하나라도 없으면 발사 없이 `static-only`(정적 추정)에 머문다(표적을 우선 판정). 종류를 하나만 지정하면 지정한 종류만 발사하고 나머지는 "표적 미지정 — 미검사"로 표기한다.
- **업로드 이중 게이트(파괴적 옵트인)**: 파일 업로드는 대상 서버에 마커 파일을 실제로 기록하므로, `--upload-target`이 있어도 `--allow-destructive`가 없으면 **미발사**한다. 이 게이트는 audit 레이어와 `attack_pathupload.py` 자체에 **독립적으로 이중** 존재하며, `--allow-destructive`가 없으면 audit이 `--upload-target` 자체를 자식에 넘기지 않는다. 경로조작은 읽기전용 GET이라 이 게이트와 무관하다.
- **판정 방식**: 경로조작은 응답 본문에 파일 내용 시그니처(`root:.*:0:0:`·`<web-app`·`[fonts]`)가 나오면 취약이다. 미검출이라도 응답이 2xx일 때만 방어로 보고, **non-2xx(404/403/5xx)·무응답은 방어가 아니라 "미확정(미도달/차단 추정)"**으로 표기해 엔드포인트 오지정을 방어로 오인하지 않는다. 업로드는 위험 확장자(.jsp) 마커가 2xx 수용되면 취약(Medium), `--retrieve-base`로 회수까지 성공하면 웹루트 저장으로 가중(High)한다.
- **leftover 정리(수동 삭제)**: `--allow-destructive`로 업로드가 실제 **수용(accepted)**되면 대상 서버에 마커 `.jsp` 파일이 남는다. audit 요약에 `[정리 필요] 업로드된 마커 파일: … — 서버에서 수동 삭제 권장` 안내가 노출되므로, 점검 후 해당 파일을 직접 삭제한다. 자동 삭제(`--cleanup-target`)는 제공하지 않는다(거부돼 파일이 남지 않은 경우엔 안내하지 않는다).
- **한계**: `audit.py` 경유 실행은 **sef-2026 로그인 프리셋**(`/api/v1/auth/login`, 토큰 경로 `data.accessToken`)을 전제로 한다. 비표준 로그인 API나 세밀한 옵션은 `skills/exploiting-path-traversal-upload/scripts/attack_pathupload.py`를 단독 실행한다.

---

## 5. 명령 레퍼런스

| 명령 | 용도 |
|---|---|
| `audit.py <소스> [--target URL] [--params a,b]` | **통합** 점검(정적+동적). 메인 진입점 |
| `scan_all.py <소스> [--only k1,k2] [--json]` | 정적 9종 일괄 후보 |
| `skills/detecting-*/scripts/scan_*.py <소스>` | 정적 단일 취약점 |
| `skills/exploiting-*/scripts/attack_*.py <URL> --param p` | 동적 단일 공격 |
| `tools/scope_guard.py <URL> [--authorized]` | 대상이 공격 허용 범위인지 사전 확인 |

공통 옵션: `--json`(기계 판독), `--authorized`(공인 대상 명시 승인).

---

## 6. 안전 수칙 (동적 공격 시)

- 동적은 로컬(`localhost`) 또는 전용 스테이징에만 쓴다. 운영은 코드로 차단된다.
- 테스트 데이터를 쓴다. 저장형 XSS 마커 등이 DB에 남을 수 있다.
- 평소에는 정적만 돌리고(완전 안전), 동적은 확인이 필요한 취약점에만 `--target`을 지정한다.
- 사설망 IP(10.x/172.16/192.168)는 기본 차단된다. 사내 스테이징이 사설망이면 `SECURITY_PLUGIN_ALLOW_HOSTS`에 호스트를 등록하거나 `SECURITY_PLUGIN_ALLOW_PRIVATE=1`로 허용한다.
- 공인 대상은 `SECURITY_PLUGIN_AUTHORIZED=1` 과 `--authorized`를 동시에 충족할 때만 허용된다(소유자 책임).

전체 정책: [ATTACK_SAFETY.md](ATTACK_SAFETY.md)

---

## 7. 산출물(리포트) 읽는 법

`reports/*.md`의 각 취약점은 4요소로 기록된다:

1. **① 취약한 점(What)** — 무엇이 취약한가
2. **② 취약한 이유(Why)** — 왜 위험한가
3. **③ 뚫리는 방법(How)** — 어떻게 공격당하나 (동적 확정 시 실제 페이로드·증거)
4. **④ 해결방법(Fix)** — 구체적 수정 코드

심각도(Critical/High/Medium/Low) 순으로 정렬되며, "의도된 예외"·"오탐 제외"도 함께 기록된다.

---

## 8. FAQ

**Q. semgrep이 꼭 필요한가?**
A. 아니다. 없으면 grep 폴백으로 동작한다(오탐이 다소 늘지만 AI 검증이 거른다). 설치하면 정밀도가 오른다.

**Q. 앱을 안 띄워도 쓸 수 있나?**
A. 정적은 소스만 있으면 된다. 동적(`exploiting-*`, `--target`)만 실행 중인 앱이 필요하다.

**Q. 운영에 실수로 쏠까 걱정된다.**
A. `scope_guard`가 `prod`/`www`/공인 대상과 사설망을 기본 차단하고, IP 위장(정수·IPv6 매핑)도 거른다. 사내 스테이징만 6번처럼 명시 등록해 쓴다.

**Q. 오탐이 많다.**
A. CLI 단독은 1차 후보라 오탐이 포함된다. **Claude Code에서 AI 운전 방식**으로 쓰면 코드 컨텍스트로 오탐을 걸러 확정 취약점만 리포트한다.

---

## 9. 구조적 한계 (동적 공격 엔진)

동적(침투) 엔진에는 다음 한계가 있어, 발사 전에 표적을 직접 준비해야 한다:

1. **크롤링/엔드포인트 자동탐색이 없다.** 공격할 URL·파라미터를 직접 지정해야 하며, 앱의 엔드포인트를 스스로 수집하지 않는다.
2. **GET·form-urlencoded POST만 지원한다.** 이 두 방식의 요청에만 페이로드를 주입한다.
3. **JSON 바디 주입은 불가하다.** `application/json` 요청 본문에는 페이로드를 삽입하지 못한다.
