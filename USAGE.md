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
