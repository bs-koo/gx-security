# gx-security 결함 제거·공통화 실행 계획 (Remediation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 전수조사에서 확인된 결함(판정 오류·recall 구멍·문서 불일치·검증 자동화 부재·동적 엔진 이식성)을 우선순위·의존성 순으로 제거해, 정적 진단은 전 사업부 공통, 동적 침투는 다중 스택으로 확장한다.

**Architecture:** 6개 Phase. Phase 0(안전망: CI+골든셋)을 먼저 세워 이후 모든 수정이 회귀 검증되게 한다 → Phase 1(반나절 quick fix) → Phase 2(동적 판정 강화) → Phase 3(정적 recall) → Phase 4(dyn_session 이식성, 별도 서브플랜) → Phase 5(스키마 균일·위생).

**Tech Stack:** Python 3(unittest, requests, PyYAML), semgrep(선택), GitHub Actions, semgrep YAML 룰.

## Global Constraints

- 표준 라이브러리 + 기존 의존성(`requests`, `PyYAML`)만. 새 서드파티 의존성 추가 금지(semgrep·sqlmap은 선택 도구로 유지).
- 테스트는 `unittest`로 작성(기존 185개와 동일 프레임워크). 네트워크는 mocking, live 대상 불필요.
- 모든 커밋은 원자적. 커밋 메시지 한국어, 기존 컨벤션(`fix:`/`feat:`/`test:`/`ci:`/`docs:`) 따름.
- 안전 불변식 절대 훼손 금지: 모든 `attack_*.py`는 발사 전 `assert_in_scope` 호출 유지, 비파괴 기본 유지, fail-closed 유지.
- 코드 수정 시 대응 테스트를 같은 커밋에 포함. 문서(SKILL.md) 수정은 실제 코드 동작과 일치시킨다.
- 검증 명령: `python -m unittest discover -s tests -p "test_*.py"` (전체), 개별은 `python -m unittest tests.test_x.Class.method -v`.

---

## Phase 0 — 안전망 (CI + 스캐너 골든셋)

*이후 모든 수정이 자동 검증되도록 먼저 세운다. 코드 로직 변경 없음.*

### Task 0.1: GitHub Actions CI 추가

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: 워크플로 파일 작성**

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install deps
        run: pip install requests PyYAML
      - name: Run unittest suite
        run: python -m unittest discover -s tests -p "test_*.py" -v
```

- [ ] **Step 2: 로컬에서 동일 명령 통과 확인**

Run: `python -m unittest discover -s tests -p "test_*.py"`
Expected: `Ran 185 tests ... OK` (현재 통과 상태 유지 확인)

- [ ] **Step 3: 커밋**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: GitHub Actions에 unittest 스위트 추가"
```

### Task 0.2: 스캐너 골든셋 픽스처 테스트 (recall 회귀 방지)

각 스캐너가 "취약 픽스처는 후보로 잡고, 안전 픽스처는 안 잡는가"를 grep-fallback 기준으로 검증한다. 우선 SQLi·CSRF·XSS 3종으로 시작(가장 recall 이슈가 큰 클래스), 이후 6종 확장.

**Files:**
- Create: `tests/fixtures/vuln/BoardMapper.xml`, `tests/fixtures/safe/BoardMapper.xml`
- Create: `tests/test_scanner_goldenset.py`

- [ ] **Step 1: 취약/안전 픽스처 작성**

`tests/fixtures/vuln/BoardMapper.xml`:
```xml
<mapper><select id="find">SELECT * FROM board WHERE title = '${title}'</select></mapper>
```
`tests/fixtures/safe/BoardMapper.xml`:
```xml
<mapper><select id="find">SELECT * FROM board WHERE title = #{title}</select></mapper>
```

- [ ] **Step 2: 실패 테스트 작성**

```python
import os, subprocess, sys, json, unittest
_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

def _scan(scanner_rel, target):
    p = subprocess.run([sys.executable, os.path.join(_ROOT, scanner_rel), target, "--json"],
                       capture_output=True, text=True, encoding="utf-8")
    return json.loads(p.stdout)

class TestSqliGoldenset(unittest.TestCase):
    S = "skills/detecting-sql-injection/scripts/scan_sqli.py"
    def test_vuln_dollar_is_flagged(self):
        r = _scan(self.S, os.path.join(_ROOT, "tests/fixtures/vuln"))
        self.assertGreaterEqual(r["candidate_count"], 1)
    def test_safe_hash_not_flagged(self):
        r = _scan(self.S, os.path.join(_ROOT, "tests/fixtures/safe"))
        self.assertEqual(r["candidate_count"], 0)
```

- [ ] **Step 3: 실행해 현재 상태 확인**

Run: `python -m unittest tests.test_scanner_goldenset -v`
Expected: `test_safe_hash_not_flagged` FAIL 가능(현행 MyBatis 폴백 `(?!#)` 버그로 `#{}`도 잡힐 수 있음) → Task 1.4에서 해소. vuln 테스트는 PASS.

- [ ] **Step 4: 커밋(테스트만, red 상태 기록)**

```bash
git add tests/fixtures tests/test_scanner_goldenset.py
git commit -m "test: 스캐너 골든셋 픽스처(SQLi) — safe #{} 회귀 가드"
```

---

## Phase 1 — Quick Fix (반나절, 판정 신뢰·문서 정합)

### Task 1.1: sqlmap `[CRITICAL]` 오판정 수정 (High)

**Files:**
- Modify: `skills/exploiting-sql-injection/scripts/attack_sqli.py:358-370`
- Test: `tests/test_attack_sqli_verdict.py` (신규)

**문제:** `[CRITICAL]`을 취약 마커로 취급 → sqlmap의 `[CRITICAL] all tested parameters do not appear to be injectable`·연결오류도 `exploited=True`로 뒤집힘.

- [ ] **Step 1: 실패 테스트 작성**

```python
import unittest
from skills.exploiting_sql_injection.scripts import attack_sqli  # 경로 임포트 불가 시 아래 헬퍼 방식 사용
# 임포트가 어려우면 판정 로직을 _classify_sqlmap(output)->bool 헬퍼로 추출 후 테스트한다.
class TestSqlmapVerdict(unittest.TestCase):
    def test_not_injectable_is_safe(self):
        out = "[CRITICAL] all tested parameters do not appear to be injectable"
        self.assertFalse(attack_sqli._classify_sqlmap(out))
    def test_vulnerable_is_true(self):
        out = "sqlmap identified the following injection point"
        self.assertTrue(attack_sqli._classify_sqlmap(out))
```

- [ ] **Step 2: 판정 로직을 헬퍼로 추출하고 `[CRITICAL]` 제거**

`attack_sqli.py`에 헬퍼 추가하고 `_run_sqlmap`에서 호출:
```python
_SQLMAP_POSITIVE = ["is vulnerable", "sqlmap identified the following injection point",
                    "the back-end dbms is"]
_SQLMAP_NEGATIVE = ["do not appear to be injectable", "unable to connect to the target",
                    "all tested parameters"]

def _classify_sqlmap(output: str) -> bool:
    low = output.lower()
    if any(n in low for n in _SQLMAP_NEGATIVE):
        return False
    return any(p in low for p in _SQLMAP_POSITIVE)
```
`_run_sqlmap` 내부: `exploited = _classify_sqlmap(output)` 로 교체(기존 `any(k in output ...)` 삭제).

- [ ] **Step 3: 테스트 통과 확인**

Run: `python -m unittest tests.test_attack_sqli_verdict -v`
Expected: PASS 2건.

- [ ] **Step 4: 커밋**

```bash
git add skills/exploiting-sql-injection/scripts/attack_sqli.py tests/test_attack_sqli_verdict.py
git commit -m "fix: sqlmap [CRITICAL] 로그레벨을 취약으로 오판하던 판정 수정 (거짓양성 제거)"
```

### Task 1.2: 구 SKILL의 scope 서술을 강화 코드에 맞게 정정 (Med, 안전인식)

**Files:**
- Modify: `skills/exploiting-sql-injection/SKILL.md:67-70`
- Modify: `skills/exploiting-xss-vulnerabilities/SKILL.md:67-70`

**문제:** "사설 IP(10/172.16/192.168)·`*staging*`/`*dev*`/`*qa*` 자동 허용"이라 기재됐으나 실제 `scope_guard.py:127-131,140`은 사설 IP를 기본 차단(needs-authorization), staging/dev/qa 부분일치 미허용.

- [ ] **Step 1: sql-injection SKILL 허용 대상 문단 교체**

허용 대상을 실제 정책으로:
```markdown
**허용 대상(scope_guard 실제 정책):**
- 자동 허용: loopback(127.x, `2130706433` 등 정수표기 포함) / localhost / RFC 예약 TLD(`.localhost`·`.local`·`.test`·`.example`·`.invalid`)
- 조건부 허용: 사설망(10.x/172.16/192.168)은 `SECURITY_PLUGIN_ALLOW_PRIVATE=1`, 사내 스테이징 도메인은 `SECURITY_PLUGIN_ALLOW_HOSTS`에 등록해야 통과(기본 차단)
- 항상 차단: `prod`/`production`/`www.`, 링크로컬/메타데이터(169.254.x), IP 위장
- 공인 대상: `--authorized` + `SECURITY_PLUGIN_AUTHORIZED=1` 동시 충족 시만
```

- [ ] **Step 2: xss SKILL의 동일 표(자동 허용 행) 교체**

`| 127.x, 10.x, 192.168.x, localhost | 자동 허용 |`·`| *.staging.*, *.dev.*, *.local | 자동 허용 |` 행을 위 정책과 일치하도록 수정(10.x/192.168/staging/dev는 "조건부(env 등록 시)"로, `.local`만 자동 허용 유지).

- [ ] **Step 3: 검증 — 실제 게이트와 대조**

Run: `python tools/scope_guard.py "http://10.0.0.5"` → `[권한 필요]` 출력 확인(문서가 이 동작과 일치하는지 육안 대조).

- [ ] **Step 4: 커밋**

```bash
git add skills/exploiting-sql-injection/SKILL.md skills/exploiting-xss-vulnerabilities/SKILL.md
git commit -m "docs: 구 SKILL 2종 scope 서술을 강화된 scope_guard 실제 정책과 정합"
```

### Task 1.3: SKILL 문서 드리프트 3건 정정 (Low)

**Files:**
- Modify: `skills/detecting-file-upload-vulnerabilities/SKILL.md:52-63` (명령이 `### 0단계` 밑에 오배치 → `### 1단계`로 이동)
- Modify: `skills/detecting-path-traversal/SKILL.md` (동일 오배치 수정)
- Modify: `skills/detecting-auth-session-weaknesses/SKILL.md:12-27` (`tags:`에 `cwe-798` 추가 — `cwe:`엔 이미 있음)
- Modify: `skills/detecting-sensitive-data-exposure/SKILL.md:50` (프로즈 "정규식 폴백" → 코드 방출값 "grep-fallback"으로 통일)
- Modify: `skills/detecting-ssrf-and-open-redirect/SKILL.md` (동일 용어 통일)

- [ ] **Step 1: 5개 파일의 해당 라인 수정(위 명세대로)**
- [ ] **Step 2: 검증** — `rtk grep -n "grep-fallback\|cwe-798" skills/detecting-*/SKILL.md` 로 반영 확인
- [ ] **Step 3: 커밋**

```bash
git add skills/detecting-*/SKILL.md
git commit -m "docs: SKILL 드리프트 정정(명령 헤딩 오배치·cwe-798 태그·폴백 용어 통일)"
```

### Task 1.4: MyBatis 폴백 무효 룩어헤드 수정 (Low, 과탐)

**Files:**
- Modify: `skills/detecting-sql-injection/scripts/scan_sqli.py:102`
- Test: `tests/test_scanner_goldenset.py` (Phase 0.2의 safe 테스트가 여기서 green)

**문제:** `_MYBATIS_DOLLAR = re.compile(r'\$\{(?!#)[^}]+\}')` — 안전형 `#{}`는 `$`로 시작 안 해 어차피 매치 안 되므로 `(?!#)`는 무의미. 목적은 "`${}`만, `#{}` 제외"인데 정규식이 `${}`를 이미 정확히 매치하므로 `(?!#)` 제거가 정답(의미 불변·혼동 제거). 단 `${#...}` 같은 OGNL도 위험이라 제거해도 무방.

- [ ] **Step 1: 정규식 정리**

```python
# MyBatis XML ${}: 파라미터 문자열 보간(취약). #{}(바인딩)는 $로 시작 안 해 자연히 제외됨.
_MYBATIS_DOLLAR = re.compile(r'\$\{[^}]+\}')
```

- [ ] **Step 2: 골든셋 safe 테스트 통과 확인**

Run: `python -m unittest tests.test_scanner_goldenset.TestSqliGoldenset -v`
Expected: `test_safe_hash_not_flagged` PASS(이제 `#{}`는 확실히 미매치), `test_vuln_dollar_is_flagged` PASS 유지.

- [ ] **Step 3: 커밋**

```bash
git add skills/detecting-sql-injection/scripts/scan_sqli.py
git commit -m "fix: MyBatis 폴백 정규식 무효 룩어헤드 제거(의미 불변·혼동 제거)"
```

### Task 1.5: 스캐너 백업 폴더 제외(.dev/.omc/.humanize) (Low, 노이즈)

**Files:**
- Modify: 9개 `skills/detecting-*/scripts/scan_*.py`의 `os.walk` 제외 튜플 2곳(`detect_stacks`·`run_fallback`)
- Test: `tests/test_scanner_ignore.py` (신규)

**문제:** 제외목록 `(".git","node_modules","build","target","dist",".gradle")`에 SQIsoft 관례 폴더(`.dev`·`.omc`·`.humanize`)가 없어 타깃 내 백업 사본을 이중 스캔(스모크에서 Gseed `.dev\checkpoint-...` 스캔 확인).

- [ ] **Step 1: 실패 테스트 작성** (`.dev` 하위 취약 픽스처가 후보에서 빠지는지)

```python
# tests/fixtures/with_backup/.dev/BoardMapper.xml 에 ${} 취약 픽스처를 두고,
# scan_sqli가 .dev를 건너뛰어 candidate_count == 0 임을 검증
```

- [ ] **Step 2: 9개 스캐너의 제외 튜플 일괄 교체**

각 파일 두 곳:
```python
dirs[:] = [d for d in dirs if d not in
           (".git", "node_modules", "build", "target", "dist", ".gradle",
            ".dev", ".omc", ".humanize", ".idea", ".vscode")]
```

- [ ] **Step 3: 전체 스위트 + 신규 테스트 통과 확인**

Run: `python -m unittest discover -s tests -p "test_*.py"`
Expected: OK.

- [ ] **Step 4: 커밋**

```bash
git add skills/detecting-*/scripts/scan_*.py tests/test_scanner_ignore.py tests/fixtures/with_backup
git commit -m "fix: 스캐너가 .dev/.omc/.humanize 백업 폴더를 이중 스캔하던 문제 제외"
```

### Task 1.6: sqlmap 출력 디렉토리 크로스플랫폼화 + access `--allow-destructive` 명확화 (Low)

**Files:**
- Modify: `skills/exploiting-sql-injection/scripts/attack_sqli.py:336`
- Modify: `skills/exploiting-broken-access-control/scripts/attack_access.py:182-183`

- [ ] **Step 1: sqlmap output-dir을 tempfile로**

```python
import tempfile
# cmd 리스트에서:
"--output-dir", os.path.join(tempfile.gettempdir(), "sqlmap_sqisoft"),
```
(`/tmp` 하드코딩 제거 — Windows 대응)

- [ ] **Step 2: access의 무동작 플래그를 정직하게 표기**

`attack_access.py:182-183`의 문구를 "미구현"임이 드러나게:
```python
if args.allow_destructive and not args.json:
    print("[!] 참고: 이 스킬은 쓰기(PUT/DELETE) 발사를 아직 구현하지 않았습니다 — "
          "--allow-destructive는 현재 무동작입니다(GET 비파괴 확정만 수행).")
```

- [ ] **Step 3: 회귀 확인 + 커밋**

Run: `python -m unittest tests.test_attack_access -v` → OK
```bash
git add skills/exploiting-sql-injection/scripts/attack_sqli.py skills/exploiting-broken-access-control/scripts/attack_access.py
git commit -m "fix: sqlmap output-dir tempfile화(Windows) + access allow-destructive 무동작 명시"
```

---

## Phase 2 — 동적 판정 강화 (거짓양성 축소)

### Task 2.1: BFLA에 무토큰 대조 오라클 추가 (Med)

**Files:**
- Modify: `skills/exploiting-broken-access-control/scripts/attack_access.py:63-74` (`run_bfla`)
- Test: `tests/test_attack_access.py` (케이스 추가)

**문제:** `vulnerable = status // 100 == 2` 뿐 — 인증조차 없는 공개 엔드포인트를 "역할우회"로 오탐. auth-session의 양방향 대조 패턴을 BFLA에 적용한다.

**Interfaces:**
- Produces: `run_bfla(base_url, target, normal_token) -> dict` — 반환에 `anon_status`, `vulnerable`(anon이 이미 2xx면 False) 포함.

- [ ] **Step 1: 실패 테스트 작성(무토큰 2xx면 취약 아님)**

```python
# dyn_session.request를 monkeypatch: anon(token=None)=200, user=200 이면 vulnerable False,
# anon=401, user=200 이면 vulnerable True 를 검증
```

- [ ] **Step 2: run_bfla에 anon 대조 추가**

```python
def run_bfla(base_url, target, normal_token):
    """무토큰(anon)과 일반토큰을 대조: anon 거부(non-2xx)인데 일반토큰 2xx여야 역할우회 취약."""
    url = base_url.rstrip("/") + target["path"]
    anon = dyn_session.request("GET", url, token=None)
    r = dyn_session.request("GET", url, token=normal_token)
    anon_2xx = anon["status"] // 100 == 2
    user_2xx = r["status"] // 100 == 2
    return {
        "kind": "bfla", "method": "GET", "path": target["path"],
        "status": r["status"], "anon_status": anon["status"],
        "vulnerable": user_2xx and not anon_2xx,
        "note": ("공개 엔드포인트(anon도 2xx) — 역할우회 아님" if anon_2xx else None),
        "evidence": {"requester": "일반 사용자 토큰", "url": url,
                     "http_status": r["status"], "anon_http_status": anon["status"]},
    }
```

- [ ] **Step 3: 테스트 통과 + 전체 회귀**

Run: `python -m unittest tests.test_attack_access -v`
Expected: 신규 2건 PASS, 기존 유지.

- [ ] **Step 4: 커밋**

```bash
git add skills/exploiting-broken-access-control/scripts/attack_access.py tests/test_attack_access.py
git commit -m "fix: BFLA에 무토큰 대조 오라클 추가(공개 엔드포인트 거짓양성 제거)"
```

### Task 2.2: SQLi time-based 베이스라인 대조 + 재확인 (Med)

**Files:**
- Modify: `skills/exploiting-sql-injection/scripts/attack_sqli.py:110-125,291-312`
- Test: `tests/test_attack_sqli_time.py` (신규)

**문제:** 베이스라인 없는 `elapsed >= 2.5s` 단발 → 느린 서버·지터에 거짓양성. Oracle 페이로드 누락.

- [ ] **Step 1: 실패 테스트 작성(느린 베이스라인이면 미확정)**

```python
# _send를 monkeypatch: 베이스라인 3.0s, sleep 페이로드 3.2s → delta<임계 → 취약 아님
# 베이스라인 0.2s, sleep 3.2s → delta≥임계 → 취약(재확인도 지연) 을 검증
```

- [ ] **Step 2: 베이스라인 측정 + 델타 판정 + 재확인 도입**

```python
_SLEEP_SECONDS = 3          # 페이로드가 지시하는 지연
_SLEEP_DELTA = 2.0          # 베이스라인 대비 최소 추가 지연(초)

def _baseline(target, param, method, base_data, samples=2):
    times = []
    for _ in range(samples):
        r = _send(target, param, "1", method, base_data, timeout=15)
        if r is None:
            return None
        times.append(r[1])
    return max(times)

# _try_time_based 내부: 베이스라인 확보 후, elapsed >= baseline + _SLEEP_DELTA 이고
# 동일 페이로드 재발사도 임계 초과할 때만 확정(1회성 지터 배제).
```
`_TIME_PAYLOADS`에 Oracle 추가:
```python
    ("oracle", "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--"),
    ("oracle", "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)"),
```

- [ ] **Step 3: 테스트 통과 + 전체 회귀** → **Step 4: 커밋**

```bash
git commit -am "fix: SQLi time-based 베이스라인 대조+재확인 도입, Oracle 페이로드 추가(거짓양성 축소)"
```

### Task 2.3: 파일 업로드 판정 문구 정합 (Low)

**Files:**
- Modify: `skills/exploiting-path-traversal-upload/scripts/attack_pathupload.py:135` 부근

**문제:** `vulnerable = accepted(2xx)`라 서버가 200 주고 뒤에서 격리/개명하는 경우 과대보고. 등급은 이미 회수성공=High/불명=Medium로 나뉘므로, `vulnerable` 플래그 대신 `accepted`+`retrievable`을 렌더가 그대로 쓰도록 유지하되, 2xx-only 케이스는 리포트 문구를 "수용됨(웹루트 저장 미확인) — 서버측 후처리 확인 필요"로 명확화.

- [ ] **Step 1: 해당 finding에 `retrievable` 미확인 시 note 추가** → **Step 2: 관련 테스트 갱신** → **Step 3: 커밋**

```bash
git commit -am "fix: 업로드 2xx-only 판정에 웹루트 저장 미확인 note 추가(과대보고 완화)"
```

---

## Phase 3 — 정적 recall 보강 (semgrep 모드 구멍)

### Task 3.1: CSRF "토큰 없는 POST 폼" semgrep 룰 추가 (Med)

**Files:**
- Modify: `skills/detecting-csrf-vulnerabilities/rules/csrf.yml` (룰 1개 추가)
- Test: `tests/test_rules.py`(구조 린트가 자동 커버) + 골든셋 확장

**문제:** semgrep 모드에서 POST 폼 후보가 룰로 앵커되지 않아, grep-fallback보다 recall이 낮다. 폴백과 동일 신호를 semgrep에도 둔다(needs-context 등급).

- [ ] **Step 1: 룰 추가(csrf.yml 말미)**

```yaml
  - id: sqisoft-jsp-post-form-needs-csrf-review
    languages: [generic]
    severity: INFO
    paths:
      include: ["*.jsp", "*.html"]
    message: >-
      POST form입니다. CSRF 토큰(hidden 필드) 부재는 음성 패턴이라 룰로 단정할 수 없습니다 —
      2단계 AI 검증에서 토큰/전역 CSRF 필터(CSRFGuard 등) 유무를 전수 확인하세요.
    metadata:
      cwe: "CWE-352"
      owasp: "A01:2021"
      stack: jsp-legacy
      confidence: needs-context
    pattern-regex: '<form\b[^>]*\bmethod\s*=\s*["'']?post'
```

- [ ] **Step 2: 룰 구조 린트 + id 유일성 통과 확인**

Run: `python -m unittest tests.test_rules -v`
Expected: OK(신규 id 유일, 스키마 유효).

- [ ] **Step 3: 커밋**

```bash
git add skills/detecting-csrf-vulnerabilities/rules/csrf.yml
git commit -m "feat: CSRF POST폼 semgrep 룰 추가(semgrep↔폴백 recall 격차 해소)"
```

### Task 3.2: XSS AST 룰 보강(가능 범위) (Med)

**Files:**
- Modify: `skills/detecting-xss-vulnerabilities/rules/xss.yml`

**문제:** 9룰 중 8룰이 generic-regex라 semgrep이 이스케이프 컨텍스트를 못 봄. JSP scriptlet `<%= request.getParameter(...) %>`·Spring `@ResponseBody` String 반환 등 AST로 표현 가능한 것부터 java/jsp AST 룰로 승격한다. (전부 AST화는 불가 — 목표는 "핵심 반사 경로 몇 개를 컨텍스트 인지 룰로".)

- [ ] **Step 1: java AST 룰 1~2개 추가**(예: `$RESP.getWriter().print($REQ.getParameter(...))`) → **Step 2: 린트 통과** → **Step 3: 커밋**

```bash
git commit -am "feat: XSS 핵심 반사 경로 java AST 룰 보강(generic-regex 의존 축소)"
```

---

## Phase 4 — dyn_session 이식성 (동적 엔진 공통화) — **별도 서브플랜 권장**

> 이 Phase는 규모가 커 자체로 하나의 프로젝트다. 여기서는 설계·인터페이스·태스크 골격을 제시하고, 실제 구현은 `docs/superpowers/plans/2026-07-XX-dyn-session-portability.md`로 분리 작성 후 착수한다. **동적 침투를 "전 사업부 공통"으로 만드는 핵심 전제.**

**문제(전수조사 확인):** `dyn_session`이 (1) 로그인 JSON 바디 전용(`:56-62`), (2) 인증 Bearer 헤더 전용(`:127-128`)이라 form-urlencoded 로그인·세션 쿠키(JSESSIONID) 기반 JSP 레거시를 검증 못 한다. frontmatter는 jsp-legacy를 표방하나 동적 엔진은 실질 JWT-Bearer 전용.

**설계 방향:**
1. **인증 모드 추상화** — `AuthMode = {"bearer", "cookie"}`. `request()`가 토큰이면 `Authorization: Bearer`, 쿠키세션이면 `requests.Session` 쿠키 jar를 재사용.
2. **로그인 인코딩 선택** — `login(..., form_encoded=False)`: True면 `requests.post(url, data=body)`(application/x-www-form-urlencoded), False면 현행 `json=body`.
3. **세션 상태 보존** — `requests.Session()` 도입: 로그인 시 Set-Cookie를 jar에 저장하고 이후 `request()`가 동일 세션으로 발사(JSESSIONID 유지). Bearer 경로는 하위호환(토큰 인자 우선).

**Interfaces (later tasks가 의존):**
- `create_session() -> requests.Session`
- `login(base_url, login_path, cred, *, form_encoded=False, token_json_path="data.accessToken", session=None) -> {"token": str|None, "session": Session, "set_cookie": str}`
- `request(method, url, *, token=None, session=None, ...) -> {status, body, headers, elapsed}` (token 없고 session 있으면 쿠키 인증)

**Task 골격(서브플랜에서 각각 TDD로 전개):**
- [ ] 4.1: `request()`에 `session` 파라미터 + 쿠키 인증 경로 추가(Bearer 하위호환 유지, 회귀 테스트)
- [ ] 4.2: `login()`에 `form_encoded` + `session` 지원(form 로그인 응답에서 세션 확립)
- [ ] 4.3: 토큰 없이 세션쿠키만으로 인증되는 로그인(`token=None` 허용) 계약 테스트
- [ ] 4.4: `attack_access`/`attack_auth`/`attack_ssrf`/`attack_pathupload`에 `--auth-mode {bearer,cookie}`·`--form-login` 플래그 배선
- [ ] 4.5: JSP 레거시(예: Gseed) 대상 통합 스모크(로컬 기동 시) + USAGE.md 레거시 사용법 추가
- [ ] 4.6: sqli/xss 익스플로잇터에 로그인/세션 옵션 부여(인증 뒤 엔드포인트 검증 가능화)

**완료 정의:** JSESSIONID 세션쿠키 기반 JSP 앱에 로그인→보호 엔드포인트 발사가 성립하고, 기존 Bearer 경로 회귀 0.

---

## Phase 5 — 스키마 균일화 + 위생 (유지보수성)

### Task 5.1: 후보 객체 스키마 균일화

**Files:**
- Modify: 9개 `scan_*.py` (선택 필드 표준화)
- Create: `skills/_common/candidate.py` (공유 스키마 헬퍼, 선택)

**문제:** `rule_summary`(D 패밀리만)·`confidence`(ssrf만)·`severity`(secrets만)로 후보 스키마가 4 authoring family로 갈림 → 상위 집계기/AI 파서가 균일 스키마 가정 시 취약.

- [ ] **Step 1: 공통 최소 스키마 확정**(`{file,line,rule_id,stack,snippet, confidence?, severity?}`), 선택 필드는 있으면-쓰고-없으면-무시 계약을 `scan_all.py`·오케스트레이터에 명문화
- [ ] **Step 2: 9종이 `confidence`를 일관 방출하도록 보강(없던 스캐너에 기본값)** → **Step 3: 스키마 계약 테스트 추가** → **Step 4: 커밋**

### Task 5.2: subprocess 인코딩 고정(7종) + XSS Playwright 문서 정정

**Files:**
- Modify: 7개 `scan_*.py`의 semgrep subprocess에 `encoding="utf-8"` 명시(D 패밀리 2종은 이미 있음)
- Modify: `skills/exploiting-xss-vulnerabilities/SKILL.md:142-147` (실제 MCP 도구 `browser_fill_form`/`browser_type`/ref기반 `browser_click`으로 예시 교체)

- [ ] **Step 1: 7종 subprocess 인코딩 명시** → **Step 2: XSS SKILL Playwright 예시를 실제 도구 시그니처로 교체** → **Step 3: 전체 회귀 + 커밋**

### Task 5.3: 심각도 루브릭 통일

**Files:**
- Create: `docs/severity-rubric.md` (Critical/High/Medium/Low 판정 기준 1장)
- Modify: 9개 `references/stack-patterns.md`에 공통 루브릭 링크

- [ ] **Step 1: 범용 루브릭 작성**(악용가능성×영향도 매트릭스) → **Step 2: 9개 references에서 참조** → **Step 3: 커밋**

---

## 실행 순서 · 의존성 요약

```
Phase 0 (CI+골든셋)  ─ 먼저. 이후 모든 수정의 회귀 가드
  └▶ Phase 1 (quick fix, 서로 독립·병렬 가능)
        · 1.4(MyBatis)는 0.2(골든셋 safe)를 green으로 만든다
  └▶ Phase 2 (동적 판정 강화) ─ Phase 1과 독립, 병렬 가능
  └▶ Phase 3 (정적 recall)   ─ Phase 0 골든셋 위에서 검증
  └▶ Phase 4 (dyn_session)   ─ 최대 규모, 별도 서브플랜으로 분리 착수
  └▶ Phase 5 (스키마·위생)   ─ 마지막(리팩터 성격)
```

**우선순위 총평:** Phase 0→1이 "반나절~2일" 투자로 신뢰도·안전인식을 즉시 끌어올린다. Phase 2·3이 판정 정확도의 본질 개선. Phase 4가 "동적 침투 전 사업부 공통화"의 유일한 관문. Phase 5는 장기 유지보수.

## Self-Review 체크

- **Spec 커버리지:** 전수조사 결함 표(High 2·Med 5·Low 다수) 전 항목이 태스크에 매핑됨 — sqlmap(1.1)·dyn_session 결합(4)·BFLA(2.1)·time-based(2.2)·CSRF/XSS recall(3.1/3.2)·문서정합(1.2/1.3)·CI(0.1)·골든셋(0.2)·MyBatis(1.4)·백업스캔(1.5)·스키마(5.1)·allow-destructive/encoding/Playwright/sqlmap tmp(1.6/5.2).
- **Placeholder:** Phase 0~3·5는 실제 코드/경로/명령 포함. Phase 4는 규모상 설계+인터페이스+태스크 골격으로 제시하고 별도 서브플랜 분리를 명시(스코프 체크 준수).
- **타입 일관성:** `_classify_sqlmap`·`run_bfla`·`_baseline`·`create_session/login/request` 시그니처가 태스크 간 일치.
