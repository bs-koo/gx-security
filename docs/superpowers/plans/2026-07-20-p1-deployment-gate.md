# P1 배포 게이트 (v0.4.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 정적 진단을 사업부 공통으로 안전하게 배포할 수 있도록 semgrep 설치 표준화·Windows CI·운영정책·버전 규율을 갖춰 v0.4.0을 릴리스한다.

**Architecture:** 코드 로직 변경 없이 배포 요건(설치·CI·문서·버전)을 정비하는 릴리스. 검증 가능한 항목(버전 일치)은 회귀 테스트로 고정하고, 문서·CI는 산출물 체크리스트로 확정한다.

**Tech Stack:** Python 3.11 · unittest · GitHub Actions · semgrep 1.95.0 · Markdown

## Global Constraints

- Python 3.11 고정 (CI setup-python)
- 런타임 의존성은 `requests`, `PyYAML`만. `semgrep==1.95.0`은 정적 정밀도용(dev/CI) — 런타임 필수 아님
- 기존 테스트 green 유지: `python -m unittest discover -s tests -p "test_*.py"` (현재 335 tests, 0 fail)
- 커밋 컨벤션: 한국어 `type: 설명` (예 `docs:`, `test:`, `chore:`, `ci:`), 메시지 끝에 `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- 플랫폼: Windows/PowerShell + Linux 모두 지원 (경로·인코딩 회귀 금지)
- 버전 체계: SemVer. 이번 목표 버전 **0.4.0** (기능 추가: 배포 요건 강화)

---

## Task 1: 버전 일치 테스트 + 0.4.0 승격 (작업 O3)

**Files:**
- Create: `tests/test_version_consistency.py`
- Modify: `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `README.md`(푸터), `CHANGELOG.md`

**Interfaces:**
- Consumes: 없음 (독립)
- Produces: `EXPECTED = "0.4.0"` 상수를 두어 이후 릴리스에서 이 값만 올리면 회귀가 잡히는 단일 진실점

- [ ] **Step 1: 실패 테스트 작성**

```python
# tests/test_version_consistency.py
"""버전 표기가 저장소 전역에서 일치하는지 검증(P5 버전 파편화 재발 방지)."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = "0.4.0"


class TestVersionConsistency(unittest.TestCase):
    def test_plugin_json_version(self):
        data = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(data["version"], EXPECTED)

    def test_marketplace_json_versions(self):
        data = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
        self.assertEqual(data["metadata"]["version"], EXPECTED)
        self.assertEqual(data["plugins"][0]["version"], EXPECTED)

    def test_readme_footer_current(self):
        txt = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(EXPECTED, txt)
        self.assertNotIn("v0.3.0", txt)

    def test_changelog_has_current_entry(self):
        txt = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"[{EXPECTED}]", txt)
```

- [ ] **Step 2: 실행하여 실패 확인**

Run: `python -m unittest tests.test_version_consistency -v`
Expected: FAIL — `plugin.json`/`marketplace.json`은 `0.3.0`, `README`/`CHANGELOG`에 `0.4.0` 없음

- [ ] **Step 3: 버전 0.4.0으로 승격**

- `.claude-plugin/plugin.json`: `"version": "0.3.0"` → `"0.4.0"`
- `.claude-plugin/marketplace.json`: `metadata.version` 및 `plugins[0].version` 둘 다 `"0.4.0"`
- `README.md`: 상단 배지 줄 `` · `v0.3.0` · `` 및 푸터 `<sub>… · v0.3.0</sub>` → `v0.4.0`
- `CHANGELOG.md`: 최상단에 `0.4.0` 항목 추가(아래 내용). 0.3.0 이후 미반영분(F3 SAST recall 보강, M5/M7/M9, M5-semgrep 룰 복구, U1~U4, Gemini 리뷰)을 요약 포함.

```markdown
## [0.4.0] - 2026-07-20

### Added
- 정적 정밀도 표준화 — `requirements-dev.txt`(semgrep 1.95.0 핀)와 설치 스크립트, semgrep 미설치 시 grep 폴백 경고를 도입 문서에서 필수 설치로 승격.
- Windows semgrep CI — `semgrep-tests` 잡에 windows 매트릭스 추가(비차단 관측 폴백 포함).
- 운영정책 문서 `docs/OPERATIONS.md` — 스테이징 허용 등록·자격증명 취급·격리 호스트 규정.
- 버전 일치 회귀 테스트 `tests/test_version_consistency.py`.

### Changed
- 0.3.0 이후 누적분 반영: SAST 미탐 9패턴 보강, semgrep 골든셋 CI(semgrep 1.95.0), semgrep 룰 전역 파탄 복구, 동적 판정 정밀화, dyn_session 레거시(form/cookie) 이식성.
```

- [ ] **Step 4: 실행하여 통과 확인**

Run: `python -m unittest tests.test_version_consistency -v`
Expected: PASS (4 tests)

- [ ] **Step 5: 전체 스위트 회귀 확인**

Run: `python -m unittest discover -s tests -p "test_*.py"`
Expected: OK (기존 + 신규 4 = 339 tests, 0 fail; semgrep 미설치 시 skip은 유지)

- [ ] **Step 6: 커밋**

```bash
git add tests/test_version_consistency.py .claude-plugin/plugin.json .claude-plugin/marketplace.json README.md CHANGELOG.md
git commit -m "chore: v0.4.0 승격 및 버전 일치 테스트 추가" -m "plugin.json·marketplace.json·README를 0.4.0으로 정합하고 회귀 테스트로 고정. CHANGELOG에 0.3.0 이후 누적분 반영." -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: semgrep 설치 표준화 (작업 S1)

**Files:**
- Create: `requirements-dev.txt`, `scripts/install-dev.sh`, `scripts/install-dev.ps1`
- Modify: `README.md`(설치 섹션), `USAGE.md`(§1 설치 방식 C)

**Interfaces:**
- Consumes: 없음
- Produces: `requirements-dev.txt`(semgrep 핀) — CI(Task 3)와 개발자가 공용으로 참조

- [ ] **Step 1: requirements-dev.txt 작성**

```
# gx-security 개발/정밀 스캔 의존성
# 런타임은 requests·PyYAML만 필요하나, 정적 정밀도(recall)를 위해 semgrep 설치를 표준으로 한다.
requests
PyYAML
semgrep==1.95.0
```

- [ ] **Step 2: 설치 스크립트 작성 (양 플랫폼)**

```bash
# scripts/install-dev.sh
#!/usr/bin/env bash
set -euo pipefail
python -m pip install -r "$(dirname "$0")/../requirements-dev.txt"
semgrep --version
echo "[gx-security] 개발 의존성 설치 완료 — 정적 엔진: semgrep"
```

```powershell
# scripts/install-dev.ps1
$ErrorActionPreference = "Stop"
python -m pip install -r "$PSScriptRoot/../requirements-dev.txt"
semgrep --version
Write-Host "[gx-security] 개발 의존성 설치 완료 — 정적 엔진: semgrep"
```

- [ ] **Step 3: README 설치 섹션 갱신**

`README.md`의 "## 설치" 아래에 다음 블록 추가(플러그인 설치 뒤):

```markdown
### 정적 정밀도 표준 (권장)

정적 진단은 semgrep이 있을 때 정밀도(recall)가 크게 오릅니다. **사업부 공통 도입 시 semgrep 설치를 표준으로 합니다.** semgrep이 없으면 grep 폴백으로 동작하되 미탐 위험이 커지며, 스캐너가 `[!] 폴백 경고`를 출력합니다.

​```bash
# Linux/macOS
bash scripts/install-dev.sh
# Windows PowerShell
scripts/install-dev.ps1
# 또는 직접
pip install -r requirements-dev.txt
​```
```

- [ ] **Step 4: USAGE 설치 방식 C 갱신**

`USAGE.md` §1 "방식 C — CLI만"의 semgrep 안내 줄을 다음으로 교체:

```markdown
> **semgrep 설치를 표준으로 한다**(`pip install -r requirements-dev.txt`). 없으면 grep 폴백으로 동작하나 recall이 낮아 미탐 위험이 크다.
```

- [ ] **Step 5: 검증 (설치 후 엔진 선택 확인)**

Run:
```bash
pip install -r requirements-dev.txt && semgrep --version && python scan_all.py tests/fixtures | head -3
```
Expected: `semgrep 1.95.0` 출력 후 스캔 헤더에 `엔진: semgrep`(grep-fallback 아님)

> 네트워크 제약으로 설치가 불가한 환경이면 이 스텝은 문서 검증으로 대체하고, requirements-dev.txt·스크립트·문서 문구만 확인한다.

- [ ] **Step 6: 커밋**

```bash
git add requirements-dev.txt scripts/install-dev.sh scripts/install-dev.ps1 README.md USAGE.md
git commit -m "chore: semgrep 설치 표준화(requirements-dev + 설치 스크립트)" -m "정적 정밀도를 위해 semgrep 1.95.0을 dev 의존성으로 핀하고 양 플랫폼 설치 스크립트·문서를 추가." -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Windows semgrep CI (작업 S2)

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `requirements-dev.txt`(Task 2) — 가능하면 설치를 이 파일로 통일
- Produces: 없음

- [ ] **Step 1: semgrep-tests 잡을 OS 매트릭스로 확장**

`.github/workflows/ci.yml`의 `semgrep-tests` 잡을 아래로 교체. Windows는 semgrep 설치가 불안정할 수 있어 `continue-on-error`로 **비차단 관측**하되, ubuntu는 하드 게이트를 유지한다.

```yaml
  semgrep-tests:
    # semgrep 경로(required on ubuntu, best-effort on windows).
    # 버전 핀(재현성): FR-4 실측값·룰 동작 드리프트 방지.
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    continue-on-error: ${{ matrix.os == 'windows-latest' }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install deps (semgrep 핀)
        run: for i in 1 2 3; do pip install requests PyYAML "semgrep==1.95.0" && break || sleep 5; done
        shell: bash
      - name: Run unittest suite (semgrep 경로)
        run: python -m unittest discover -s tests -p "test_*.py" -v
```

- [ ] **Step 2: YAML 문법 검증**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml', encoding='utf-8')); print('yaml ok')"`
Expected: `yaml ok`

- [ ] **Step 3: 커밋**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: semgrep-tests에 windows 매트릭스 추가(비차단)" -m "Windows semgrep 실탐지 정확도를 CI로 관측. ubuntu는 하드 게이트 유지, windows는 continue-on-error." -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

> **Note (실행자용):** 이 Task의 최종 확인은 PR 푸시 후 GitHub Actions에서 `semgrep-tests (windows-latest)` 잡이 실행되는지로 완료된다. 로컬에서는 문법 검증까지만 가능하다.

---

## Task 4: 운영정책 문서 (작업 O1)

**Files:**
- Create: `docs/OPERATIONS.md`
- Modify: `README.md`(문서 지도 표에 링크 추가)

**Interfaces:**
- Consumes: 없음
- Produces: 없음

- [ ] **Step 1: docs/OPERATIONS.md 작성**

다음 섹션을 **모두** 포함한다(각 섹션은 실제 절차/명령을 담아야 하며 제목만 두지 않는다):

1. **대상 범위 원칙** — 운영 금지, 로컬/스테이징만. `scope_guard` 4단계 판정(deny→IP→allow→needs-auth) 요약.
2. **사내 스테이징 등록 절차** — `SECURITY_PLUGIN_ALLOW_HOSTS=<정확매칭|.suffix>` 예시, 사설망은 `SECURITY_PLUGIN_ALLOW_PRIVATE=1` 정책 결정 기준(사내 운영이 사설망일 수 있으므로 기본 차단 유지 권고).
3. **공인 대상 승인** — `--authorized` + `SECURITY_PLUGIN_AUTHORIZED=1` 이중 충족, 소유자 책임.
4. **자격증명 취급 규정(MUST)** — CLI 인자 평문노출 경로(프로세스 목록·셸 히스토리), **단일 운영자 전용 격리 호스트 + 전용 테스트 계정** 필수. (env/stdin 입력은 v0.5.0 D1에서 제공 예정임을 명시.)
5. **파괴적 작업** — 업로드 등은 `--allow-destructive` + 사람 승인, leftover 마커 파일 수동 삭제 절차.
6. **점검 산출물 취급** — `reports/`는 gitignore, 중앙 보관 방안은 v0.7.0 O5에서 확정 예정.

- [ ] **Step 2: README 문서 지도에 링크 추가**

`README.md`의 "## 문서 지도" 표에 행 추가:

```markdown
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | 운영정책 — 스테이징 허용 등록·자격증명 취급·격리 호스트 규정 |
```

- [ ] **Step 3: 링크 유효성 확인**

Run: `test -f docs/OPERATIONS.md && grep -q "OPERATIONS.md" README.md && echo "links ok"`
Expected: `links ok`

- [ ] **Step 4: 커밋**

```bash
git add docs/OPERATIONS.md README.md
git commit -m "docs: 운영정책 문서(OPERATIONS.md) 추가" -m "스테이징 허용 등록·자격증명 취급·격리 호스트·파괴적 작업 규정을 명문화하고 문서 지도에 링크." -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## 릴리스 마무리 (전체 Task 완료 후)

- [ ] **전체 회귀**: `python -m unittest discover -s tests -p "test_*.py"` → OK
- [ ] **버전 확인**: `python -m unittest tests.test_version_consistency` → PASS
- [ ] **P1 수용 기준 대조**: semgrep CI(Win+Linux) 실행 · 설치 원클릭 · 운영정책 문서화 · CHANGELOG 최신 — 4개 모두 충족
- [ ] (선택) `v0.4.0` 태그는 PR 병합 후 사용자 승인 하에 부여

## Self-Review 대상 (계획 작성자 체크리스트)

- 스펙 P1의 4개 작업(S1/S2/O1/O3) → Task 2/3/4/1로 1:1 매핑됨
- Placeholder 없음: 각 Task에 실제 코드/설정/문서 항목 포함
- 타입 일관성: `EXPECTED="0.4.0"` 상수가 Task 1 전반에서 일관
