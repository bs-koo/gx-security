# Burp Suite MCP 동적검사 연동 설계 (Spec)

**작성일:** 2026-07-31
**상태:** 확정 (브레인스토밍 완료 → 구현 계획 대기)

## 배경

현재 동적검사 스킬(`exploiting-*` 6종)은 전부 Python 스크립트다. 각 `attack_*.py`가
공용 엔진 `tools/dyn_session.py`(requests 기반 발사·로그인 자동화·판정)와 안전 게이트
`tools/scope_guard.py`(fail-closed, 운영 호스트 코드 수준 차단)를 공유한다. 정적
`detecting-*`가 후보를 뽑고 → `exploiting-*`이 실제 발사로 확정 → 4요소 Evidence 리포트.
오케스트레이터 `auditing-web-application-security`(gx-audit)의 `audit.py`가 정적+동적을
한 번에 돌린다.

PortSwigger가 **Burp Suite MCP Server**(Java 확장, BApp Store/GitHub 오픈소스)를 제공한다.
Burp 내부에서 SSE MCP 서버(기본 `127.0.0.1:9876`)를 띄우고, AI 클라이언트가 `send_http1_request`,
프록시 히스토리, `base64`/`url` 인코딩, Collaborator(Pro) 등 27개 도구를 호출할 수 있다.

## 핵심 결정

### 1. 범위 — 4종 연동, 2종 유지
- **Burp 연동 4종:** 접근통제(IDOR/BFLA)·인증세션·SSRF/open-redirect·path-traversal/upload
- **기존 유지 2종:** SQL Injection(`sqlmap` 우위)·XSS(Playwright 실행확정 우위)
- 근거: `send_http1_request` 하나로 6종 전부 발사는 가능하나, SQLi는 `sqlmap`의
  UNION 컬럼탐지·자동 덤프·정밀 time-blind를, XSS는 Playwright의 DOM 실행확정을 잃는다.
  Burp가 실제 이득을 주는 곳은 살아있는 세션·인코딩이 결정적인 접근통제·인증세션이다.

### 2. 통합 방식 — 하이브리드
결정적 제약: **MCP 도구는 Python 스크립트가 못 부른다. AI만 대화형으로 부른다.**
따라서 "완전자동 스크립트"와 "MCP 도구 활용"은 동시에 가질 수 없다. 그리고 완전자동
로그인·판정·세션은 이미 `dyn_session`이 requests로 하고 있고, pytest 38개가 이를 고정한다.

→ **하이브리드**: 두 경로를 병용한다.
- **프록시 경유(결정론 경로):** 기존 `attack_*.py`를 Burp 프록시(기본 `127.0.0.1:8080`)로
  흘려보낸다. 발사·판정·테스트·`scope_guard`가 전부 그대로 유지되고, 트래픽이 Burp
  히스토리에 증거로 축적된다. 기존 자산 100% 재사용.
- **MCP 보조(대화형 경로):** JWT `base64` 변조·히스토리 조회·Collaborator 같은 Burp
  고유 강점만 AI가 MCP 도구로 심화 검증한다.

### 3. 안전 — scope_guard 유지 + 프리플라이트 온보딩
- 프록시 경유는 `dyn_session`을 그대로 지나가므로 `assert_in_scope()`가 **여전히 강제**된다
  (프록시를 켜도 운영 호스트 차단이 무력화되지 않는다 — 하이브리드의 핵심 안전 이점).
- MCP 보조 경로는 AI가 직접 발사하므로, SKILL 워크플로가 발사 대상 호스트를 `scope_guard`로
  사전 검증하도록 강제한다(화이트리스트, fail-closed).
- **프리플라이트 게이트:** audit·Burp 스킬 진입 시 Burp 가동 여부를 프로브한다. 미설정이면
  단순 중단이 아니라 **설치 온보딩**(절차·명령 안내)을 출력한 뒤, 사용자 선택으로 기존
  스크립트 폴백(우아한 저하)한다. MCP/프록시 없이 Burp 경로를 임의 발사하지 않는다.

## 아키텍처

```
audit.py (오케스트레이터)
  └─ --burp-proxy http://127.0.0.1:8080 지정 시:
        1) burp_preflight.check() → 미가동 시 온보딩 안내
        2) os.environ["SECURITY_PLUGIN_BURP_PROXY"] 세팅 → 모든 자식 subprocess 상속
  └─ run_{access,auth,ssrf,pathupload}_dynamic → attack_*.py (무수정)
        └─ dyn_session.request/login/... → SECURITY_PLUGIN_BURP_PROXY 있으면 proxies 경유

exploiting-with-burp/ (신규 스킬 — MCP 보조 워크플로 문서)
  └─ SKILL.md: 프리플라이트 온보딩 → 프록시 경유 4종 발사 → MCP 도구로 심화
  └─ references/burp-engine.md: MCP 도구 사용법·프록시 설정·JWT 변조 절차

tools/burp_preflight.py (신규): 포트 프로브 + 온보딩 텍스트
tools/dyn_session.py (수정): SECURITY_PLUGIN_BURP_PROXY 프록시 경유 지원
```

## 컴포넌트 책임

| 컴포넌트 | 책임 | 변경 |
|----------|------|------|
| `tools/dyn_session.py` | `SECURITY_PLUGIN_BURP_PROXY` env를 읽어 requests에 `proxies`+`verify=False` 적용 | 수정 |
| `tools/burp_preflight.py` | 프록시(8080)/MCP(9876) 포트 프로브, 온보딩 안내 텍스트 | 신규 |
| `skills/.../audit.py` | `--burp-proxy` 옵션 + 프리플라이트 게이트 + env 세팅 | 수정 |
| `skills/exploiting-with-burp/` | 하이브리드 워크플로 문서(SKILL.md + references) | 신규 |
| `attack_{access,auth,ssrf,pathupload}.py` | (프록시는 dyn_session 레벨) | **무수정** |

## 데이터 흐름

**프록시 경유(결정론)** — 4종 공통
1. `audit.py --target <url> --burp-proxy http://127.0.0.1:8080 --user-a-id/pw ...`
2. 프리플라이트: 8080 미가동 시 온보딩 → 중단/폴백
3. `os.environ` 세팅 → 각 `attack_*.py` 자식이 상속
4. `dyn_session`이 모든 발사를 Burp 프록시로 경유(scope_guard 그대로 강제)
5. 기존 판정·4요소 Evidence 리포트 산출 + Burp 히스토리에 트래픽 축적

**MCP 보조(대화형)** — Burp 고유 강점
1. AI가 `exploiting-with-burp` SKILL 절차대로 프리플라이트 통과 확인
2. 발사 대상 호스트를 `scope_guard`로 사전 검증(화이트리스트)
3. `get_proxy_http_history`로 세션 요청 캡처 → `base64_decode`로 JWT 변조 → `send_http1_request`
4. 블라인드 SSRF는 `generate_collaborator_payload`(Pro) 또는 기존 `oob_canary.py` 폴백
5. 판정은 기존 스크립트 기준 계승(IDOR 403 오탐, 토큰변조 4xx 안전 등)

## 환경 전제 (사용자 1회 셋업)

1. Java(JDK) — PATH에 `java`
2. Burp Suite 실행 (Community로 프록시 경유·send·인코딩 동작 가능성 높음. Collaborator·Scanner는 Pro 전용)
3. MCP Server 확장 로드 (BApp Store 또는 `./gradlew embedProxyJar`)
4. Burp MCP 탭에서 서버 Enable (`127.0.0.1:9876`) + 프록시 리스너(`127.0.0.1:8080`)
5. Claude Code에 MCP 등록: `claude mcp add burp -- <java> -jar mcp-proxy-all.jar --sse-url http://127.0.0.1:9876`

## 미해결(구현 전 확인)

- Burp Community에서 `send_http1_request`·프록시 히스토리·인코딩이 동작하는지 실제 검증
- Burp Target Scope가 MCP `send`까지 막는지(막으면 2차 방어로 추가)
- HTTPS 대상에서 Burp CA 미신뢰 시 `verify=False` 필요 범위

## 트레이드오프

- 프록시 경유는 기존 자산을 온전히 살리되 "MCP 도구 호출"은 아니다(트래픽 경유일 뿐).
- MCP 보조는 진짜 MCP지만 대화형이라 결정론·CI를 일부 포기한다.
- 하이브리드는 결정론(프록시)을 기본선으로 두고 Burp 고유 강점(MCP)만 얹어 둘의 장점을 취한다.
- Burp GUI 상시 구동이 필요해 "python 한 줄"의 가벼움은 프록시 켤 때 한정으로 포기된다.
  → 기존 스크립트를 **병존**시켜 Burp 없는 환경에서도 최소 동작을 보장한다.
