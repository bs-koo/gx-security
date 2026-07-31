# Burp Suite MCP 하이브리드 연동 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 기존 `attack_*.py` 4종(접근통제·인증세션·SSRF·path/upload)을 Burp 프록시로 경유시키고(결정론 유지), Burp 고유 강점은 MCP 도구로 심화하는 하이브리드 동적검사 경로를 추가한다.

**Architecture:** `tools/dyn_session.py`가 `SECURITY_PLUGIN_BURP_PROXY` 환경변수를 읽어 모든 requests 발사를 Burp 프록시(기본 `127.0.0.1:8080`)로 경유시킨다. `audit.py`는 `--burp-proxy` 옵션으로 이 env를 세팅하고 자식 subprocess가 상속한다. `tools/burp_preflight.py`가 Burp 가동을 프로브하고 미설정 시 설치 온보딩을 안내한다. 신규 `exploiting-with-burp` 스킬 문서가 MCP 보조 워크플로를 규정한다. 기존 `attack_*.py` 4종과 pytest 38개는 무수정·무회귀.

**Tech Stack:** Python 3.11+, 표준 라이브러리(`socket`, `argparse`, `os`), `requests`(기존), pytest/unittest(기존 테스트 스타일).

## Global Constraints

- **기존 자산 무회귀:** `SECURITY_PLUGIN_BURP_PROXY`가 없으면 `dyn_session`의 모든 발사는 기존과 **바이트 동일**해야 한다(기존 pytest 38개 그대로 통과).
- **attack 4종 무수정:** `attack_access.py`·`attack_auth.py`·`attack_ssrf.py`·`attack_pathupload.py`는 한 줄도 고치지 않는다(프록시는 `dyn_session` 레벨).
- **scope_guard 유지:** 프록시를 켜도 `assert_in_scope()`는 그대로 강제된다(운영 호스트 차단 무력화 금지).
- **UTF-8 콘솔:** 신규 스크립트는 진입 시 `from tools import io_utf8; io_utf8.configure()`를 호출한다(Windows cp949 크래시 방지, 기존 패턴).
- **플러그인 루트 부트스트랩:** `tools/` 밖에서 임포트 가능하도록 `_PLUGIN_ROOT`를 `sys.path`에 추가하는 기존 패턴을 따른다.
- **한국어:** 주석·docstring·문서·SKILL.md는 한국어로 작성한다.
- **SKILL.md frontmatter:** 신규 스킬은 기존 스킬과 동일한 frontmatter 스키마(`name`/`description`/`version` 등)를 갖춰 `tests/test_version_consistency.py`를 통과해야 한다.
- **프록시 env 이름 고정:** 환경변수명은 정확히 `SECURITY_PLUGIN_BURP_PROXY`, 값은 프록시 URL(예: `http://127.0.0.1:8080`).
- **Intercept OFF 전제:** 프록시 경유는 Burp Proxy Intercept가 OFF여야 발사가 멈추지 않는다(ON이면 100% hang). onboarding·SKILL·audit 활성 메시지에 경고를 노출한다.
- **verify=False 경고 억제:** 프록시 활성 시 requests `verify=False`가 유발하는 `InsecureRequestWarning`을 1회만 억제한다(로그 오염 방지).

---

### Task 1: `tools/burp_preflight.py` — 포트 프로브 + 설치 온보딩

**Files:**
- Create: `tools/burp_preflight.py`
- Test: `tests/test_burp_preflight.py`

**Interfaces:**
- Produces:
  - `probe_port(host: str, port: int, timeout: float = 1.0) -> bool` — TCP 연결 성공 여부
  - `split_hostport(proxy_url: str) -> tuple[str, int]` — `"http://127.0.0.1:8080"` → `("127.0.0.1", 8080)`
  - `check(proxy_host, proxy_port, mcp_host, mcp_port, timeout=1.0) -> dict` — `{"proxy_up","mcp_up","proxy","mcp"}`
  - `onboarding_text(proxy: str = "127.0.0.1:8080", mcp: str = "127.0.0.1:9876") -> str`
  - 상수: `DEFAULT_PROXY_HOST="127.0.0.1"`, `DEFAULT_PROXY_PORT=8080`, `DEFAULT_MCP_HOST="127.0.0.1"`, `DEFAULT_MCP_PORT=9876`

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_burp_preflight.py`:

```python
import unittest
from unittest.mock import patch, MagicMock
from tools import burp_preflight


class TestSplitHostport(unittest.TestCase):
    def test_split_full_url(self):
        self.assertEqual(burp_preflight.split_hostport("http://127.0.0.1:8080"), ("127.0.0.1", 8080))

    def test_split_bare_hostport(self):
        self.assertEqual(burp_preflight.split_hostport("127.0.0.1:8080"), ("127.0.0.1", 8080))

    def test_split_default_port_when_missing(self):
        # 포트 없으면 프록시 기본 8080으로 폴백
        self.assertEqual(burp_preflight.split_hostport("http://127.0.0.1"), ("127.0.0.1", 8080))


class TestProbePort(unittest.TestCase):
    @patch("socket.create_connection")
    def test_probe_open(self, mock_conn):
        mock_conn.return_value = MagicMock()
        self.assertTrue(burp_preflight.probe_port("127.0.0.1", 8080))

    @patch("socket.create_connection", side_effect=OSError("refused"))
    def test_probe_closed(self, _mock):
        self.assertFalse(burp_preflight.probe_port("127.0.0.1", 8080))


class TestCheckAndOnboarding(unittest.TestCase):
    @patch("tools.burp_preflight.probe_port")
    def test_check_reports_both(self, mock_probe):
        mock_probe.side_effect = [True, False]  # proxy up, mcp down
        st = burp_preflight.check()
        self.assertTrue(st["proxy_up"])
        self.assertFalse(st["mcp_up"])

    def test_onboarding_mentions_setup_steps(self):
        txt = burp_preflight.onboarding_text()
        self.assertIn("claude mcp add", txt)
        self.assertIn("Extensions", txt)
        self.assertIn("Intercept", txt)  # 엣지 A: Intercept OFF 경고 포함
```

- [ ] **Step 2: 실패 확인**

Run: `python -m pytest tests/test_burp_preflight.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tools.burp_preflight'`

- [ ] **Step 3: 구현 작성**

`tools/burp_preflight.py`:

```python
#!/usr/bin/env python3
"""
tools/burp_preflight.py — Burp Suite 가동 프리플라이트 + 설치 온보딩.

Burp 프록시(기본 127.0.0.1:8080)와 MCP 서버(기본 127.0.0.1:9876)의 포트 개방을
TCP 연결로 프로브한다. 미가동이면 설치·설정 온보딩 텍스트를 제공한다.
Burp 경로(audit --burp-proxy / exploiting-with-burp)는 발사 전 이 게이트를 통과해야 한다.
"""
import argparse
import os
import socket
import sys
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from tools import io_utf8  # noqa: E402
io_utf8.configure()

DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8080
DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_MCP_PORT = 9876


def probe_port(host, port, timeout=1.0):
    """host:port에 TCP 연결을 시도해 열려 있으면 True. 거부·타임아웃·오류면 False."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError, OverflowError):
        return False


def split_hostport(proxy_url):
    """'http://127.0.0.1:8080' 또는 '127.0.0.1:8080' → ('127.0.0.1', 8080).
    포트 없으면 프록시 기본(8080)으로 폴백."""
    raw = proxy_url if "://" in proxy_url else "http://" + proxy_url
    u = urlparse(raw)
    return (u.hostname or DEFAULT_PROXY_HOST), int(u.port or DEFAULT_PROXY_PORT)


def check(proxy_host=DEFAULT_PROXY_HOST, proxy_port=DEFAULT_PROXY_PORT,
          mcp_host=DEFAULT_MCP_HOST, mcp_port=DEFAULT_MCP_PORT, timeout=1.0):
    """프록시/MCP 포트 개방 상태를 dict로 반환."""
    return {
        "proxy_up": probe_port(proxy_host, proxy_port, timeout),
        "mcp_up": probe_port(mcp_host, mcp_port, timeout),
        "proxy": f"{proxy_host}:{proxy_port}",
        "mcp": f"{mcp_host}:{mcp_port}",
    }


def onboarding_text(proxy="127.0.0.1:8080", mcp="127.0.0.1:9876"):
    """Burp 미가동 시 설치·설정 온보딩 안내(1회 셋업)."""
    return (
        "\n[Burp 미가동] Burp Suite MCP 연동이 설정되지 않았습니다. 1회 셋업:\n"
        "  1) Java(JDK) 설치 — PATH에 java\n"
        "  2) Burp Suite 실행 (Community 가능. Collaborator·Scanner는 Pro 전용)\n"
        "  3) MCP Server 확장 로드 — BApp Store 또는 ./gradlew embedProxyJar 후\n"
        "     Burp > Extensions > Add > Java > burp-mcp-all.jar\n"
        f"  4) Burp MCP 탭에서 서버 Enable ({mcp}) + 프록시 리스너 확인 ({proxy})\n"
        "  5) Claude Code에 MCP 등록:\n"
        "     claude mcp add burp -- <java> -jar mcp-proxy-all.jar --sse-url http://127.0.0.1:9876\n"
        "  ⚠ Burp Proxy > Intercept 는 OFF로 두세요 — ON이면 프록시 경유 발사가 전부 멈춥니다.\n"
        "  설정 후 다시 실행하세요. (Burp 없이 진행하려면 --burp-proxy 없이 기존 스크립트 경로 사용)\n"
    )


def main():
    p = argparse.ArgumentParser(description="Burp 가동 프리플라이트 프로브")
    p.add_argument("--proxy-host", default=DEFAULT_PROXY_HOST)
    p.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT)
    p.add_argument("--mcp-host", default=DEFAULT_MCP_HOST)
    p.add_argument("--mcp-port", type=int, default=DEFAULT_MCP_PORT)
    p.add_argument("--require", choices=["proxy", "mcp", "both"], default="proxy",
                   help="통과 조건(기본 proxy — 프록시 경유만 필요)")
    args = p.parse_args()
    st = check(args.proxy_host, args.proxy_port, args.mcp_host, args.mcp_port)
    need_proxy = args.require in ("proxy", "both")
    need_mcp = args.require in ("mcp", "both")
    ok = (st["proxy_up"] or not need_proxy) and (st["mcp_up"] or not need_mcp)
    print(f"[프리플라이트] 프록시({st['proxy']}): {'OK' if st['proxy_up'] else '미가동'}  /  "
          f"MCP({st['mcp']}): {'OK' if st['mcp_up'] else '미가동'}")
    if not ok:
        print(onboarding_text(st["proxy"], st["mcp"]))
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: 통과 확인**

Run: `python -m pytest tests/test_burp_preflight.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: 커밋**

```bash
git add tools/burp_preflight.py tests/test_burp_preflight.py
git commit -m "feat: Burp 프리플라이트 프로브 + 설치 온보딩(tools/burp_preflight.py)"
```

---

### Task 2: `tools/dyn_session.py` — Burp 프록시 경유 지원

**Files:**
- Modify: `tools/dyn_session.py` (신규 헬퍼 `_burp_proxies` + `request`/`login`/`login_response`/`form_login`에 프록시 적용)
- Test: `tests/test_dyn_session_burp_proxy.py`

**Interfaces:**
- Consumes: 기존 `request`/`login`/`login_response`/`form_login` 시그니처(불변)
- Produces:
  - `_burp_proxies() -> dict | None` — env `SECURITY_PLUGIN_BURP_PROXY` 있으면 `{"http": v, "https": v}`, 없으면 `None`
  - `_proxy_kwargs() -> dict` — 프록시 활성 시 `{"proxies","verify"}`(+ `InsecureRequestWarning` 1회 억제), 비활성 시 `{}`
  - 위 4개 발사 함수는 프록시 활성 시 requests 호출에 `proxies=<dict>` + `verify=False`를 추가한다. 비활성 시 기존과 바이트 동일(추가 kwargs 없음).
  - `login()`·`login_response()`는 프록시 활성 중 요청 예외 시 진단 힌트("Burp 프록시 경유 중 …")를 예외 메시지에 덧붙인다(엣지 F).

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_dyn_session_burp_proxy.py`:

```python
import os
import unittest
from unittest.mock import patch, MagicMock
from tools import dyn_session


class TestBurpProxyResolution(unittest.TestCase):
    def test_no_env_returns_none(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECURITY_PLUGIN_BURP_PROXY", None)
            self.assertIsNone(dyn_session._burp_proxies())

    def test_env_returns_proxies_dict(self):
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
            self.assertEqual(
                dyn_session._burp_proxies(),
                {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})

    def test_blank_env_returns_none(self):
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "   "}):
            self.assertIsNone(dyn_session._burp_proxies())


class TestRequestProxyWiring(unittest.TestCase):
    @patch("requests.request")
    def test_request_no_env_no_proxies_kwarg(self, mock_req):
        # 하위호환: env 없으면 proxies/verify 키를 아예 넘기지 않는다(바이트 불변).
        mock_req.return_value = MagicMock(status_code=200, text="ok", headers={})
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECURITY_PLUGIN_BURP_PROXY", None)
            dyn_session.request("GET", "http://localhost:7171/x", token="TKN")
        _, kwargs = mock_req.call_args
        self.assertNotIn("proxies", kwargs)
        self.assertNotIn("verify", kwargs)

    @patch("requests.request")
    def test_request_env_sets_proxies_and_verify_false(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, text="ok", headers={})
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
            dyn_session.request("GET", "http://localhost:7171/x", token="TKN")
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["proxies"], {"http": "http://127.0.0.1:8080",
                                             "https": "http://127.0.0.1:8080"})
        self.assertFalse(kwargs["verify"])


class TestLoginProxyWiring(unittest.TestCase):
    @patch("requests.post")
    def test_login_env_sets_proxies(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200, headers={}, json=lambda: {"data": {"accessToken": "T"}})
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
            dyn_session.login("http://localhost:7171", "/login", {"id": "a", "pw": "b"})
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["proxies"]["http"], "http://127.0.0.1:8080")
        self.assertFalse(kwargs["verify"])

    @patch("requests.post", side_effect=OSError("proxy refused"))
    def test_login_proxy_error_hint(self, _mock):
        # 엣지 F: 프록시 활성 중 요청 예외를 '자격 실패'로 오진단하지 않도록 Burp 힌트를 남긴다
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
            with self.assertRaises(RuntimeError) as cm:
                dyn_session.login("http://localhost:7171", "/login", {"id": "a", "pw": "b"})
        self.assertIn("Burp", str(cm.exception))


class TestProxyWarningSuppress(unittest.TestCase):
    @patch("requests.request")
    def test_verify_false_warning_suppressed_once(self, mock_req):
        # 엣지 B: 프록시 활성 시 InsecureRequestWarning 억제가 1회만 호출되는지(로그 오염 방지)
        mock_req.return_value = MagicMock(status_code=200, text="ok", headers={})
        dyn_session._burp_warned = False
        with patch("urllib3.disable_warnings") as mock_dis:
            with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
                dyn_session.request("GET", "http://localhost:7171/x")
                dyn_session.request("GET", "http://localhost:7171/y")
        self.assertEqual(mock_dis.call_count, 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 실패 확인**

Run: `python -m pytest tests/test_dyn_session_burp_proxy.py -v`
Expected: FAIL — `AttributeError: module 'tools.dyn_session' has no attribute '_burp_proxies'`

- [ ] **Step 3: 구현 작성**

`tools/dyn_session.py` — 상단 import 아래(20행 `io_utf8.configure()` 다음)에 헬퍼 추가:

```python
_burp_warned = False


def _burp_proxies():
    """SECURITY_PLUGIN_BURP_PROXY env가 있으면 requests용 proxies dict, 없으면 None.
    하이브리드 Burp 경유 — 값이 없거나 공백이면 프록시를 쓰지 않아 기존 발사와 바이트 동일."""
    val = os.environ.get("SECURITY_PLUGIN_BURP_PROXY", "").strip()
    if not val:
        return None
    return {"http": val, "https": val}


def _proxy_kwargs():
    """프록시 활성 시 requests 호출에 병합할 kwargs({proxies, verify}), 비활성 시 빈 dict.
    Burp가 TLS를 MITM하므로 프록시 경유 시 verify=False가 필요하다(로컬/스테이징 한정).
    verify=False가 유발하는 InsecureRequestWarning을 프록시 활성 시 1회만 억제한다(엣지 B)."""
    proxies = _burp_proxies()
    if not proxies:
        return {}
    global _burp_warned
    if not _burp_warned:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        _burp_warned = True
    return {"proxies": proxies, "verify": False}
```

`request()` 내부 — `resp = caller.request(...)` 호출을 프록시 kwargs 병합으로 교체(192~220행 블록):

```python
    caller = session if session is not None else requests
    t0 = time.monotonic()
    resp = caller.request(
        method.upper(), url, headers=headers, json=json_body,
        files=files, data=data,
        timeout=timeout, allow_redirects=False, **_proxy_kwargs())
    return {"status": resp.status_code, "body": resp.text,
            "headers": dict(resp.headers),
            "elapsed": round(time.monotonic() - t0, 3)}
```

`login()` 내부 — `resp = requests.post(...)`(76행)와 예외 핸들러(77~78행)를 교체(엣지 F 힌트 추가):

```python
    try:
        resp = requests.post(url, json=body, timeout=timeout,
                             allow_redirects=False, **_proxy_kwargs())
    except Exception as e:
        hint = " (Burp 프록시 경유 중 — Burp 가동·Intercept OFF 확인)" if _burp_proxies() else ""
        raise RuntimeError(f"로그인 요청 실패: {url} — {type(e).__name__}{hint}")
```

`login_response()` 내부 — `resp = requests.post(...)`(113행)와 예외 핸들러(114~115행)를 동일하게 교체:

```python
    try:
        resp = requests.post(url, json=body, timeout=timeout,
                             allow_redirects=False, **_proxy_kwargs())
    except Exception as e:
        hint = " (Burp 프록시 경유 중 — Burp 가동·Intercept OFF 확인)" if _burp_proxies() else ""
        raise RuntimeError(f"로그인 요청 실패: {url} — {type(e).__name__}{hint}")
```

`form_login()` 내부 — `resp = session.post(...)` 를(170행) 교체:

```python
        resp = session.post(url, data=form, timeout=timeout,
                            allow_redirects=False, **_proxy_kwargs())
```

- [ ] **Step 4: 통과 + 무회귀 확인**

Run: `python -m pytest tests/test_dyn_session_burp_proxy.py tests/test_dyn_session.py -v`
Expected: PASS (신규 6 + 기존 test_dyn_session 전부). 기존 `test_request_adds_bearer` 등은 env 미설정이라 proxies 미추가로 그대로 통과.

- [ ] **Step 5: 커밋**

```bash
git add tools/dyn_session.py tests/test_dyn_session_burp_proxy.py
git commit -m "feat: dyn_session Burp 프록시 경유 지원(SECURITY_PLUGIN_BURP_PROXY)"
```

---

### Task 3: `audit.py` — `--burp-proxy` 옵션 + 프리플라이트 게이트

**Files:**
- Modify: `skills/auditing-web-application-security/scripts/audit.py` (argparse 옵션 + `_apply_burp_proxy` 헬퍼 + `if args.target:` 초입 배선)
- Test: `tests/test_audit_burp_proxy.py`

**Interfaces:**
- Consumes: `tools.burp_preflight.split_hostport`, `tools.burp_preflight.probe_port` (Task 1)
- Produces:
  - `_apply_burp_proxy(burp_proxy: str | None, *, strict=False, probe=None) -> dict` — `{"enabled": bool, "proxy_up": bool | None, "strict_abort": bool}`. 프록시 가동 시 `os.environ["SECURITY_PLUGIN_BURP_PROXY"]`를 세팅하고 `enabled=True`; 미가동이면 세팅하지 않고 `enabled=False`(온보딩 후 폴백). `strict=True`이고 미가동이면 `strict_abort=True`로 호출부가 발사를 중단하게 한다(엣지 C). 호출부는 `report["burp_proxy"]`에 이 dict를 실어 `--json`에 노출한다(엣지 G). `probe`는 테스트 주입용(기본 `burp_preflight.probe_port`).

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_audit_burp_proxy.py`:

```python
import os
import sys
import importlib
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "skills", "auditing-web-application-security", "scripts"))
audit = importlib.import_module("audit")


class TestApplyBurpProxy(unittest.TestCase):
    def setUp(self):
        os.environ.pop("SECURITY_PLUGIN_BURP_PROXY", None)

    def tearDown(self):
        os.environ.pop("SECURITY_PLUGIN_BURP_PROXY", None)

    def test_none_disabled_no_env(self):
        out = audit._apply_burp_proxy(None)
        self.assertFalse(out["enabled"])
        self.assertNotIn("SECURITY_PLUGIN_BURP_PROXY", os.environ)

    def test_proxy_up_sets_env(self):
        out = audit._apply_burp_proxy("http://127.0.0.1:8080", probe=lambda h, p: True)
        self.assertTrue(out["enabled"])
        self.assertEqual(os.environ["SECURITY_PLUGIN_BURP_PROXY"], "http://127.0.0.1:8080")

    def test_proxy_down_no_env_fallback(self):
        out = audit._apply_burp_proxy("http://127.0.0.1:8080", probe=lambda h, p: False)
        self.assertFalse(out["enabled"])
        self.assertNotIn("SECURITY_PLUGIN_BURP_PROXY", os.environ)

    def test_strict_down_aborts(self):
        # 엣지 C: strict + 미가동 → strict_abort True, env 미설정(발사 중단 신호)
        out = audit._apply_burp_proxy("http://127.0.0.1:8080", strict=True, probe=lambda h, p: False)
        self.assertTrue(out["strict_abort"])
        self.assertNotIn("SECURITY_PLUGIN_BURP_PROXY", os.environ)

    def test_strict_up_no_abort(self):
        out = audit._apply_burp_proxy("http://127.0.0.1:8080", strict=True, probe=lambda h, p: True)
        self.assertFalse(out["strict_abort"])
        self.assertTrue(out["enabled"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 실패 확인**

Run: `python -m pytest tests/test_audit_burp_proxy.py -v`
Expected: FAIL — `AttributeError: module 'audit' has no attribute '_apply_burp_proxy'`

- [ ] **Step 3: 구현 작성**

`audit.py` — `from tools import io_utf8` 아래(29행 근처)에 임포트 추가:

```python
from tools import burp_preflight  # noqa: E402  (Burp 프록시 프리플라이트 게이트)
```

`audit.py` — `main()` 위(752행 근처)에 헬퍼 추가(strict·엣지 C 반영):

```python
def _apply_burp_proxy(burp_proxy, *, strict=False, probe=None):
    """--burp-proxy 지정 시 프리플라이트 확인 후 os.environ에 세팅한다.

    가동(프록시 포트 열림) 시 SECURITY_PLUGIN_BURP_PROXY를 세팅해 모든 자식 subprocess가
    dyn_session 프록시 경유를 상속하게 한다. 미가동이면 세팅하지 않고 enabled=False를 반환해
    호출부가 온보딩 안내 후 기존 스크립트 경로로 폴백하게 한다(우아한 저하). strict면 미가동 시
    strict_abort=True로 신호해 호출부가 발사를 중단하게 한다(증거 없는 폴백 금지·엣지 C). probe는 테스트 주입용.
    """
    if not burp_proxy:
        return {"enabled": False, "proxy_up": None, "strict_abort": False}
    probe = probe or burp_preflight.probe_port
    host, port = burp_preflight.split_hostport(burp_proxy)
    up = probe(host, port)
    if up:
        os.environ["SECURITY_PLUGIN_BURP_PROXY"] = burp_proxy
    return {"enabled": up, "proxy_up": up, "strict_abort": bool(strict and not up)}
```

`audit.py` — argparse에 옵션 추가(`--json` 인자 정의(804행) 바로 위):

```python
    ap.add_argument("--burp-proxy",
                    help="Burp 프록시 URL(예: http://127.0.0.1:8080). 지정+Burp 가동 시 "
                         "모든 동적 발사를 Burp 경유(히스토리 증거 축적). 미가동 시 온보딩 후 기존 경로 폴백")
    ap.add_argument("--burp-proxy-strict", action="store_true",
                    help="Burp 미가동 시 폴백하지 않고 발사를 중단(증거 없는 발사 방지). --burp-proxy와 함께 사용")
```

`audit.py` — `if args.target:` 블록 진입 직후(818행 다음 줄), 자격증명 처리보다 먼저 배선(엣지 A·C·G 반영):

```python
    if args.target:
        # Burp 프록시 프리플라이트(하이브리드) — 가동 시 env 세팅, 미가동 시 strict면 중단·아니면 폴백
        _bp = _apply_burp_proxy(args.burp_proxy, strict=args.burp_proxy_strict)
        report["burp_proxy"] = _bp  # 엣지 G: --json 리포트에 경유/폴백 상태 노출
        if _bp.get("strict_abort"):
            print(burp_preflight.onboarding_text(), file=sys.stderr)
            print("[중단] --burp-proxy-strict: Burp 미가동으로 발사를 중단합니다(증거 없는 폴백 금지).",
                  file=sys.stderr)
            if args.json:
                io_utf8.emit_json(report)
            sys.exit(1)
        if args.burp_proxy and not args.json:
            if _bp["enabled"]:
                print(f"[+] Burp 프록시 경유 활성: {args.burp_proxy} — "
                      f"Burp Proxy>Intercept가 OFF인지 확인하세요(ON이면 발사가 멈춥니다).")
            else:
                print(burp_preflight.onboarding_text(), file=sys.stderr)
                print("[!] Burp 미가동 — 기존 스크립트 경로로 폴백합니다(프록시 미경유).", file=sys.stderr)
```

- [ ] **Step 4: 통과 확인**

Run: `python -m pytest tests/test_audit_burp_proxy.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: 무회귀 확인(오케스트레이터 전체 테스트)**

Run: `python -m pytest tests/test_audit.py tests/test_audit_creds_forwarding.py tests/test_audit_login_forwarding.py -v`
Expected: PASS — 기존 audit 테스트 무회귀(`--burp-proxy` 미지정 시 동작 불변)

- [ ] **Step 6: 커밋**

```bash
git add skills/auditing-web-application-security/scripts/audit.py tests/test_audit_burp_proxy.py
git commit -m "feat: audit --burp-proxy 옵션 + 프리플라이트 게이트(env 전파)"
```

---

### Task 4: `exploiting-with-burp` 스킬 문서 — 하이브리드 MCP 워크플로

**Files:**
- Create: `skills/exploiting-with-burp/SKILL.md`
- Create: `skills/exploiting-with-burp/references/burp-engine.md`
- Test: `tests/test_exploiting_with_burp_meta.py`

**Interfaces:**
- Consumes: Task 1~3 산출물(`burp_preflight`, `--burp-proxy`, 프록시 경유)
- Produces: 신규 스킬 디렉토리. SKILL.md는 프리플라이트 온보딩 → 프록시 경유 4종 발사 → MCP 보조 심화 절차를 규정한다.

- [ ] **Step 1: 메타 정합성 실패 테스트 작성**

`tests/test_exploiting_with_burp_meta.py`:

```python
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SKILL = os.path.join(ROOT, "skills", "exploiting-with-burp", "SKILL.md")


class TestSkillMeta(unittest.TestCase):
    def test_skill_file_exists(self):
        self.assertTrue(os.path.isfile(SKILL))

    def test_frontmatter_has_required_keys(self):
        with open(SKILL, encoding="utf-8") as f:
            head = f.read().split("---", 2)
        self.assertGreaterEqual(len(head), 3, "frontmatter 블록(---...---) 필요")
        fm = head[1]
        for key in ("name:", "description:", "version:"):
            self.assertIn(key, fm)
        self.assertIn("name: exploiting-with-burp", fm)

    def test_body_mentions_preflight_and_proxy(self):
        with open(SKILL, encoding="utf-8") as f:
            body = f.read()
        self.assertIn("burp_preflight", body)
        self.assertIn("--burp-proxy", body)
        self.assertIn("SECURITY_PLUGIN_BURP_PROXY", body)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 실패 확인**

Run: `python -m pytest tests/test_exploiting_with_burp_meta.py -v`
Expected: FAIL — 파일 없음

- [ ] **Step 3: SKILL.md 작성**

`skills/exploiting-with-burp/SKILL.md`:

````markdown
---
name: exploiting-with-burp
description: >-
  SQIsoft 사내 권한 있는 펜테스트 전용. Burp Suite MCP를 활용해 접근통제(IDOR/BFLA)·
  인증세션·SSRF/오픈리다이렉트·경로조작/업로드 4종을 하이브리드로 동적 검증한다.
  기존 attack_*.py를 Burp 프록시(127.0.0.1:8080)로 경유시켜 결정론·판정·scope_guard를
  그대로 유지하고(트래픽을 Burp 히스토리에 축적), JWT base64 변조·히스토리 조회·
  Collaborator 같은 Burp 고유 강점만 MCP 도구로 심화한다. SQLi·XSS는 기존 경로 유지.
domain: cybersecurity
subdomain: web-application-security
tags: [burp, mcp, pentest, exploiting, idor, bfla, auth-session, ssrf, path-traversal, sqisoft]
version: "0.1.0"
author: sqisoft-security
license: Proprietary
---

> ┌─────────────────────────────────────────────────────────────────┐
> │  경고 — 사내 권한 있는 펜테스트 전용                           │
> │  실제 공격 페이로드를 발사합니다.                               │
> │  운영 환경(prod/www.*) 대상 사용 절대 금지.                     │
> │  프록시 경유도 dyn_session의 scope_guard가 강제 차단합니다.     │
> └─────────────────────────────────────────────────────────────────┘

# Burp MCP 하이브리드 동적검사

## When to Use

- 접근통제·인증세션·SSRF·경로조작/업로드를 **살아있는 세션/Burp 히스토리** 맥락에서 검증할 때
- 기존 스크립트로 확정한 결과에 **Burp 고유 심화**(JWT 변조·인코딩·Collaborator)를 더할 때

**쓰지 않을 때:** SQLi(→ `exploiting-sql-injection`, sqlmap 우위) · XSS(→ `exploiting-xss-vulnerabilities`,
Playwright 실행확정 우위) · Burp 미설치 환경(→ 기존 `attack_*.py` 직접 사용)

## Prerequisites (1회 셋업)

1. Java(JDK) — PATH에 `java`
2. Burp Suite 실행 (Community 가능. Collaborator·Scanner는 Pro 전용)
3. MCP Server 확장 로드 — BApp Store 또는 `./gradlew embedProxyJar` 후 `Extensions > Add > Java`
4. Burp MCP 탭에서 서버 Enable(`127.0.0.1:9876`) + 프록시 리스너(`127.0.0.1:8080`)
5. Claude Code에 MCP 등록:
   `claude mcp add burp -- <java> -jar mcp-proxy-all.jar --sse-url http://127.0.0.1:9876`

## Workflow

### 0단계 — 프리플라이트(필수)

```bash
python tools/burp_preflight.py --require proxy
# → [프리플라이트] 프록시(127.0.0.1:8080): OK / MCP(127.0.0.1:9876): OK
# 미가동이면 설치 온보딩을 출력하고 exit 1 — 안내대로 설정 후 재시도
```

MCP 도구까지 확인하려면 `--require both`. MCP 도구가 노출됐는지는 AI가 `send_http1_request`
등 Burp 도구 호출 가능 여부로 판단한다.

> ⚠ **Burp Proxy > Intercept는 반드시 OFF.** ON이면 프록시 경유 발사가 전부 멈춘다(hang).
> MCP 도구를 쓸 수 있으면 `set_proxy_intercept_state(false)`로 먼저 해제한다.

### 1단계 — 프록시 경유 발사(결정론 경로)

기존 4종을 Burp 프록시로 경유시킨다. `scope_guard`·판정·리포트가 그대로 유지되고
트래픽이 Burp 히스토리에 남는다. audit 경유가 가장 간단하다:

```bash
python skills/auditing-web-application-security/scripts/audit.py <소스경로> \
    --target http://localhost:8080 \
    --burp-proxy http://127.0.0.1:8080 \
    --user-a-id userA --user-a-pw '***' \
    --user-b-id userB --user-b-pw '***' --resource-id 1001
```

개별 스킬을 직접 돌릴 때는 환경변수로 프록시를 켠다(모든 `attack_*.py`가 상속):

```bash
export SECURITY_PLUGIN_BURP_PROXY=http://127.0.0.1:8080
python skills/exploiting-broken-access-control/scripts/attack_access.py \
    http://localhost:8080 --scan access.json --token-a "$TA" --token-b "$TB" --resource-id 1001
```

### 2단계 — MCP 보조 심화(대화형 경로)

프록시 경유로 잡힌 결과에 Burp 고유 강점을 더한다.

> ⚠ **한계(엣지 E):** MCP `send_http1_request`는 Burp가 직접 발사하므로 `scope_guard`가
> 코드로 개입할 수 없다(fail-open). 따라서 MCP 보조는 **1단계 프록시 경유로 이미 scope 통과가
> 확인된 호스트에만** 사용한다. 그리고 시작 전 `set_proxy_intercept_state(false)`로 Intercept를 해제한다.

**발사 전 대상 호스트를 `scope_guard`로 반드시 사전 검증**한다(화이트리스트, fail-closed):

```bash
python tools/scope_guard.py "http://localhost:8080/api/v1/users/me"
# ALLOW 가 나온 호스트에만 MCP 발사
```

- **인증세션(JWT 변조):** `get_proxy_http_history_regex`로 로그인 응답의 토큰을 찾고,
  `base64_decode`로 헤더/페이로드를 디코드 → `alg:none`·역할 변조·만료 조작 →
  `base64_encode` → `send_http1_request`로 재발사. **변조 토큰이 4xx면 안전(정상), 2xx면 취약 확정.**
- **접근통제(IDOR/BFLA):** 히스토리에서 A 세션 요청을 캡처 → 쿠키/토큰만 B로 치환 →
  `send_http1_request`. **IDOR에서 403이면 즉시 오탐 확정, `200 + 타인 데이터`만 취약.**
  BFLA는 일반 세션이 관리자 기능을 2xx로 수행 시 확정.
- **SSRF 블라인드:** Pro면 `generate_collaborator_payload` → 주입 → `get_collaborator_interactions`
  콜백 확인. Community면 기존 `oob_canary.py` 폴백.
- **경로조작:** `url_encode`로 `../` 변형 → `send_http1_request` → 응답에 파일 시그니처
  (`/etc/passwd`·`web.xml`) 인밴드 확인.

### 3단계 — 통합 리포트

프록시 경유(결정론)와 MCP 보조(대화형) 결과를 기존 **4요소 Evidence 리포트**
(What/Why/How/Fix)로 통합한다. Burp의 실제 요청/응답 원문을 Evidence로 첨부한다.
판정 기준은 기존 스크립트를 계승한다(과대표기 금지: static-only·미확정 3상태 유지).

## Verification (스킬 신뢰성)

- [ ] `burp_preflight.py`가 프록시 미가동 시 온보딩을 출력하고 exit 1 하는가
- [ ] `SECURITY_PLUGIN_BURP_PROXY` 없이 실행 시 기존 발사와 동일(프록시 미경유)한가
- [ ] 프록시 경유해도 운영 호스트(`www.*`)가 `scope_guard`로 차단되는가
- [ ] MCP 발사 전 대상 호스트를 `scope_guard`로 사전 검증했는가
- [ ] JWT 변조 토큰이 4xx면 안전으로 판정하는가

## Tools & Systems

- `tools/burp_preflight.py` — 프리플라이트 프로브 + 온보딩
- `tools/dyn_session.py` — `SECURITY_PLUGIN_BURP_PROXY` 프록시 경유
- `tools/scope_guard.py` — 안전 게이트(프록시·MCP 양 경로 공통)
- `references/burp-engine.md` — MCP 도구 사용법·JWT 변조 절차
- Burp MCP 도구: `send_http1_request`, `get_proxy_http_history(_regex)`, `base64_encode/decode`,
  `url_encode/decode`, `generate_collaborator_payload`(Pro)
````

- [ ] **Step 4: references/burp-engine.md 작성**

`skills/exploiting-with-burp/references/burp-engine.md`:

````markdown
# Burp MCP 엔진 레퍼런스

## 프록시 경유(결정론) vs MCP 보조(대화형)

| 구분 | 경로 | 판정 | scope 강제 |
|------|------|------|-----------|
| 프록시 경유 | `attack_*.py` → dyn_session → Burp 프록시 | 스크립트(결정론) | dyn_session `assert_in_scope` |
| MCP 보조 | AI → `send_http1_request` 등 | AI(스크립트 기준 계승) | SKILL이 `scope_guard` 사전 호출 |

## 프록시 설정

- 환경변수 `SECURITY_PLUGIN_BURP_PROXY=http://127.0.0.1:8080` → dyn_session이 requests에
  `proxies`+`verify=False`(Burp TLS MITM 대응) 적용.
- 값이 없거나 공백이면 프록시 미경유(기존 발사와 바이트 동일).

## 주요 MCP 도구(27종 중 4종 워크플로 사용분)

- `send_http1_request` / `send_http2_request` — raw HTTP 발사 후 응답 반환(핵심)
- `get_proxy_http_history` / `get_proxy_http_history_regex` — 살아있는 세션 요청 재료
- `base64_encode` / `base64_decode` — JWT 헤더·페이로드 변조
- `url_encode` / `url_decode` — 경로조작 `../` 변형
- `generate_collaborator_payload` / `get_collaborator_interactions` — 블라인드 SSRF(Pro 전용)

## JWT 변조 절차(인증세션)

1. `get_proxy_http_history_regex`로 `Authorization: Bearer` 또는 `Set-Cookie`의 JWT 확보
2. `base64_decode`로 헤더(`{"alg":"HS256",...}`)·페이로드(`{"role":"user",...}`) 디코드
3. 변조: `alg:none`(서명 제거) / `role:admin`(권한 상승) / `exp` 과거(만료 무시)
4. `base64_encode`로 재조립 → `send_http1_request`로 보호 엔드포인트에 발사
5. 판정: **4xx 거부 = 안전(정상), 2xx 수용 = 취약 확정**

> ⚠ **base64url 주의(엣지 D):** JWT는 URL-safe base64(`-`/`_`, 무패딩)다. Burp `base64_decode`가
> 표준 base64만 지원하면 디코드가 깨진다 — 이 경우 `url_decode`+수동 패딩 보정으로 처리하거나
> 기존 `attack_auth.py`의 JWT 변조 경로(`--probe`)를 사용한다. **구현 전 Burp base64의 URL-safe
> 지원 여부를 확인**한다.

## 판정 기준(기존 스크립트 계승)

- IDOR: `403` 즉시 오탐 확정 / `200 + 타인 데이터`만 취약
- BFLA: 일반 세션 2xx AND 익명 non-2xx = 취약(공개 엔드포인트 제외)
- 토큰 변조: 변조본 4xx = 안전 / 2xx = 취약
- SSRF: OOB 콜백 수신만 취약 확정(미수신은 방어 아님·미확정)
- 경로조작: 응답에 파일 시그니처 검출 시 취약
````

- [ ] **Step 5: 통과 확인**

Run: `python -m pytest tests/test_exploiting_with_burp_meta.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: 커밋**

```bash
git add skills/exploiting-with-burp/ tests/test_exploiting_with_burp_meta.py
git commit -m "feat: exploiting-with-burp 스킬 문서(하이브리드 MCP 워크플로)"
```

---

### Task 5: 문서 반영 — 오케스트레이터·README·버전 정합

**Files:**
- Modify: `skills/auditing-web-application-security/SKILL.md` (--burp-proxy 옵션 + 프리플라이트 문서화)
- Modify: `README.md` (스킬 목록에 exploiting-with-burp 추가)
- Test: `tests/test_version_consistency.py` (기존 — 신규 스킬 포함해 통과 확인)

**Interfaces:**
- Consumes: Task 1~4 전체
- Produces: 사용자 문서에 하이브리드 경로 노출. 버전 정합성 테스트 통과.

- [ ] **Step 1: 기존 버전 정합성 테스트를 먼저 실행해 요구사항 파악**

Run: `python -m pytest tests/test_version_consistency.py -v`
Expected: 신규 스킬 추가로 실패할 수 있음 — 실패 메시지가 요구하는 필드(예: 스킬 인덱스·버전 표)를 확인한다. 통과하면 이 태스크는 문서 추가만 수행한다.

- [ ] **Step 2: 오케스트레이터 SKILL.md에 --burp-proxy 문서 추가**

`skills/auditing-web-application-security/SKILL.md`의 동적 옵션 설명 섹션에 다음을 추가:

```markdown
### Burp 프록시 경유(하이브리드, 선택)

`--burp-proxy http://127.0.0.1:8080` 지정 시 모든 동적 발사가 Burp 프록시를 경유해
트래픽이 Burp 히스토리에 축적된다(판정·scope_guard 불변). 발사 전
`tools/burp_preflight.py`가 Burp 가동을 확인하고, 미가동이면 설치 온보딩을 출력한 뒤
기존 스크립트 경로로 폴백한다. Burp 고유 심화(JWT 변조·Collaborator)는
`exploiting-with-burp` 스킬을 참조한다.
```

- [ ] **Step 3: README에 신규 스킬 등재**

`README.md`의 스킬/exploiting 목록에 한 줄 추가(기존 항목 포맷을 따른다):

```markdown
- `exploiting-with-burp` — Burp MCP 하이브리드(접근통제·인증세션·SSRF·경로조작 4종): 프록시 경유(결정론) + MCP 보조 심화
```

- [ ] **Step 4: 버전 정합성 통과 확인**

Run: `python -m pytest tests/test_version_consistency.py -v`
Expected: PASS. (실패 시 Step 1에서 파악한 인덱스/버전 표에 `exploiting-with-burp`·`version 0.1.0`을 반영한 뒤 재실행)

- [ ] **Step 5: 전체 회귀 스위트**

Run: `python -m pytest tests/ -q`
Expected: 전체 PASS(신규 포함, 기존 38개 무회귀)

- [ ] **Step 6: 커밋**

```bash
git add skills/auditing-web-application-security/SKILL.md README.md
git commit -m "docs: 하이브리드 Burp 경로 문서화(오케스트레이터·README) + 버전 정합"
```

---

## Self-Review (작성자 점검 결과)

**Spec coverage:**
- 범위(4종 연동/2종 유지) → Task 4 SKILL.md When to Use ✓
- 프록시 경유(dyn_session) → Task 2 ✓
- MCP 보조(SKILL 문서) → Task 4 ✓
- 프리플라이트 온보딩 → Task 1 + Task 3 게이트 ✓
- scope_guard 유지 → Task 2(프록시가 dyn_session 경유이므로 자동) + Task 4 Verification ✓
- 오케스트레이터 배선 → Task 3 ✓
- 환경 전제/폴백 → Task 1 onboarding + Task 3 폴백 ✓

**Placeholder scan:** 모든 코드 스텝에 실제 코드 포함. TBD/TODO 없음.

**Type consistency:** `_burp_proxies`/`_proxy_kwargs`(Task 2), `probe_port`/`split_hostport`/`check`/
`onboarding_text`(Task 1), `_apply_burp_proxy`(Task 3) 시그니처가 태스크 간 일치.

**엣지케이스 반영(A~G):** Intercept OFF 경고(A: Task 1 onboarding·Task 3 활성 메시지·Task 4 SKILL),
`verify=False` 경고 억제(B: Task 2 `_proxy_kwargs`), `--burp-proxy-strict`(C: Task 3),
base64url 주의(D: Task 4 references), MCP scope fail-open 한계 명시(E: Task 4 SKILL),
로그인 프록시 오류 힌트(F: Task 2 `login`/`login_response`), `report["burp_proxy"]` 노출(G: Task 3).

**미확정 리스크(구현 중 확인):** `test_version_consistency.py`의 정확한 요구는 Task 5 Step 1에서
실행으로 파악한다(레포별 인덱스 규약이 있을 수 있음). Burp `base64` 도구의 URL-safe 지원 여부는
Task 4 구현 전 실제 확인한다(미지원 시 D 폴백 적용).
