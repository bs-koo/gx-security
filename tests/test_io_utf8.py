# tests/test_io_utf8.py
"""tools/io_utf8.py 회귀 테스트 (P4 Task 1 — ⑤ 인코딩 근본 수정).

배경: Windows(cp949) 콘솔/파이프에서 이전 패턴
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
은 reconfigure()가 예외를 던지는 환경에서 아무 폴백 없이 스트림을 깨진 채로
남겨, 이후 em-dash(—) 같은 cp949 미표현 문자를 print()하면 UnicodeEncodeError로
크래시했다. tools/io_utf8.configure()는 이 경우 버퍼를 TextIOWrapper(encoding=
"utf-8")로 재감싸 복구하고, emit_json()은 JSON을 sys.stdout.buffer에 UTF-8
바이트로 직접 기록해 콘솔 코덱 자체를 우회한다.

주의(경험적으로 검증한 사실 — 아래 서브프로세스 테스트 설계 근거):
  sys.stdout은 쓰기 전용이라 CPython에서 reconfigure(encoding=...)는 사실상
  거의 항상 성공한다(문서상 "encoding 변경 제한"은 스트림에서 이미 read()가
  일어난 경우에만 적용됨). 즉 `PYTHONIOENCODING=cp949`만 강제해서는 구코드도
  reconfigure에 성공해 크래시가 재현되지 않는다(직접 확인함). 그래서
  test_scan_secrets_survives_broken_console_codec()는 sys.stdout/stderr를
  "reconfigure()가 예외를 던지는" 스트림으로 실제로 대체(sabotage)한 뒤
  실제 스캐너 스크립트를 하위 프로세스에서 실행해, io_utf8 도입 전에는
  UnicodeEncodeError로 죽고(FAIL) 도입 후에는 정상 종료(PASS)하는지 검증한다.
"""
import io
import json
import os
import string
import subprocess
import sys
import tempfile
import unittest

from tools import io_utf8

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_SECRETS = os.path.join(
    ROOT, "skills", "detecting-sensitive-data-exposure", "scripts", "scan_secrets.py")
SCOPE_GUARD = os.path.join(ROOT, "tools", "scope_guard.py")


class _NoReconfigureStream:
    """reconfigure()가 없는(예외를 던지는) 스트림을 흉내낸다 — io_utf8.configure()의
    폴백(TextIOWrapper 재감쌈)을 유닛 테스트 수준에서 결정적으로 검증하기 위한 더블.

    .buffer는 실제 바이너리 버퍼를 그대로 노출해, configure()의 폴백이
    `getattr(stream, "buffer", None)`으로 그 버퍼를 재사용할 수 있게 한다.
    """

    def __init__(self, buffer, encoding="cp949"):
        self.buffer = buffer
        self.encoding = encoding
        self.errors = "strict"

    def write(self, s):
        return self.buffer.write(s.encode(self.encoding, self.errors))

    def flush(self):
        self.buffer.flush()

    def isatty(self):
        return False

    def reconfigure(self, **kwargs):
        raise ValueError("simulated: reconfigure unavailable on this stream")


class TestConfigureFallback(unittest.TestCase):
    """io_utf8.configure()가 reconfigure() 불가 스트림에서도 복구하는지 유닛 검증."""

    def test_configure_falls_back_to_textiowrapper_and_prevents_crash(self):
        real_buf = io.BytesIO()
        fake = _NoReconfigureStream(real_buf)
        old_stdout = sys.stdout
        sys.stdout = fake
        try:
            io_utf8.configure()
            # 폴백이 발동해 sys.stdout이 실제 TextIOWrapper로 교체됐어야 한다
            # (구코드의 "except: pass"였다면 fake가 그대로 남아있었을 것).
            self.assertIsNot(sys.stdout, fake)
            self.assertIsInstance(sys.stdout, io.TextIOWrapper)
            # em-dash는 cp949 strict에서 크래시 트리거 — 폴백이 정말 utf-8인지 확인
            print("한글 테스트 — em dash 확인")
            sys.stdout.flush()
            # sys.stdout(새 TextIOWrapper)이 살아있는 동안(= real_buf가 close되기 전) 값을 읽는다.
            # sys.stdout을 먼저 복원하면 새 TextIOWrapper의 참조가 사라져 GC가 즉시 close()를
            # 호출하고, close()는 기본적으로 감싼 real_buf까지 닫아 이후 getvalue()가
            # "I/O operation on closed file"로 죽는다.
            text = real_buf.getvalue().decode("utf-8")
        finally:
            sys.stdout = old_stdout
        self.assertIn("—", text)   # em-dash 원문 보존
        self.assertIn("한글", text)      # 한글 원문 보존

    def test_configure_noop_when_stream_missing(self):
        """sys.stdout/stderr가 None이어도(pythonw.exe 등) crash하지 않는다."""
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = None, None
        try:
            io_utf8.configure()   # 예외 없이 조용히 지나가야 함
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr


class TestEmitJsonBackwardCompat(unittest.TestCase):
    """emit_json()이 기존 print(json.dumps(obj, ensure_ascii=False, indent=2))와
    ASCII-safe 페이로드에 대해 바이트 동일한지 검증 (하위호환 계약)."""

    def test_emit_json_byte_identical_to_legacy_print(self):
        obj = {"target": "x", "candidates": [{"file": "a.py", "line": 1}], "note": "ok"}
        expected = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

        real_buf = io.BytesIO()
        wrapper = io.TextIOWrapper(real_buf, encoding="utf-8", errors="replace")
        old_stdout = sys.stdout
        sys.stdout = wrapper
        try:
            io_utf8.emit_json(obj)
        finally:
            sys.stdout = old_stdout
        self.assertEqual(real_buf.getvalue(), expected)

    def test_emit_json_preserves_korean_and_em_dash(self):
        obj = {"snippet": "db.password=hunter2 — 한글 주석 확인"}
        real_buf = io.BytesIO()
        wrapper = io.TextIOWrapper(real_buf, encoding="utf-8", errors="replace")
        old_stdout = sys.stdout
        sys.stdout = wrapper
        try:
            io_utf8.emit_json(obj)
        finally:
            sys.stdout = old_stdout
        parsed = json.loads(real_buf.getvalue().decode("utf-8"))
        self.assertEqual(parsed, obj)


# ── 서브프로세스 회귀 테스트 — 실제 스캐너를 깨진 콘솔 코덱에서 실행 ──────────
_BOOTSTRAP_SRC = string.Template(r'''
import runpy
import sys


class _NoReconfigureStream:
    """reconfigure()가 없는(예외를 던지는) 스트림을 흉내낸다.
    .buffer는 실제 바이너리 버퍼를 그대로 노출해 io_utf8.configure()의 폴백
    (TextIOWrapper 재감쌈)이 성공할 수 있게 한다 -- 이 폴백이 없던 구코드
    (try: reconfigure() except: pass)는 여기서 그대로 깨져야 정상이다.
    """

    def __init__(self, buffer):
        self.buffer = buffer
        self.encoding = "cp949"
        self.errors = "strict"

    def write(self, s):
        return self.buffer.write(s.encode(self.encoding, self.errors))

    def flush(self):
        self.buffer.flush()

    def isatty(self):
        return False

    def reconfigure(self, **kwargs):
        raise ValueError("simulated: reconfigure unavailable on this stream")


sys.stdout = _NoReconfigureStream(sys.stdout.buffer)
sys.stderr = _NoReconfigureStream(sys.stderr.buffer)

sys.argv = $argv_repr
runpy.run_path($script_repr, run_name="__main__")
''')


def _run_sabotaged_subprocess(script_path, argv, *, extra_env=None, timeout=30):
    """script_path를 하위 프로세스에서 실행하되, 그 프로세스 안의 sys.stdout/stderr를
    "reconfigure() 불가 + cp949 strict" 스트림으로 먼저 바꿔치기한다(Task 1 Round 1
    공용 헬퍼 — scan_secrets.py·scope_guard.py 회귀 테스트가 공유)."""
    bootstrap_src = _BOOTSTRAP_SRC.substitute(
        script_repr=repr(script_path), argv_repr=repr([script_path] + list(argv)))
    fd, bootstrap_path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as bf:
            bf.write(bootstrap_src)
        env = dict(os.environ)
        env.update(extra_env or {})
        return subprocess.run(
            [sys.executable, bootstrap_path],
            capture_output=True, timeout=timeout, env=env,
        )
    finally:
        os.unlink(bootstrap_path)


class TestScanSecretsCP949Regression(unittest.TestCase):
    """Step 1 회귀 테스트: io_utf8 도입 전 FAIL(UnicodeEncodeError)·도입 후 PASS.

    scan_secrets.py를 하위 프로세스로 실행하되, 그 프로세스 안에서 stdout/stderr를
    "reconfigure() 불가 + cp949 strict" 스트림으로 미리 바꿔치기(sabotage)한 뒤
    실제 스크립트 파일을 실행한다. em-dash·한글이 섞인 후보가 크래시 없이
    JSON으로 나오는지 확인한다.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # scan_secrets.py의 hardcoded-password-properties 규칙에 걸리는 라인에
        # em-dash(—)와 한글을 함께 심는다 — cp949 strict에서 em-dash가 크래시를 유발한다
        # (한글 자체는 cp949로 인코딩 가능하므로 em-dash 없이는 재현되지 않는다).
        fixture_path = os.path.join(self.tmp.name, "app.properties")
        with open(fixture_path, "w", encoding="utf-8") as f:
            f.write("db.password=hunter2 — 한글 주석 확인\n")
        self.fixture_dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_secrets_survives_broken_console_codec(self):
        out = _run_sabotaged_subprocess(
            SCAN_SECRETS, [self.fixture_dir, "--json"],
            extra_env={"GXSEC_NO_SEMGREP": "1"})   # 폴백 경로 강제 — semgrep 설치 여부와 무관한 결정적 테스트
        self.assertEqual(
            out.returncode, 0,
            msg=(f"scan_secrets.py가 콘솔 코덱이 깨진 환경(reconfigure 불가)에서 "
                 f"크래시했다. stderr={out.stderr.decode('utf-8', errors='replace')!r}"))
        # stdout 자체가 유효한 UTF-8이어야 한다(디코드가 크래시하지 않아야 함)
        text = out.stdout.decode("utf-8")
        data = json.loads(text)
        snippets = " ".join(c.get("snippet", "") for c in data.get("candidates", []))
        self.assertIn("—", snippets)   # em-dash 원문 보존(치환/삭제되지 않음)
        self.assertIn("한글", snippets)  # 한글("한글") 원문 보존


class TestScopeGuardCP949Regression(unittest.TestCase):
    """Task 1 Round 1 회귀 테스트: tools/scope_guard.py 단독 CLI 경로.

    commands/gx-pentest.md Step 0이 사용자에게 직접 실행시키는 실경로
    (`python tools/scope_guard.py <URL>`)다. deny 판정 메시지
    (assert_in_scope의 "[차단] ... — 운영/위험 대상으로 보입니다. 공격 중단.")에
    em-dash가 들어있고 __main__ 블록이 이를 print(e)로 출력하므로, 콘솔 코덱이
    깨진 환경에서는 io_utf8 도입 전 UnicodeEncodeError로 죽었어야 한다.
    """

    def test_scope_guard_deny_message_survives_broken_console_codec(self):
        # prod.example.com은 _DENY_HOST_PATTERNS(운영 의심)에 매치 → ScopeError →
        # __main__이 print(e); sys.exit(1) — 크래시가 아니라 "정상적인 차단"이 rc=1이다.
        out = _run_sabotaged_subprocess(SCOPE_GUARD, ["http://prod.example.com"])
        self.assertEqual(
            out.returncode, 1,
            msg=(f"scope_guard.py CLI가 예상과 다르게 종료됨(rc={out.returncode}). "
                 f"stderr={out.stderr.decode('utf-8', errors='replace')!r}"))
        stderr_text = out.stderr.decode("utf-8", errors="replace")
        self.assertNotIn("UnicodeEncodeError", stderr_text)
        self.assertNotIn("Traceback", stderr_text)
        stdout_text = out.stdout.decode("utf-8")   # 디코드 자체가 크래시하지 않아야 함
        self.assertIn("차단", stdout_text)
        self.assertIn("—", stdout_text)   # em-dash 원문 보존(deny 메시지 " — 운영/위험 대상으로...")

    def test_scope_guard_importable_as_tools_package(self):
        """from tools import scope_guard 경로(dyn_session.py가 쓰는 경로)가 여전히 동작."""
        out = subprocess.run(
            [sys.executable, "-c",
             "from tools import scope_guard; print(scope_guard.classify('http://localhost')[0])"],
            capture_output=True, text=True, cwd=ROOT, timeout=10,
        )
        self.assertEqual(out.returncode, 0, msg=out.stderr)
        self.assertEqual(out.stdout.strip(), "allow")


class TestPythonUtf8Propagation(unittest.TestCase):
    """configure()가 자식 프로세스용 PYTHONUTF8=1을 전파하는지 검증(cp949 semgrep 회귀 가드).

    Windows 한국어(cp949)에서 semgrep은 config(룰) 파일을 인코딩 미지정 read_text()로 읽어
    OS 기본 코덱(cp949)으로 디코딩하므로, 한글 message가 담긴 UTF-8 룰이 로드 실패 →
    룰 전체 무효화 → grep-폴백(저정밀) 강등된다. io_utf8.configure()가 PYTHONUTF8=1을
    setdefault해 자식 semgrep이 UTF-8 모드로 뜨게 함으로써 이를 막는다. 이 계약이 제거되면
    cp949 환경에서 정밀 진단이 조용히 강등되므로 회귀 테스트로 고정한다."""

    def setUp(self):
        self._saved = os.environ.get("PYTHONUTF8")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("PYTHONUTF8", None)
        else:
            os.environ["PYTHONUTF8"] = self._saved

    def test_configure_sets_pythonutf8_when_unset(self):
        os.environ.pop("PYTHONUTF8", None)
        io_utf8.configure()
        self.assertEqual(os.environ.get("PYTHONUTF8"), "1",
                         "configure()가 PYTHONUTF8=1을 전파해야 한다(cp949 semgrep 크래시 방지)")

    def test_configure_respects_existing_pythonutf8(self):
        os.environ["PYTHONUTF8"] = "0"   # 사용자가 명시적으로 끈 경우 존중(setdefault)
        io_utf8.configure()
        self.assertEqual(os.environ.get("PYTHONUTF8"), "0",
                         "setdefault라 이미 설정된 값을 덮어쓰지 않아야 한다")


if __name__ == "__main__":
    unittest.main()
