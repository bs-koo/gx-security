#!/usr/bin/env python3
"""tools/io_utf8.py

JSON 계약을 콘솔 코덱에서 분리한다 — Windows(cp949) 파이프/캡처 크래시 근본 방지.

configure(): sys.stdout/stderr를 UTF-8·errors=replace로 강제한다. reconfigure()가
불가능한 환경(스트림이 .reconfigure를 지원하지 않거나 예외를 던지는 경우)은
버퍼를 재사용한 TextIOWrapper로 폴백한다 — 기존 "try: reconfigure() except: pass"는
폴백이 없어 이 경우 스트림이 깨진 채로 남아 이후 print()가 UnicodeEncodeError로
크래시할 수 있었다(회귀 테스트: tests/test_io_utf8.py).

emit_json(): JSON을 sys.stdout.buffer에 UTF-8 바이트로 직접 기록해 콘솔 코덱과
완전히 무관하게 만든다(텍스트 인코더를 우회). 기존
print(json.dumps(obj, ensure_ascii=False, indent=2))와 ASCII-safe 페이로드에 대해
POSIX에서는 바이트 동일하다. Windows에서는 텍스트 래퍼의 개행 번역(\\n→\\r\\n)을 우회하므로
JSON 내부 개행이 LF로 나온다 — 기능 영향은 없다(소비자는 모두 json.loads 또는 universal-newline
캡처라 개행 스타일 무관). 즉 "콘텐츠 동일, 개행 스타일은 POSIX 기준"이 정확한 서술이다.
"""
import io
import json
import os
import sys


def configure():
    """sys.stdout/stderr를 UTF-8·errors=replace로 강제. 실패 시 TextIOWrapper 폴백.

    또한 PYTHONUTF8=1을 프로세스 환경에 전파해, 이 스크립트가 subprocess로 실행하는
    semgrep 등 자식 프로세스가 Windows 한국어(cp949) 로케일에서 UTF-8 룰 파일을 읽다
    UnicodeDecodeError로 크래시하는 것을 막는다. semgrep은 config 파일을 인코딩 미지정
    read_text()로 읽어 OS 기본 코덱(cp949)으로 디코딩하므로, 한글 message가 담긴 UTF-8
    룰이 cp949에서 로드 실패 → 룰 전체 무효화 → grep-폴백(저정밀) 강등된다. setdefault라
    이미 설정된 값은 존중한다(회귀 테스트: tests/test_io_utf8.py)."""
    os.environ.setdefault("PYTHONUTF8", "1")
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            buf = getattr(stream, "buffer", None)
            if buf is not None:
                setattr(sys, name, io.TextIOWrapper(
                    buf, encoding="utf-8", errors="replace", line_buffering=True))


def emit_json(obj, *, indent=2):
    """JSON을 콘솔 코덱과 무관하게 stdout에 UTF-8 바이트로 직접 기록한다.

    buffer가 없는 극단적 환경(예: buffer 속성이 없는 커스텀 stdout 대체)에서만
    print() 폴백을 사용한다 — 이 폴백 경로는 콘솔 코덱에 여전히 의존한다.

    주의(순서 위험): sys.stdout.buffer에 직접 쓰기 때문에 sys.stdout(텍스트
    래퍼)의 내부 버퍼를 우회한다. 이 함수 호출 "직전"에 flush 안 된
    print()/sys.stdout.write()가 남아있으면 출력 순서가 뒤바뀔 수 있다 —
    이 분기 앞에 버퍼링된 print()를 추가하지 말 것(추가한다면 먼저
    sys.stdout.flush()할 것).
    """
    data = json.dumps(obj, ensure_ascii=False, indent=indent)
    buf = getattr(sys.stdout, "buffer", None)
    if buf is not None:
        buf.write(data.encode("utf-8"))
        buf.write(b"\n")
        buf.flush()
    else:
        print(data)
