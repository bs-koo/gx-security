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
바이트 동일(하위호환 — 기존 stdout 캡처 테스트가 그대로 통과해야 한다).
"""
import io
import json
import sys


def configure():
    """sys.stdout/stderr를 UTF-8·errors=replace로 강제. 실패 시 TextIOWrapper 폴백."""
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
