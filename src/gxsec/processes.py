"""Capture native process output within a shared memory cap and deadline."""
import os
import signal
import subprocess
import threading
import time

from .diagnostics import MAX_JSON_BYTES, OutputLimitExceeded


def bounded_run(command, *, cwd, env, timeout, shell=False):
    if shell:
        raise ValueError('Native engines cannot use a shell')
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(command, cwd=cwd, env=env, shell=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=os.name != 'nt')
    lock, overflow = threading.Lock(), threading.Event()
    buffers, total = [bytearray(), bytearray()], [0]

    def stop():
        if os.name != 'nt':
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()

    def drain(stream, index):
        try:
            while True:
                block = stream.read(65536)
                if not block:
                    return
                with lock:
                    total[0] += len(block)
                    if total[0] > MAX_JSON_BYTES:
                        overflow.set()
                        stop()
                        return
                    buffers[index].extend(block)
        except (OSError, ValueError):
            overflow.set()
            stop()

    threads = [threading.Thread(target=drain, args=(stream, index), daemon=True)
               for index, stream in enumerate((process.stdout, process.stderr))]
    for thread in threads:
        thread.start()
    try:
        while process.poll() is None or any(thread.is_alive() for thread in threads):
            if overflow.is_set():
                raise OutputLimitExceeded('Engine exceeded its shared output limit')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            if process.poll() is None:
                try:
                    process.wait(timeout=min(0.05, remaining))
                except subprocess.TimeoutExpired:
                    pass
            else:
                for thread in threads:
                    thread.join(timeout=min(0.01, remaining))
        if overflow.is_set():
            raise OutputLimitExceeded('Engine exceeded its shared output limit')
        return subprocess.CompletedProcess(command, process.returncode,
            *(bytes(buffer).decode('utf-8', errors='replace') for buffer in buffers))
    finally:
        stop()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        for index, thread in enumerate(threads):
            thread.join(timeout=0.1)
            if not thread.is_alive():
                (process.stdout, process.stderr)[index].close()
