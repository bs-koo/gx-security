"""Bounded execution accounting. Progress carries counts, never source content."""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import math
import sys
import threading
import time

_active = ContextVar('gxsec_execution', default=None)


class BudgetExceeded(RuntimeError):
    def __init__(self, reason, stage):
        self.diagnostic = {'type': 'execution_budget_exceeded', 'reason': reason, 'stage': stage}
        super().__init__('Execution budget exceeded: ' + reason + ' at ' + stage)


class Execution:
    def __init__(self, seconds, max_input_bytes, stream, clock, heartbeat_seconds):
        if (isinstance(seconds, bool) or not math.isfinite(seconds) or seconds <= 0
                or type(max_input_bytes) is not int or max_input_bytes <= 0):
            raise ValueError('Execution duration and input byte limits must be positive and finite')
        self.seconds, self.max_input_bytes = float(seconds), max_input_bytes
        self.clock, self.started = clock, clock()
        self.stream = stream
        self.stage = 'preparation'
        self.bytes_read = self.files = self.input_bytes = 0
        self.phases = {}
        self.failure = None
        self.interval = max(0.01, float(heartbeat_seconds))
        self.stop = threading.Event()
        self.lock = threading.RLock()

    def check(self):
        reason = ('duration' if self.clock() - self.started >= self.seconds else
                  'input_bytes' if self.input_bytes > self.max_input_bytes else None)
        if reason:
            error = BudgetExceeded(reason, self.stage)
            if self.failure is None:
                self.failure = error.diagnostic
            raise error

    def emit(self, event):
        with self.lock:
            data = {'event': event, 'stage': self.stage,
                    'elapsed_seconds': round(self.clock() - self.started, 3),
                    'bytes_read': self.bytes_read, 'files': self.files}
            try:
                self.stream.write('[gxsec] ' + json.dumps(data, ensure_ascii=True) + '\n')
                self.stream.flush()
            except (OSError, ValueError):
                pass

    def heartbeat(self):
        while not self.stop.wait(self.interval):
            self.emit('heartbeat')

    def summary(self):
        return {'elapsed_seconds': round(self.clock() - self.started, 3),
                'max_duration_seconds': self.seconds, 'max_input_bytes': self.max_input_bytes,
                'input_scope': 'working-tree-files',
                'input_bytes': self.input_bytes, 'bytes_read': self.bytes_read, 'files': self.files,
                'phases': {name: dict(value) for name, value in self.phases.items()},
                'budget_exceeded': self.failure}


@contextmanager
def session(seconds, *, max_input_bytes, stream=None, clock=time.monotonic, heartbeat_seconds=5):
    budget = Execution(seconds, max_input_bytes, stream if stream is not None else sys.stderr,
                       clock, heartbeat_seconds)
    token = _active.set(budget)
    worker = threading.Thread(target=budget.heartbeat, daemon=True, name='gxsec-progress')
    budget.emit('started')
    worker.start()
    try:
        yield budget
    finally:
        budget.stop.set()
        worker.join(timeout=1)
        budget.emit('finished')
        _active.reset(token)


@contextmanager
def phase(name):
    budget = _active.get()
    if budget is None:
        yield
        return
    if not isinstance(name, str) or not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in name):
        raise ValueError('Execution phase must be a fixed non-sensitive identifier')
    previous = budget.stage
    budget.stage = name
    started = budget.clock()
    with budget.lock:
        row = budget.phases.setdefault(name, {'seconds': 0, 'bytes_read': 0, 'files': 0, 'calls': 0})
        row['calls'] += 1
    budget.emit('phase-started')
    try:
        budget.check()
        yield
    finally:
        with budget.lock:
            row['seconds'] = round(row['seconds'] + budget.clock() - started, 6)
        budget.emit('phase-finished')
        budget.stage = previous


def checkpoint(*, bytes_read=0, files=0):
    budget = _active.get()
    if budget is not None:
        with budget.lock:
            budget.bytes_read += bytes_read
            budget.files += files
            row = budget.phases.get(budget.stage)
            if row is not None:
                row['bytes_read'] += bytes_read
                row['files'] += files
        budget.check()


def admit_input(size):
    budget = _active.get()
    if budget is not None:
        budget.input_bytes += size
        budget.check()


def timeout_for(seconds):
    budget = _active.get()
    if budget is None:
        return seconds
    budget.check()
    return max(0.001, min(float(seconds), budget.seconds - (budget.clock() - budget.started)))


def current():
    return _active.get()
