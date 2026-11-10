"""Small ordered work windows with context propagation and joined cancellation."""
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextvars import copy_context
import threading


def ordered_bounded_map(fn, items, *, workers=4, max_pending=8):
    """Yield in input order; consumers that stop early must explicitly close.

    Pending includes completed results that have not yet been consumed. On an
    observed worker failure, discard that pending suffix, cancel queued work,
    and join running workers before propagating the original exception.
    """
    if (type(workers) is not int or not 1 <= workers <= 4 or
            type(max_pending) is not int or not 1 <= max_pending <= 8):
        raise ValueError('Parallel work requires 1-4 workers and 1-8 pending items')
    iterator = iter(items)
    pending = deque()
    failures = []
    failure_lock = threading.RLock()
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='gxsec-input')

    def observe(future):
        if not future.cancelled():
            problem = future.exception()
            if problem is not None:
                with failure_lock:
                    if not failures:
                        failures.append(problem)

    def check_failure():
        with failure_lock:
            if failures:
                raise failures[0]

    exhausted = False
    try:
        while pending or not exhausted:
            while not exhausted and len(pending) < max_pending:
                check_failure()
                try:
                    item = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                # Serialize only submission/error observation, never source I/O.
                with failure_lock:
                    check_failure()
                    future = executor.submit(copy_context().run, fn, item)
                    pending.append(future)
                    future.add_done_callback(observe)
            check_failure()
            if not pending:
                break
            while not pending[0].done():
                wait([future for future in pending if not future.done()], return_when=FIRST_COMPLETED)
                check_failure()
            check_failure()
            yield pending.popleft().result()
    except Exception:
        # An input iterator can also fail while a submitted task is failing.
        # Preserve an already observed worker error rather than a cancellation.
        check_failure()
        raise
    finally:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
