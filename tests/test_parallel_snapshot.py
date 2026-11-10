"""Bounded parallel work must drain before snapshot cleanup or engine use."""
from contextlib import closing
from contextvars import ContextVar, copy_context
import hashlib
import importlib
import io
import os
from pathlib import Path
import threading
import time

import pytest

from gxsec import execution, snapshot, source


def parallel_map():
    return importlib.import_module('gxsec.parallel').ordered_bounded_map


def fixture_inventory(root, count=6):
    root.mkdir()
    rows = []
    for index in range(count):
        path = f'nested/file-{index}.txt'
        target = root / path
        target.parent.mkdir(exist_ok=True)
        data = f'fixture-{index}'.encode()
        target.write_bytes(data)
        rows.append({'path': path, 'hash': hashlib.sha256(data).hexdigest(), 'size': len(data)})
    return {'files': [row['path'] for row in rows], 'inventory': rows,
            'hash': 'a' * 64, 'revision': 'fixture', 'exclusions': []}


def test_map_bounds_workers_and_all_unconsumed_results():
    barrier = threading.Barrier(4)
    lock = threading.Lock()
    active = peak = pulled = consumed = outstanding = 0

    def items():
        nonlocal pulled, outstanding
        for item in range(24):
            with lock:
                pulled += 1
                outstanding = max(outstanding, pulled - consumed)
            yield item

    def work(item):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        if item < 4:
            barrier.wait(timeout=3)
        time.sleep(0.002)
        with lock:
            active -= 1
        return item

    results = []
    with closing(parallel_map()(work, items())) as iterator:
        for result in iterator:
            with lock:
                consumed += 1
            results.append(result)
            time.sleep(0.002)  # Completed, unconsumed tasks must still occupy slots.
    assert results == list(range(24))
    assert peak == 4
    assert outstanding <= 8


def test_each_submission_has_its_own_context_and_shared_budget():
    marker = ContextVar('fixture-marker', default='missing')
    token = marker.set('parent')
    barrier = threading.Barrier(4)
    try:
        with execution.session(60, max_input_bytes=100, stream=io.StringIO()) as budget:
            with execution.phase('snapshot-copy'), source.selected_paths(['archives']):
                def work(item):
                    observed = marker.get()
                    marker.set(str(item))
                    if item < 4:
                        barrier.wait(timeout=3)
                    execution.admit_input(1)
                    execution.checkpoint(bytes_read=2, files=1)
                    return observed, execution.current() is budget, source.exclusion_contract()['selected_directory_paths']

                assert list(parallel_map()(work, range(12))) == [('parent', True, ['archives'])] * 12
                summary = budget.summary()
                assert summary['input_bytes'] == summary['files'] == 12
                assert summary['phases']['snapshot-copy']['bytes_read'] == 24
            assert marker.get() == 'parent'
    finally:
        marker.reset(token)


def test_first_failure_stops_submission_and_drains_running_workers():
    running = threading.Event()
    failed = threading.Event()
    finished = threading.Event()
    problem = execution.BudgetExceeded('duration', 'snapshot-copy')
    pulled = []

    def items():
        for item in range(50):
            pulled.append(item)
            yield item

    def work(item):
        if item == 0:
            running.set()
            assert failed.wait(3)
            time.sleep(0.04)
            finished.set()
        elif item == 1:
            assert running.wait(3)
            failed.set()
            raise problem
        return item

    with pytest.raises(execution.BudgetExceeded) as error:
        list(parallel_map()(work, items(), workers=2))
    assert error.value is problem
    assert finished.is_set()
    assert len(pulled) <= 8


def test_input_generator_error_also_drains_started_work():
    started, finished = threading.Event(), threading.Event()
    problem = ValueError('fixed input failure')

    def work(item):
        started.set()
        time.sleep(0.04)
        finished.set()
        return item

    def items():
        yield 1
        assert started.wait(3)
        raise problem

    with pytest.raises(ValueError) as error:
        list(parallel_map()(work, items()))
    assert error.value is problem and finished.is_set()


def test_consumer_break_drains_workers_when_closed():
    finished = threading.Event()
    started = threading.Event()

    def work(item):
        if item == 0:
            assert started.wait(3)
        if item == 1:
            started.set()
            time.sleep(0.04)
            finished.set()
        return item

    with closing(parallel_map()(work, range(20), workers=2)) as iterator:
        assert next(iterator) == 0
    assert finished.is_set()


@pytest.mark.parametrize('kwargs', [{'workers': 0}, {'workers': 5}, {'workers': True},
                                   {'max_pending': 0}, {'max_pending': 9}, {'max_pending': True}])
def test_invalid_parallel_bounds_are_rejected(kwargs):
    with pytest.raises(ValueError):
        list(parallel_map()(lambda item: item, [], **kwargs))


def test_snapshot_parallel_and_single_worker_have_equal_provenance(tmp_path, monkeypatch):
    inventory = fixture_inventory(tmp_path / 'source')
    root = tmp_path / 'source'
    with snapshot.verified_snapshot(root, inventory, include_history=False) as private:
        parallel_hashes = dict(private._hashes)
        parallel_provenance = dict(private.provenance)
    bounded = parallel_map()
    monkeypatch.setattr(snapshot, 'ordered_bounded_map', lambda fn, items: bounded(fn, items, workers=1))
    with snapshot.verified_snapshot(root, inventory, include_history=False) as private:
        assert private._hashes == parallel_hashes
        assert private.provenance == parallel_provenance


def test_snapshot_failure_drains_before_cleanup_and_never_reaches_engine(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    inventory = fixture_inventory(root)
    running, failed, finished = threading.Event(), threading.Event(), threading.Event()
    problem = execution.BudgetExceeded('duration', 'snapshot-copy')
    real_cleanup = snapshot._remove_private_tree
    cleanups = []

    def copy(root, relative, expected, destination):
        if relative.endswith('0.txt'):
            running.set()
            assert failed.wait(3)
            time.sleep(0.04)
            assert destination.parent.parent.exists()
            finished.set()
        elif relative.endswith('1.txt'):
            assert running.wait(3)
            failed.set()
            raise problem

    def cleanup(path):
        assert finished.is_set(), 'Cleanup ran while a copy worker was using its directory'
        cleanups.append(path)
        real_cleanup(path)

    monkeypatch.setattr(snapshot, '_copy_file', copy)
    monkeypatch.setattr(snapshot, '_remove_private_tree', cleanup)
    with pytest.raises(execution.BudgetExceeded) as error:
        with snapshot.verified_snapshot(root, inventory, include_history=False):
            pytest.fail('Engine may not see a partially copied snapshot')
    assert error.value is problem
    assert len(cleanups) == 1 and not cleanups[0].exists()


@pytest.mark.parametrize('alias', ['nested//file-0.txt', 'nested/./file-0.txt', 'nested/file-0.txt',
                                 '../outside', '/absolute', 'nested\\file-0.txt', 'C:outside',
                                 'nested/null\x00.txt', '.'])
def test_snapshot_validates_all_paths_before_any_copy(tmp_path, monkeypatch, alias):
    root = tmp_path / 'source'
    inventory = fixture_inventory(root, 1)
    row = dict(inventory['inventory'][0], path=alias)
    inventory['inventory'].append(row)
    inventory['files'].append(alias)
    copies = []
    monkeypatch.setattr(snapshot, '_copy_file', lambda *args: copies.append(args))
    with pytest.raises(ValueError):
        with snapshot.verified_snapshot(root, inventory, include_history=False):
            pytest.fail('Invalid inventory was accepted')
    assert not copies


@pytest.mark.parametrize('operation', ['summary', 'check', 'admit'])
def test_shared_budget_operations_use_execution_lock(operation):
    with execution.session(60, max_input_bytes=100, stream=io.StringIO()) as budget:
        completed = threading.Event()
        with budget.lock:
            action = {'summary': budget.summary, 'check': budget.check,
                      'admit': lambda: execution.admit_input(1)}[operation]
            context = copy_context()
            worker = threading.Thread(target=lambda: context.run(lambda: (action(), completed.set())))
            worker.start()
            assert not completed.wait(0.02), 'Shared budget operation ignored the counter lock'
        worker.join(3)
        assert completed.is_set()


def test_actual_shared_deadline_preserves_phase_until_drain():
    now = [0.0]
    started, timed_out = threading.Event(), threading.Event()
    observed = []
    with execution.session(10, max_input_bytes=100, stream=io.StringIO(), clock=lambda: now[0]) as budget:
        with pytest.raises(execution.BudgetExceeded) as error:
            with execution.phase('snapshot-copy'):
                def work(item):
                    if item == 0:
                        started.set()
                        assert timed_out.wait(3)
                        time.sleep(0.02)
                        observed.append(execution.current().stage)
                    else:
                        assert started.wait(3)
                        now[0] = 11.0
                        timed_out.set()
                        execution.checkpoint()

                list(parallel_map()(work, [0, 1], workers=2))
        assert observed == ['snapshot-copy']
        assert error.value.diagnostic == budget.summary()['budget_exceeded']
        assert error.value.diagnostic['reason'] == 'duration'
        assert error.value.diagnostic['stage'] == 'snapshot-copy'


def test_snapshot_prevalidation_checks_deadline_before_next_row(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    inventory = fixture_inventory(root)
    now = [0.0]
    validations = []
    real_fullmatch = snapshot.re.fullmatch

    def expire(pattern, value):
        validations.append(value)
        assert len(validations) == 1, 'Validation continued after the parent budget expired'
        now[0] = 11.0
        return real_fullmatch(pattern, value)

    monkeypatch.setattr(snapshot.re, 'fullmatch', expire)
    monkeypatch.setattr(snapshot, '_copy_file', lambda *args: pytest.fail('Copy preceded complete validation'))
    with execution.session(10, max_input_bytes=100, stream=io.StringIO(), clock=lambda: now[0]):
        with pytest.raises(execution.BudgetExceeded) as error:
            with snapshot.verified_snapshot(root, inventory, include_history=False):
                pytest.fail('Expired snapshot was accepted')
    assert error.value.diagnostic['stage'] == 'snapshot-copy'
