"""Parallel collection preserves scope, ordering, failure and lifetime boundaries."""
import hashlib
import io
from pathlib import Path
import threading
import time

import pytest

from gxsec import execution, source


@pytest.fixture(autouse=True)
def no_git(monkeypatch):
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)


def write_inputs(root, count=16):
    for number in range(count):
        (root / f'{number:02}.java').write_text(f'class C{number} {{}}', encoding='utf-8')


def test_collection_uses_at_most_four_simultaneous_file_readers(tmp_path, monkeypatch):
    write_inputs(tmp_path)
    original = source._read_inventory_file
    lock = threading.Lock()
    first_group = threading.Event()
    active = peak = 0
    threads = set()

    def observed(*args, **kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            threads.add(threading.get_ident())
            if active == 4:
                first_group.set()
        try:
            assert first_group.wait(3), 'File collection remained serial'
            time.sleep(0.01)
            return original(*args, **kwargs)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(source, '_read_inventory_file', observed)
    result = source.collect_source(tmp_path)
    assert result['inventory_complete']
    assert len(result['files']) == 16
    assert peak == 4 and len(threads) <= 4 and active == 0
    assert threading.get_ident() not in threads


def test_completion_order_does_not_change_source_hash_or_inventory_order(tmp_path, monkeypatch):
    expected = ['A.java', 'B.java', 'Z.java', 'app/Z.java', 'app/pom.xml', 'other/package.json']
    for relative in reversed(expected):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative, encoding='utf-8')
    original = source._read_inventory_file
    completed = []

    def delayed(path, *args, **kwargs):
        if path == tmp_path / 'A.java':
            time.sleep(0.08)
        result = original(path, *args, **kwargs)
        completed.append(path.relative_to(tmp_path).as_posix())
        return result

    monkeypatch.setattr(source, '_read_inventory_file', delayed)
    result = source.collect_source(tmp_path)
    digest = hashlib.sha256()
    for relative in expected:
        digest.update(relative.encode() + b'\x00' + hashlib.sha256(relative.encode()).hexdigest().encode() + b'\x00')
    assert completed[0] != expected[0]
    assert result['files'] == expected
    assert [item['path'] for item in result['inventory']] == expected
    assert result['hash'] == digest.hexdigest()
    assert result['modules'] == [{'path': 'app', 'manifests': ['pom.xml']},
                                 {'path': 'other', 'manifests': ['package.json']}]


def test_workers_inherit_budget_and_operator_selected_scope(tmp_path, monkeypatch):
    write_inputs(tmp_path, 12)
    (tmp_path / 'archive').mkdir()
    (tmp_path / 'archive' / 'backup.dump').write_bytes(b'not an application input')
    original = source._read_inventory_file
    observed = []

    def inspect_context(path, *args, **kwargs):
        observed.append((execution.current(), source._selected_paths.get(), threading.get_ident()))
        assert path.parent == tmp_path
        return original(path, *args, **kwargs)

    monkeypatch.setattr(source, '_read_inventory_file', inspect_context)
    with source.selected_paths(['archive']):
        with execution.session(60, max_input_bytes=10000, stream=io.StringIO()) as budget:
            with execution.phase('source-inventory'):
                result = source.collect_source(tmp_path)
    assert result['inventory_complete'] and result['scope'] == 'selected'
    assert len(observed) == 12
    assert all(item[0] is budget and item[1] == ('archive',) for item in observed)
    assert all(item[2] != threading.get_ident() for item in observed)
    assert budget.summary()['input_bytes'] == sum(item['size'] for item in result['inventory'])
    assert budget.summary()['files'] == 12
    assert source._selected_paths.get() == () and execution.current() is None


def test_sequential_and_parallel_collection_have_identical_source_and_scope(tmp_path, monkeypatch):
    write_inputs(tmp_path, 12)
    for relative in ('app/pom.xml', 'web/package.json', 'archive/backup.dump', 'node_modules/vendor.js'):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative, encoding='utf-8')
    with source.selected_paths(['archive']):
        parallel = source.collect_source(tmp_path)
        monkeypatch.setattr(source, 'ordered_bounded_map',
                            lambda fn, items, **kwargs: (fn(item) for item in items))
        sequential = source.collect_source(tmp_path)
    assert parallel == sequential


@pytest.mark.parametrize('failure', [OSError('unreadable'), ValueError('source_changed_while_reading')])
def test_one_input_failure_keeps_other_completed_inputs(tmp_path, monkeypatch, failure):
    for name in ('A.java', 'B.java', 'C.java'):
        (tmp_path / name).write_text(name)
    original = source._read_inventory_file

    def fail_one(path, *args, **kwargs):
        if path.name == 'B.java':
            raise failure
        return original(path, *args, **kwargs)

    monkeypatch.setattr(source, '_read_inventory_file', fail_one)
    result = source.collect_source(tmp_path)
    assert result['files'] == ['A.java', 'C.java']
    assert result['inventory_complete'] is False
    assert result['errors'][0]['path'] == 'B.java'


def test_budget_failure_drains_workers_and_never_reads_git(tmp_path, monkeypatch):
    write_inputs(tmp_path)
    original = source._read_inventory_file
    active = set()
    lock = threading.Lock()

    def bounded(path, *args, **kwargs):
        with lock:
            active.add(path)
        try:
            if path.name == '00.java':
                raise execution.BudgetExceeded('duration', 'source-inventory')
            time.sleep(0.02)
            return original(path, *args, **kwargs)
        finally:
            with lock:
                active.remove(path)

    monkeypatch.setattr(source, '_read_inventory_file', bounded)
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: pytest.fail('Git read after exhausted input'))
    result = source.collect_source(tmp_path)
    assert result['inventory_complete'] is False
    assert any(error.get('type') == 'execution_budget_exceeded' for error in result['errors'])
    assert not active


def test_parent_assembly_failure_closes_and_drains_parallel_readers(tmp_path, monkeypatch):
    write_inputs(tmp_path, 8)
    original = source._read_inventory_file
    real_digest = hashlib.sha256
    parent_thread = threading.get_ident()
    first_group = threading.Event()
    lock = threading.Lock()
    active = 0

    class FailedAssembly:
        def update(self, value):
            raise RuntimeError('parent assembly failed')

    def digest(*args, **kwargs):
        return FailedAssembly() if threading.get_ident() == parent_thread else real_digest(*args, **kwargs)

    def delayed(path, *args, **kwargs):
        nonlocal active
        with lock:
            active += 1
            if active == 4:
                first_group.set()
        try:
            assert first_group.wait(3)
            if path.name != '00.java':
                time.sleep(0.06)
            return original(path, *args, **kwargs)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(source, '_read_inventory_file', delayed)
    monkeypatch.setattr(source.hashlib, 'sha256', digest)
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: pytest.fail('Git read after assembly failure'))
    with pytest.raises(RuntimeError, match='parent assembly failed'):
        source.collect_source(tmp_path)
    assert active == 0
