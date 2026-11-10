import io
import json
import time
import threading

import pytest

from gxsec import execution


def test_budget_preserves_phase_and_stops_on_deadline():
    ticks = [100.0]
    stream = io.StringIO()
    with execution.session(10, max_input_bytes=1024, stream=stream, clock=lambda: ticks[0]) as budget:
        with execution.phase('source-inventory'):
            execution.checkpoint(bytes_read=512, files=1)
            assert execution.timeout_for(300) == 10
            ticks[0] = 111
            with pytest.raises(execution.BudgetExceeded) as error:
                execution.checkpoint()
            assert error.value.diagnostic['reason'] == 'duration'
            assert error.value.diagnostic['stage'] == 'source-inventory'
    assert budget.summary()['bytes_read'] == 512
    assert 'source-inventory' in stream.getvalue()


def test_input_budget_does_not_count_snapshot_rechecks_as_new_input():
    with execution.session(60, max_input_bytes=4, stream=io.StringIO()) as budget:
        execution.admit_input(4)
        execution.checkpoint(bytes_read=100)
        with pytest.raises(execution.BudgetExceeded, match='input_bytes'):
            execution.admit_input(1)
        assert budget.summary()['input_bytes'] == 5


def test_first_exhausted_phase_survives_followup_recheck():
    ticks = [0.0]
    with execution.session(10, max_input_bytes=1024, stream=io.StringIO(), clock=lambda: ticks[0]) as budget:
        with execution.phase('snapshot-copy'):
            ticks[0] = 11
            with pytest.raises(execution.BudgetExceeded):
                execution.checkpoint()
        with pytest.raises(execution.BudgetExceeded):
            with execution.phase('source-recheck'):
                pytest.fail('an exhausted budget must not resume work')
        assert budget.summary()['budget_exceeded'] == {
            'type': 'execution_budget_exceeded', 'reason': 'duration', 'stage': 'snapshot-copy'}


def test_nested_phases_restore_outer_and_do_not_leak_paths():
    stream = io.StringIO()
    with execution.session(60, max_input_bytes=1024, stream=stream) as budget:
        with execution.phase('snapshot'):
            with execution.phase('snapshot-verify'):
                execution.checkpoint(bytes_read=5, files=1)
            assert budget.stage == 'snapshot'
    events = [json.loads(line.removeprefix('[gxsec] ')) for line in stream.getvalue().splitlines()]
    assert events and all('path' not in item for item in events)
    assert budget.summary()['phases']['snapshot-verify']['bytes_read'] == 5


def test_invalid_budgets_rejected_and_no_active_session_is_noop():
    for duration in (0, -1, float('inf'), float('nan')):
        with pytest.raises(ValueError):
            with execution.session(duration, max_input_bytes=100):
                pass
    execution.checkpoint(bytes_read=1)
    assert execution.timeout_for(15) == 15


def test_heartbeat_visible_during_blocked_engine():
    stream = io.StringIO()
    with execution.session(60, max_input_bytes=1024, stream=stream, heartbeat_seconds=0.01):
        with execution.phase('engine-sast'):
            time.sleep(0.04)
    assert 'heartbeat' in stream.getvalue()


def test_first_input_failure_is_rethrown_after_later_deadline_and_phase():
    ticks = [0.0]
    with execution.session(10, max_input_bytes=1, stream=io.StringIO(), clock=lambda: ticks[0]) as budget:
        with execution.phase('source-inventory'):
            with pytest.raises(execution.BudgetExceeded) as first:
                execution.admit_input(2)
        ticks[0] = 11.0
        with pytest.raises(execution.BudgetExceeded) as later:
            with execution.phase('source-recheck'):
                pytest.fail('An exhausted execution resumed')
        assert later.value.diagnostic == first.value.diagnostic == budget.summary()['budget_exceeded']
        assert later.value.diagnostic['reason'] == 'input_bytes'
        assert later.value.diagnostic['stage'] == 'source-inventory'


def test_parallel_callback_order_cannot_change_the_first_budget_reason():
    from gxsec.parallel import ordered_bounded_map
    ticks = [0.0]
    first_failure, later_failure = threading.Event(), threading.Event()
    with execution.session(10, max_input_bytes=1, stream=io.StringIO(), clock=lambda: ticks[0]) as budget:
        with execution.phase('snapshot-copy'):
            def work(index):
                if index == 0:
                    try:
                        execution.admit_input(2)
                    except execution.BudgetExceeded:
                        first_failure.set()
                        assert later_failure.wait(3)
                        time.sleep(0.03)  # Make the later worker's exception observable first.
                        raise
                assert first_failure.wait(3)
                ticks[0] = 11.0
                try:
                    execution.checkpoint()
                finally:
                    later_failure.set()

            with pytest.raises(execution.BudgetExceeded) as error:
                list(ordered_bounded_map(work, [0, 1], workers=2))
        assert error.value.diagnostic == budget.summary()['budget_exceeded']
        assert error.value.diagnostic['reason'] == 'input_bytes'


def test_expired_budget_cannot_resume_when_clock_recovers():
    ticks = [0.0]
    with execution.session(10, max_input_bytes=1, stream=io.StringIO(), clock=lambda: ticks[0]) as budget:
        ticks[0] = 11.0
        with pytest.raises(execution.BudgetExceeded) as first:
            execution.checkpoint()
        ticks[0] = 0.0
        with pytest.raises(execution.BudgetExceeded) as later:
            execution.checkpoint()
        assert later.value.diagnostic == first.value.diagnostic == budget.summary()['budget_exceeded']
