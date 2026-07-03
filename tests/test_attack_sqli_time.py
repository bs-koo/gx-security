import importlib.util
import os
import unittest
from unittest.mock import patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-sql-injection",
                    "scripts", "attack_sqli.py")
_spec = importlib.util.spec_from_file_location("attack_sqli", _MOD)
attack_sqli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attack_sqli)


class _Resp:
    """status_code 속성만 갖는 간단 응답 스텁."""

    def __init__(self, status_code=200):
        self.status_code = status_code


def _seq_send(elapsed_seq, status=200):
    """호출 시퀀스별 (resp, elapsed)를 반환하는 _send 대체.

    목록 소진 후에는 마지막 값을 반복 반환(베이스라인 이후 잔여 페이로드 발사 대응).
    베이스라인은 3샘플(_baseline samples=3)이므로 시퀀스는 [b1, b2, b3, payload, confirm] 순.
    """
    resp = _Resp(status)
    state = {"i": 0}

    def _fake(*args, **kwargs):
        i = state["i"]
        state["i"] += 1
        elapsed = elapsed_seq[i] if i < len(elapsed_seq) else elapsed_seq[-1]
        return resp, elapsed

    return _fake


class TestTimeBasedBaseline(unittest.TestCase):
    """time-based 베이스라인(3샘플 median) 대조 + 재확인(Task 2.2 / U2-Q1)."""

    def test_sleep_over_baseline_with_confirm_is_vulnerable(self):
        # 베이스라인 0.2s(×3) → median 0.2 → threshold 2.2s. sleep 3.2s + confirm 3.2s → 취약 확정.
        with patch.object(attack_sqli, "_send",
                          side_effect=_seq_send([0.2, 0.2, 0.2, 3.2, 3.2])):
            ev, err = attack_sqli._try_time_based(
                "http://app.local", "id", "get", {}, False)
        self.assertIsNone(err)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["technique"], "time-based-blind")
        self.assertIn("baseline_sec", ev)
        self.assertIn("threshold_sec", ev)
        self.assertIn("confirm_sec", ev)

    def test_slow_server_baseline_not_vulnerable(self):
        # 베이스라인 3.0s(×3) → median 3.0 → threshold 5.0s. sleep 3.2s는 delta<2.0 → 미달 → 미확정.
        with patch.object(attack_sqli, "_send",
                          side_effect=_seq_send([3.0, 3.0, 3.0, 3.2])):
            ev, err = attack_sqli._try_time_based(
                "http://app.local", "id", "get", {}, False)
        self.assertIsNone(err)
        self.assertIsNone(ev)

    def test_one_off_jitter_confirm_fails_not_vulnerable(self):
        # 베이스라인 0.2s(×3) → threshold 2.2s. 첫 발사 3.2s이나 confirm 0.3s → 재확인 실패 → 미확정(지터 배제).
        with patch.object(attack_sqli, "_send",
                          side_effect=_seq_send([0.2, 0.2, 0.2, 3.2, 0.3])):
            ev, err = attack_sqli._try_time_based(
                "http://app.local", "id", "get", {}, False)
        self.assertIsNone(err)
        self.assertIsNone(ev)

    def test_median_ignores_single_baseline_spike(self):
        # [U2-Q1] 베이스라인 3샘플 [0.2, 0.2, 2.5] → median 0.2 (스파이크 1회 무시) → threshold 2.2.
        # sleep 3.2s + confirm 3.2s → 취약. (max()였다면 2.5 → threshold 4.5로 3.2를 놓쳐 미탐)
        with patch.object(attack_sqli, "_send",
                          side_effect=_seq_send([0.2, 0.2, 2.5, 3.2, 3.2])):
            ev, err = attack_sqli._try_time_based(
                "http://app.local", "id", "get", {}, False)
        self.assertIsNone(err)
        self.assertIsNotNone(ev)

    def test_connection_failed_during_baseline(self):
        # _send가 None(연결 실패)이면 (None, "CONNECTION_FAILED") 반환.
        with patch.object(attack_sqli, "_send", side_effect=lambda *a, **k: None):
            ev, err = attack_sqli._try_time_based(
                "http://app.local", "id", "get", {}, False)
        self.assertIsNone(ev)
        self.assertEqual(err, "CONNECTION_FAILED")

    def test_oracle_payloads_present(self):
        # Oracle DBMS_PIPE.RECEIVE_MESSAGE 페이로드가 추가되었는가.
        dbmses = [d for d, _ in attack_sqli._TIME_PAYLOADS]
        self.assertIn("oracle", dbmses)
        joined = " ".join(p for _, p in attack_sqli._TIME_PAYLOADS)
        self.assertIn("DBMS_PIPE.RECEIVE_MESSAGE", joined)


if __name__ == "__main__":
    unittest.main()
