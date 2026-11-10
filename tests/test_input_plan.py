from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gxsec import preflight, source


def test_input_plan_counts_without_reading_contents(tmp_path, monkeypatch):
    (tmp_path / 'App.java').write_bytes(b'code')
    (tmp_path / 'data').mkdir()
    (tmp_path / 'data' / 'backup.dump').write_bytes(b'private')
    def no_read(*args, **kwargs):
        raise AssertionError('Input plan must use metadata only')
    monkeypatch.setattr(Path, 'open', no_read)
    plan = preflight.inspect_inputs(tmp_path)
    assert plan['files'] == 2 and plan['bytes'] == 11
    assert plan['separate_review_candidates'] == ['data/backup.dump']
    assert plan['content_verified'] is False


def test_input_plan_retains_explicit_exclusions(tmp_path):
    (tmp_path / 'data').mkdir()
    (tmp_path / 'data' / 'backup.dump').write_bytes(b'private')
    with source.selected_paths(['data']):
        plan = preflight.inspect_inputs(tmp_path)
    assert plan['files'] == 0
    assert plan['exclusions'][0]['reason'] == 'operator-selected-separate-review'
