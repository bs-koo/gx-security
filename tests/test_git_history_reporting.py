"""Safe preparation failures reach the user even when the scanner is unavailable."""
import json

from gxsec import adapters


def test_secrets_preserves_safe_history_cause_without_native_text(tmp_path, monkeypatch):
    monkeypatch.setattr(adapters, '_probe', lambda *args, **kwargs: None)
    history = {'required': True, 'status': 'incomplete', 'errors': [
        {'type': 'git_history_failed', 'category': 'timeout', 'stage': 'clone',
         'message': 'PRIVATE_NATIVE_TEXT', 'stderr': 'PRIVATE_STDERR'},
        {'type': 'git_history_failed', 'category': 'ownership_rejected_reported',
         'stage': 'clone', 'returncode': 128, 'evidence': 'stderr-marker'},
        {'type': 'git_history_failed', 'category': 'PRIVATE_CATEGORY',
         'stage': 'PRIVATE_STAGE', 'signal': True, 'returncode': 'PRIVATE_CODE',
         'evidence': 'PRIVATE_EVIDENCE'},
        {'type': 'PRIVATE_TYPE', 'message': 'PRIVATE_MESSAGE'},
    ]}
    check, findings = adapters._secrets(tmp_path, {'_snapshot_provenance': {'history': history}},
                                       {'files': ['app.py'], 'scope_hash': 'scope'}, 'static-release')
    assert findings == []
    assert check['status'] == 'incomplete'
    assert check['errors'] == [
        {'type': 'git_history_failed', 'category': 'timeout', 'stage': 'clone'},
        {'type': 'git_history_failed', 'category': 'ownership_rejected_reported',
         'stage': 'clone', 'returncode': 128, 'evidence': 'stderr-marker'},
        {'type': 'git_history_failed'},
    ]
    assert 'PRIVATE_' not in json.dumps(check)


def test_complete_history_does_not_propagate_stale_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(adapters, '_probe', lambda *args, **kwargs: None)
    history = {'required': True, 'status': 'complete',
               'errors': [{'type': 'git_history_failed', 'category': 'timeout'}]}
    check, _ = adapters._secrets(tmp_path, {'_snapshot_provenance': {'history': history}},
                                {'files': ['app.py'], 'scope_hash': 'scope'}, 'static-release')
    assert not check['errors']
