import json
from pathlib import Path

import pytest

from gxsec.reporting import write_reports


def sample_run():
    return {
        "schema_version": 1,
        "run_id": "run-example",
        "project_id": "example-service",
        "profile": "static-release",
        "source": {"commit": "abc123", "hash": "sourcehash", "dirty": False},
        "checks": [{"id": "sast", "status": "incomplete", "required": True,
                    "errors": ["parser failed"], "coverage": {"eligible": 2, "scanned": 1}}],
        "findings": [{"finding_id": "GXSEC-123", "fingerprint": "abc", "title": "<img src=x onerror=alert(1)>",
                      "description": "<script>alert('unsafe')</script>", "category": "xss", "severity": "High",
                      "validation": "candidate", "lifecycle": "open", "token": "test-secret-that-must-disappear",
                      "locations": [{"path": "backend/Board.java", "line": 12}],
                      "remediation": {"owner": "backend", "description": "Escape output"}}],
        "gate": {"status": "INCOMPLETE", "exit_code": 2, "incomplete": ["sast"]},
        "reviews": [], "exceptions": [],
    }


def test_shared_exports_are_redacted_and_payload_html_is_inert(tmp_path):
    files = write_reports(sample_run(), tmp_path)
    names = {Path(p).name for p in files}
    assert {"result.json", "report.html", "developer.md", "qa-checklist.md", "results.sarif", "manifest.json"} <= names
    combined = "\n".join(p.read_text(encoding="utf-8") for p in tmp_path.iterdir() if p.is_file())
    assert "test-secret-that-must-disappear" not in combined
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<img src=x" not in html
    assert "<script>alert('unsafe')</script>" not in html
    assert "&lt;img" in html
    assert "INCOMPLETE" in html
    assert "static-release" in html
    assert "cdn." not in html
    assert "Content-Security-Policy" in html


def test_reports_share_gate_and_stable_sarif_fingerprint(tmp_path):
    write_reports(sample_run(), tmp_path)
    result = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    sarif = json.loads((tmp_path / "results.sarif").read_text(encoding="utf-8"))
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert result["gate"]["status"] == "INCOMPLETE"
    assert sarif["version"] == "2.1.0"
    finding = sarif["runs"][0]["results"][0]
    assert finding["partialFingerprints"]["gxsec/v1"] == "abc"
    assert finding["properties"]["validation"] == "candidate"
    assert finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "backend/Board.java"
    assert manifest["run_id"] == "run-example"
    assert "report.html" in manifest["files"]
    assert all(len(digest) == 64 for digest in manifest["files"].values())


def test_unsafe_source_path_is_not_a_clickable_sarif_uri(tmp_path):
    run = sample_run()
    run["findings"][0]["locations"] = [{"path": "javascript:alert(1)", "line": 1}]
    write_reports(run, tmp_path)
    sarif = json.loads((tmp_path / "results.sarif").read_text(encoding="utf-8"))
    locations = sarif["runs"][0]["results"][0].get("locations", [])
    assert not locations


def test_qa_lists_unconfirmed_findings_and_check_failures(tmp_path):
    write_reports(sample_run(), tmp_path)
    qa = (tmp_path / "qa-checklist.md").read_text(encoding="utf-8")
    assert "GXSEC-123" in qa
    assert "parser failed" in qa
    assert "- [ ]" in qa


def test_retest_handoff_keeps_docker_host_paths_and_previous_run(tmp_path):
    run = sample_run()
    run['execution_context'] = {'authority': 'report-hint-only', 'runner': 'powershell-docker', 'source': 'D:/project',
        'output': 'D:/shared-results', 'state_dir': 'D:/shared-results/state',
        'policy': 'D:/approved/policy.json', 'database': 'D:/approved/db'}
    write_reports(run, tmp_path)
    text = (tmp_path / 'developer.md').read_text(encoding='utf-8')
    for required in ('run-example', 'GXSEC-123', 'D:/project', 'D:/shared-results/state', 'D:/approved/policy.json'):
        assert required in text
    assert '--config &lt;' not in text
    assert '$gx-security' in text


def test_legacy_run_handoff_does_not_invent_default_state(tmp_path):
    write_reports(sample_run(), tmp_path)
    text = (tmp_path / 'developer.md').read_text(encoding='utf-8')
    assert '--config &lt;' not in text
    assert '.gxsec/state.sqlite3' not in text
    assert '기존 상태 저장소' in text


def test_report_does_not_recommend_untrusted_tmpfs_options(tmp_path):
    run = sample_run()
    run['execution_context'] = {'authority': 'report-hint-only', 'runner': 'powershell-docker',
                               'temporary_size': '4g,exec'}
    write_reports(run, tmp_path)
    text = (tmp_path / 'developer.md').read_text(encoding='utf-8')
    assert '-TemporarySize' not in text
    assert '4g,exec' not in text


def test_export_replaces_file_symlink_without_overwriting_its_target(tmp_path):
    import pytest
    victim = tmp_path / "outside.txt"
    victim.write_text("keep this content", encoding="utf-8")
    output = tmp_path / "reports"
    output.mkdir()
    try:
        (output / "result.json").symlink_to(victim)
    except OSError:
        pytest.skip("symlink creation unavailable on this host")
    write_reports(sample_run(), output)
    assert victim.read_text(encoding="utf-8") == "keep this content"
    assert not (output / "result.json").is_symlink()


def test_markdown_evidence_cannot_create_active_links_or_images(tmp_path):
    run = sample_run()
    run["findings"][0]["description"] = "[open](javascript:alert(1)) ![external](https://attacker.example/tracking.png)"
    write_reports(run, tmp_path)
    for filename in ("developer.md", "qa-checklist.md"):
        content = (tmp_path / filename).read_text(encoding="utf-8")
        assert "[open](javascript:" not in content
        assert "![external](https://" not in content


@pytest.mark.parametrize('reason', ['operator-selected-separate-review', 'operator-selected-exclusion'])
def test_selected_exclusion_report_does_not_impose_a_separate_review(tmp_path, reason):
    run = sample_run()
    run['source'].update(exclusion_contract={'selected_directory_paths': ['docs/design']},
                         exclusions=[{'path': 'docs/design', 'reason': reason}], scope='selected')
    write_reports(run, tmp_path)
    for filename in ('developer.md', 'qa-checklist.md', 'report.html'):
        content = (tmp_path / filename).read_text(encoding='utf-8')
        assert '사용자 지정 검사 제외 경로' in content
        assert 'docs/design' in content and 'INCOMPLETE' in content
        assert '별도 점검' not in content
    saved = json.loads((tmp_path / 'result.json').read_text(encoding='utf-8'))
    assert saved['source']['exclusions'][0]['reason'] == reason
    assert saved['gate']['status'] == 'INCOMPLETE'


@pytest.mark.parametrize('stage,category,expected', [
    ('inventory', 'invalid_engine_output', ('초기 이력 정보', '검증되지 않았습니다')),
    ('clone', 'timeout', ('이력 복사', '시간 제한')),
    ('independent-objects', 'local_clone_rejected_reported', ('독립 객체', '로컬 복사 거부')),
    ('object-format', 'ownership_rejected_reported', ('객체 형식', '소유권 거부')),
    ('commit-and-refs', 'nonzero_exit', ('커밋·참조', '실행 실패')),
])
def test_git_history_diagnostic_uses_fixed_stage_and_cause_text(stage, category, expected):
    from gxsec.reporting import _error_text
    text = _error_text({'type': 'git_history_failed', 'stage': stage, 'category': category,
                        'returncode': 128, 'message': 'private-raw-evidence-marker'})
    assert 'Git 이력' in text and all(part in text for part in expected)
    assert '종료 코드 128' in text
    assert 'private-raw-evidence-marker' not in text


@pytest.mark.parametrize('code', ['128', True, 2**31, -256])
def test_unknown_git_diagnostic_values_do_not_become_report_text(code):
    from gxsec.reporting import _error_text
    text = _error_text({'type': 'git_history_failed', 'stage': {'private-stage-marker': 'x'},
                        'category': ['private-category-marker'], 'returncode': code,
                        'message': 'private-message-marker'})
    assert 'Git 이력' in text
    assert 'private-' not in text and '종료 코드' not in text
