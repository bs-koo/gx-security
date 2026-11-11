"""The preflight CLI must never approve a command it did not understand."""
from pathlib import Path
import os
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'scope_guard.py'


def run_guard(tmp_path, *arguments):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('SECURITY_PLUGIN_')}
    return subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), *arguments],
                          cwd=tmp_path, env=environment, capture_output=True,
                          text=True, encoding='utf-8', timeout=10)


@pytest.mark.parametrize('unexpected', [
    ['--param', 'q'], ['--unknown'], ['another-target'], ['--author'], ['--authorized=false'],
])
def test_unknown_scope_arguments_fail_before_approval(tmp_path, unexpected):
    result = run_guard(tmp_path, 'http://127.0.0.1', *unexpected)
    assert result.returncode == 2
    assert 'ALLOW:' not in result.stdout


def test_scope_help_is_available_without_a_target(tmp_path):
    result = run_guard(tmp_path, '--help')
    assert result.returncode == 0
    assert '--authorized' in result.stdout and 'ALLOW:' not in result.stdout


def test_scope_local_target_remains_allowed(tmp_path):
    result = run_guard(tmp_path, 'http://127.0.0.1:7171')
    assert result.returncode == 0 and 'ALLOW:' in result.stdout


def test_scope_production_target_remains_denied(tmp_path):
    result = run_guard(tmp_path, 'https://www.example.com')
    assert result.returncode == 1 and 'ALLOW:' not in result.stdout


def test_scope_public_target_still_needs_both_authorization_signals(tmp_path):
    result = run_guard(tmp_path, 'https://api.company.example.org', '--authorized')
    assert result.returncode == 1 and 'ALLOW:' not in result.stdout
