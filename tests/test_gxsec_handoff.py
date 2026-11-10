"""Host path hints support reports and never change the security execution inputs."""
import json
import base64
from types import SimpleNamespace


def test_native_handoff_preserves_custom_state_and_config(tmp_path):
    from gxsec.handoff import execution_context
    source, state = tmp_path / 'source', tmp_path / 'original-state'
    args = SimpleNamespace(config=str(tmp_path / 'profile.yml'), policy=None)
    result = execution_context(args, source, state, environment={})
    assert result['runner'] == 'native'
    assert result['source'] == str(source)
    assert result['state_dir'] == str(state)
    assert result['config'] == str(tmp_path / 'profile.yml')


def test_docker_handoff_uses_host_paths_only_as_report_hints(tmp_path):
    from gxsec.handoff import execution_context
    context = {'runner': 'powershell-docker', 'source': 'D:/project', 'output': 'D:/results',
               'state_dir': 'D:/results/state', 'policy': 'D:/trusted.json'}
    result = execution_context(SimpleNamespace(), tmp_path / 'workspace', tmp_path / 'state',
        environment={'GXSEC_REPORT_CONTEXT_B64': base64.b64encode(json.dumps(context).encode()).decode()})
    assert result == {**context, 'authority': 'report-hint-only'}


def test_arbitrary_commands_and_control_characters_are_not_report_context(tmp_path):
    from gxsec.handoff import execution_context
    for hint in ({'runner': 'powershell-docker', 'command': 'do-anything'},
                 {'runner': 'powershell-docker', 'source': 'a\ncommand', 'output': 'x', 'state_dir': 'x/state'}):
        result = execution_context(SimpleNamespace(), tmp_path / 'workspace', tmp_path / 'state',
            environment={'GXSEC_REPORT_CONTEXT_B64': base64.b64encode(json.dumps(hint).encode()).decode()})
        assert result['runner'] == 'native'
        assert 'command' not in result
