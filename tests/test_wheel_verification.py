"""A built artifact must contain exactly the source runtime and its resources."""
import importlib.util
from pathlib import Path
import zipfile

import pytest
import yaml


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'verify-wheel.py'


def verifier():
    spec = importlib.util.spec_from_file_location('wheel_verifier', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def package(tmp_path):
    source = tmp_path / 'source'
    files = {
        'src/gxsec/__init__.py': b'__version__ = "0.10.3"\n',
        'src/gxsec/adapters.py': b'ROOT = "bundled-assets"\n',
        'scan_all.py': b'# scanner entrypoint\n',
        'tools/contract.py': b'# shared scanner contract\n',
        'tools/resources.json': b'{"required": true}\n',
        'skills/detecting-example/SKILL.md': b'# required scanner instructions\n',
    }
    members = {}
    for name, data in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        member = name.removeprefix('src/') if name.startswith('src/') else 'gxsec/_assets/' + name
        members[member] = data
    return source, tmp_path / 'gx_security-0.10.3-py3-none-any.whl', members


def write_wheel(wheel, members):
    with zipfile.ZipFile(wheel, 'w') as archive:
        for name, data in members.items():
            archive.writestr(name, data)
        archive.writestr('gx_security-0.10.3.dist-info/METADATA', 'Name: gx-security\nVersion: 0.10.3\n')


def test_wheel_matches_python_and_non_python_resources(package):
    source, wheel, members = package
    write_wheel(wheel, members)
    report = verifier().verify_wheel(source, wheel)
    assert report['matched_files'] == 6
    assert len(report['sha256']) == 64


@pytest.mark.parametrize('corruption', ['missing-resource', 'stale-module', 'unexpected-runtime',
                                      'unexpected-package', 'unrelated-distribution', 'bytecode'])
def test_broken_or_stale_wheel_is_rejected(package, corruption):
    source, wheel, members = package
    if corruption == 'missing-resource':
        del members['gxsec/_assets/tools/resources.json']
    elif corruption == 'stale-module':
        members['gxsec/adapters.py'] = b'ROOT = "stale-source-checkout"\n'
    elif corruption == 'unexpected-runtime':
        members['gxsec/_assets/tools/old.py'] = b'# stale artifact\n'
    elif corruption == 'unexpected-package':
        members['unexpected_package/__init__.py'] = b'# unrelated executable package\n'
    elif corruption == 'unrelated-distribution':
        members['unrelated-1.0.dist-info/METADATA'] = b'Name: unrelated\n'
    else:
        members['gxsec/__pycache__/adapters.cpython-312.pyc'] = b'compiled-stale-code'
    write_wheel(wheel, members)
    module = verifier()
    with pytest.raises(module.VerificationError):
        module.verify_wheel(source, wheel)


def test_duplicate_archive_entries_are_rejected(package):
    source, wheel, members = package
    write_wheel(wheel, members)
    with zipfile.ZipFile(wheel, 'a') as archive, pytest.warns(UserWarning):
        archive.writestr('gxsec/adapters.py', members['gxsec/adapters.py'])
    module = verifier()
    with pytest.raises(module.VerificationError):
        module.verify_wheel(source, wheel)


def test_ci_gates_wheel_installation_and_keeps_verification_proof():
    workflow = yaml.safe_load((SCRIPT.parents[1] / '.github/workflows/ci.yml').read_text(encoding='utf-8'))
    steps = workflow['jobs']['bundle']['steps']
    gates = [step for step in steps if '/scripts/verify-wheel.py' in step.get('run', '')]
    assert len(gates) == 1
    command = gates[0]['run']
    for flag in ('--network none', '--read-only', '--cap-drop ALL', '--security-opt no-new-privileges'):
        assert flag in command
    artifacts = [step for step in steps if step.get('with', {}).get('name') == 'wheel-verification']
    assert len(artifacts) == 1 and artifacts[0].get('if') == '${{ always() }}'
    proof = artifacts[0]['with']['path']
    assert proof.endswith('/wheel-verification.json') and proof in command
