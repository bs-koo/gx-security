"""File accounting and annotation presence cannot substitute for security support."""
import json
import subprocess

import pytest
import yaml

from gxsec import adapters, config, policy, source
from tests.test_gxsec_framework import ADMIN, BUILD, METHOD, WEB, run


def scan_static(tmp_path, monkeypatch, files):
    root = tmp_path / 'input'
    root.mkdir()
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding='utf-8')
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    inventory = source.collect_source(root)
    cfg = config.default_config(root)
    cfg['_state_dir'] = tmp_path / 'state'

    def probe(name, options, path, check, **kwargs):
        check['engine'] = {'name': name, 'version': '1.172.0', 'available': True}
        return 'approved-semgrep'

    monkeypatch.setattr(adapters, '_probe', probe)
    payload = {'results': [], 'errors': [], 'paths': {'scanned': inventory['files']}}
    monkeypatch.setattr(adapters, '_run', lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 0, json.dumps(payload), ''))
    return adapters._sast(root, cfg, inventory, 'static-release')


def test_scanned_kotlin_with_only_generic_rules_remains_unsupported(tmp_path, monkeypatch):
    check, findings = scan_static(tmp_path, monkeypatch, {
        'src/main/kotlin/Weak.kt': 'fun read(request: Request) = Runtime.getRuntime().exec(request.getParameter("cmd"))',
        'src/main/java/Normal.java': 'class Normal {}',
    })
    assert check['coverage']['eligible'] == check['coverage']['scanned'] == 2
    assert check['coverage']['missing'] == []
    assert check['status'] == 'incomplete'
    assert policy.evaluate([check], findings)['status'] == 'INCOMPLETE'
    gap = next(row for row in check['errors'] if row['type'] == 'rule_coverage_unavailable')
    assert gap['language'] == 'kotlin' and gap['files'] == ['src/main/kotlin/Weak.kt']
    required = check['coverage']['required_coverage']
    assert required['complete'] is False
    assert required['unsupported_files'] == ['src/main/kotlin/Weak.kt']
    kotlin = next(row for row in required['languages'] if row['language'] == 'kotlin')
    assert kotlin['ast_rule_ids'] == [] and kotlin['generic_rule_ids']
    assert kotlin['required_mode'] == 'language-specific'


def test_kotlin_build_metadata_does_not_prove_application_language_support(tmp_path, monkeypatch):
    check, _ = scan_static(tmp_path, monkeypatch, {
        'build.gradle.kts': 'plugins { java }',
        'settings.gradle.kts': 'rootProject.name = "test"',
        'src/main/kotlin/task.kts': 'Runtime.getRuntime().exec(input)',
    })
    required = check['coverage']['required_coverage']
    assert required['complete'] is False
    assert set(required['unsupported_files']) == set(check['coverage']['files'])
    assert required['build_metadata_files'] == ['build.gradle.kts', 'settings.gradle.kts']
    kotlin = next(row for row in required['languages'] if row['language'] == 'kotlin')
    assert kotlin['source_files'] == ['src/main/kotlin/task.kts']


def test_language_specific_kotlin_rules_allow_scanned_supported_scope(tmp_path, monkeypatch):
    rule_root = tmp_path / 'ruleset'
    rule_path = rule_root / 'skills/detecting-example/rules/kotlin.yml'
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text(yaml.safe_dump({'rules': [{'id': 'kotlin-example', 'languages': ['kotlin'],
        'message': 'Example', 'severity': 'WARNING', 'pattern': 'danger($X)'}]}), encoding='utf-8')
    monkeypatch.setattr(adapters, 'ROOT', rule_root)
    check, _ = scan_static(tmp_path, monkeypatch, {'Weak.kt': 'fun safe() = 1'})
    assert check['status'] == 'complete'
    required = check['coverage']['required_coverage']
    assert required['complete'] is True and required['unsupported_files'] == []
    assert required['languages'][0]['ast_rule_ids'] == ['kotlin-example']


def test_language_targeted_regex_is_not_reported_as_kotlin_ast_support(tmp_path, monkeypatch):
    rule_root = tmp_path / 'ruleset'
    rule_path = rule_root / 'skills/detecting-example/rules/kotlin.yml'
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text(yaml.safe_dump({'rules': [{'id': 'kotlin-regex', 'languages': ['kotlin'],
        'message': 'Example', 'severity': 'WARNING', 'pattern-regex': 'secret',
        'metadata': {'pattern': 'description-only'}}]}), encoding='utf-8')
    monkeypatch.setattr(adapters, 'ROOT', rule_root)
    check, _ = scan_static(tmp_path, monkeypatch, {'Weak.kt': 'fun bad() = input'})
    assert check['status'] == 'incomplete'
    kotlin = check['coverage']['required_coverage']['languages'][0]
    assert kotlin['ast_rule_ids'] == []
    assert kotlin['language_rule_ids'] == kotlin['regex_rule_ids'] == ['kotlin-regex']


def test_active_language_rule_outside_its_path_scope_cannot_fulfill_support(tmp_path, monkeypatch):
    rule_root = tmp_path / 'ruleset'
    rule_path = rule_root / 'skills/detecting-example/rules/kotlin.yml'
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text(yaml.safe_dump({'rules': [{'id': 'kotlin-example', 'languages': ['kotlin'],
        'paths': {'include': ['Supported.kt']}, 'message': 'Example', 'severity': 'WARNING',
        'pattern': 'danger($X)'}]}), encoding='utf-8')
    monkeypatch.setattr(adapters, 'ROOT', rule_root)
    check, _ = scan_static(tmp_path, monkeypatch, {'Supported.kt': 'fun ok() = 1', 'Unsupported.kt': 'fun bad() = 1'})
    assert check['status'] == 'incomplete'
    required = check['coverage']['required_coverage']
    assert required['supported_files'] == ['Supported.kt']
    assert required['unsupported_files'] == ['Unsupported.kt']


def test_malformed_rule_path_scope_is_reported_as_incomplete(tmp_path, monkeypatch):
    rule_root = tmp_path / 'ruleset'
    rule_path = rule_root / 'skills/detecting-example/rules/kotlin.yml'
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text(yaml.safe_dump({'rules': [{'id': 'kotlin-example', 'languages': ['kotlin'],
        'paths': ['invalid'], 'message': 'Example', 'severity': 'WARNING',
        'pattern': 'danger($X)'}]}), encoding='utf-8')
    monkeypatch.setattr(adapters, 'ROOT', rule_root)
    check, _ = scan_static(tmp_path, monkeypatch, {'Weak.kt': 'fun bad() = 1'})
    assert check['status'] == 'incomplete'
    assert any(row['type'] == 'rule_load_failed' for row in check['errors'])


def test_unmodeled_directory_glob_cannot_claim_language_support(tmp_path, monkeypatch):
    rule_root = tmp_path / 'ruleset'
    rule_path = rule_root / 'skills/detecting-example/rules/kotlin.yml'
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text(yaml.safe_dump({'rules': [{'id': 'kotlin-example', 'languages': ['kotlin'],
        'paths': {'include': ['src/*.kt']}, 'message': 'Example', 'severity': 'WARNING',
        'pattern': 'danger($X)'}]}), encoding='utf-8')
    monkeypatch.setattr(adapters, 'ROOT', rule_root)
    check, _ = scan_static(tmp_path, monkeypatch, {'src/nested/Weak.kt': 'fun bad() = 1'})
    assert check['status'] == 'incomplete'
    assert check['coverage']['required_coverage']['unsupported_files'] == ['src/nested/Weak.kt']


@pytest.mark.parametrize('declaration', ['private void', 'public final void', 'public static void',
                                         'private @Audited void', 'public final @Audited void'])
@pytest.mark.parametrize('guard_level', ['method', 'class'])
def test_non_interceptable_admin_annotations_preserve_review(tmp_path, declaration, guard_level):
    controller = ADMIN.replace('public void', declaration)
    controller = controller.replace('@PutMapping' if guard_level == 'method' else '@RestController',
        '@PreAuthorize("hasRole(\'ADM\')") ' + ('@PutMapping' if guard_level == 'method' else '@RestController'))
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    admin = next(row for row in check['framework']['contracts'] if row['id'] == 'admin-boundary')
    assert admin['state'] == 'unknown'
    assert admin['method_guard_applicability']['state'] == 'unknown'
    assert any(f['rule_id'] == 'SEF-ADM-01' for f in findings)
    assert check['status'] == 'incomplete'


def test_final_controller_annotation_preserves_review(tmp_path):
    controller = ADMIN.replace('class UserAdminController', 'final class UserAdminController')
    controller = controller.replace('@PutMapping', '@PreAuthorize("hasRole(\'ADM\')") @PutMapping')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    admin = next(row for row in check['framework']['contracts'] if row['id'] == 'admin-boundary')
    assert admin['state'] == 'unknown' and check['status'] == 'incomplete'
    assert any(f['rule_id'] == 'SEF-ADM-01' for f in findings)


def test_independent_url_role_guard_is_observed_for_private_annotation(tmp_path):
    controller = ADMIN.replace('public void', 'private void')
    controller = controller.replace('@PutMapping', '@PreAuthorize("hasRole(\'ADM\')") @PutMapping')
    web = WEB.replace('"/adm/**").authenticated()', '"/adm/**").hasRole("ADM")')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': web, 'src/main/java/C.java': controller})
    admin = next(row for row in check['framework']['contracts'] if row['id'] == 'admin-boundary')
    assert admin['state'] == 'guard-observed'
    assert admin['guard_basis'] == ['url-role-guard']
    assert admin['method_guard_applicability']['state'] == 'unknown'
    assert check['status'] == 'complete'
    assert not any(f['rule_id'] == 'SEF-ADM-01' for f in findings)


def test_public_method_annotation_retains_supported_guard_observation(tmp_path):
    controller = ADMIN.replace('@PutMapping', '@PreAuthorize("hasRole(\'ADM\')") @PutMapping')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    admin = next(row for row in check['framework']['contracts'] if row['id'] == 'admin-boundary')
    assert admin['state'] == 'guard-observed' and check['status'] == 'complete'
    assert admin['guard_basis'] == ['method-role-guard']
    assert admin['method_guard_applicability']['state'] == 'source-compatible'
    assert not any(f['rule_id'] == 'SEF-ADM-01' for f in findings)


def test_final_parameter_does_not_make_public_method_non_interceptable(tmp_path):
    controller = ADMIN.replace('changeRole(String id)', 'changeRole(final String id)')
    controller = controller.replace('@PutMapping', '@PreAuthorize("hasRole(\'ADM\')") @PutMapping')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    admin = next(row for row in check['framework']['contracts'] if row['id'] == 'admin-boundary')
    assert admin['state'] == 'guard-observed' and check['status'] == 'complete'
    assert admin['method_guard_applicability']['state'] == 'source-compatible'
    assert not any(f['rule_id'] == 'SEF-ADM-01' for f in findings)


def test_non_interceptable_predicate_does_not_hide_unmatched_route(tmp_path):
    controller = ADMIN.replace('/adm/users', '/business/users').replace('UserAdminController', 'Controller')
    controller = controller.replace('public void', 'public final void')
    controller = controller.replace('@PutMapping', '@PreAuthorize("isAuthenticated()") @PutMapping')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert check['status'] == 'incomplete'
    assert any(f['rule_id'] == 'SEF-ROUTE-01' for f in findings)
