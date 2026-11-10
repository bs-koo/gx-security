"""A declared SEF foundation cannot silently become a successful non-SEF scan."""
import copy
import json

import pytest

from gxsec import config, framework
from tests.test_gxsec_framework import ADMIN, BUILD, METHOD, WEB, inputs


BOUNDARIES = {'admin-boundary', 'jwt-purpose', 'menu-object-association',
              'route-boundary', 'file-confinement'}


def expectation(*contracts):
    return {'expected_family': 'SEF', 'required_contracts': list(contracts)}


def scan(tmp_path, files, project=None, protected=None):
    cfg = {}
    if project is not None:
        cfg['framework'] = project
    if protected is not None:
        cfg['_trusted_policy'] = {'framework': protected}
    return framework.run_framework_check(tmp_path, cfg, inputs(tmp_path, files), 'static-release')


def errors(check):
    return {e['type'] for e in check['errors']}


def basic_files(marker=METHOD):
    return {'build.gradle.kts': BUILD, 'src/main/java/M.java': marker,
            'src/main/java/W.java': WEB, 'src/main/java/C.java': ADMIN}


def test_generic_project_remains_detection_only_without_sef_expectation(tmp_path):
    check, findings = scan(tmp_path, {'App.java': 'class App {}'})
    assert check['status'] == 'complete'
    assert check['framework']['family'] == 'unknown'
    assert not findings


def test_java_strings_cannot_supply_sef_security_signals(tmp_path):
    files = {'build.gradle.kts': BUILD, 'src/main/java/Example.java': '''class Example {
        String menu = "MenuSecurityExpressionHandler";
        String url = "WebSecurityConfig .requestMatchers(";
        String jwt = "JwtTokenProvider Jwts. parseSignedClaims";
        String common = "BoardFileService ApiResponse SecurityUser MenuRoleService";
    }'''}
    check, findings = scan(tmp_path, files, protected=expectation())
    assert check['framework']['family'] == 'unknown'
    assert check['status'] == 'incomplete'
    assert 'framework_expected_family_unverified' in errors(check)


def test_expected_sef_unknown_is_incomplete_and_still_investigates_controller(tmp_path):
    files = basic_files(METHOD.replace('MenuSecurityExpressionHandler', 'PermissionExpressionHandler'))
    check, findings = scan(tmp_path, files, protected=expectation('admin-boundary'))
    assert check['status'] == 'incomplete'
    assert check['framework']['family'] == 'unknown'
    assert 'framework_expected_family_unverified' in errors(check)
    assert any(f['rule_id'] == 'SEF-ADM-01' for f in findings)
    assert all(f['validation'] == 'candidate' for f in findings)


def test_missing_required_boundary_is_coverage_gap_not_vulnerability(tmp_path):
    check, findings = scan(tmp_path, basic_files(), protected=expectation('jwt-purpose'))
    assert check['status'] == 'incomplete'
    assert 'framework_required_contract_unobserved' in errors(check)
    assert any(e.get('contract') == 'jwt-purpose' for e in check['errors'])
    assert not any(f['rule_id'] == 'SEF-JWT-01' for f in findings)


def test_expected_family_defaults_to_all_five_boundaries(tmp_path):
    check, _ = scan(tmp_path, basic_files(), protected={'expected_family': 'SEF'})
    assert set(check['framework']['requirements']['required_contracts']) == BOUNDARIES
    assert check['status'] == 'incomplete'


def test_observed_required_admin_boundary_can_complete_without_safety_claim(tmp_path):
    check, findings = scan(tmp_path, basic_files(), protected=expectation('admin-boundary'))
    assert check['status'] == 'complete'
    assert any(f['rule_id'] == 'SEF-ADM-01' for f in findings)
    assert check['framework']['boundary_coverage']['admin-boundary']['evaluated'] >= 1


def test_guarded_routes_also_record_route_evaluation(tmp_path):
    files = basic_files()
    files['src/main/java/W.java'] = WEB.replace('"/adm/**").authenticated()', '"/adm/**").hasRole("ADM")')
    check, findings = scan(tmp_path, files, protected=expectation('route-boundary'))
    assert check['status'] == 'complete'
    assert check['framework']['boundary_coverage']['route-boundary']['evaluated'] == 1
    assert not any(f['rule_id'] == 'SEF-ADM-01' for f in findings)


def test_protected_contract_cannot_be_removed_by_project_empty_list(tmp_path):
    check, _ = scan(tmp_path, basic_files(), project=expectation(),
                    protected=expectation('jwt-purpose'))
    assert check['status'] == 'incomplete'
    assert check['framework']['requirements']['required_contracts'] == ['jwt-purpose']


def test_project_can_add_requirements_to_protected_contract(tmp_path):
    check, _ = scan(tmp_path, basic_files(), project=expectation('file-confinement'),
                    protected=expectation('admin-boundary'))
    assert set(check['framework']['requirements']['required_contracts']) == {'admin-boundary', 'file-confinement'}
    assert check['status'] == 'incomplete'


@pytest.mark.parametrize('bad', [False, [], 'SEF', {'expected_family': 'none'},
    {'expected_family': 'SEF', 'required_contracts': 'admin-boundary'},
    {'expected_family': 'SEF', 'required_contracts': ['typo']},
    {'expected_family': 'SEF', 'required_contracts': [False]},
    {'expected_family': 'SEF', 'skip': True}, {'required_contracts': ['admin-boundary']}])
def test_malformed_protected_expectation_fails_closed(tmp_path, bad):
    check, _ = scan(tmp_path, basic_files(), protected=bad)
    assert check['status'] == 'incomplete'
    assert 'framework_requirement_invalid' in errors(check)


@pytest.mark.parametrize('bad', [False, {'expected_family': 'none'},
    {'expected_family': 'SEF', 'required_contracts': ['typo']}])
def test_project_config_rejects_invalid_framework_expectations(tmp_path, bad):
    path = tmp_path / 'gxsec.yaml'
    path.write_text(json.dumps({'framework': bad}), encoding='utf-8')
    with pytest.raises(ValueError, match='framework'):
        config.load_config(path)


def test_project_config_accepts_additional_strict_expectation(tmp_path):
    path = tmp_path / 'gxsec.yaml'
    path.write_text(json.dumps({'framework': expectation('admin-boundary')}), encoding='utf-8')
    assert config.load_config(path)['framework'] == expectation('admin-boundary')


def test_declared_gradle_dependency_carries_detection_not_guard_authority(tmp_path):
    files = {'build.gradle.kts': BUILD,
        'security/build.gradle.kts': 'dependencies {}',
        'security/src/main/java/M.java': METHOD,
        'security/src/main/java/W.java': WEB.replace('"/adm/**").authenticated()', '"/adm/**").hasRole("ADM")'),
        'api/build.gradle.kts': 'dependencies { implementation(project(":security")) }',
        'api/src/main/java/C.java': ADMIN}
    check, findings = scan(tmp_path, files)
    assert check['framework']['family'] == 'SEF'
    assert {m['path'] for m in check['framework']['modules']} == {'security', 'api'}
    assert any(f['rule_id'] == 'SEF-ADM-01' for f in findings), 'A linked module does not prove runtime guard activation'


def test_dependency_text_inside_string_is_not_a_module_link(tmp_path):
    files = {'build.gradle.kts': BUILD,
        'security/build.gradle.kts': 'dependencies {}',
        'security/src/main/java/M.java': METHOD, 'security/src/main/java/W.java': WEB,
        'api/build.gradle.kts': '''def example = 'implementation(project(":security"))' ''',
        'api/src/main/java/C.java': ADMIN}
    check, _ = scan(tmp_path, files)
    assert {m['path'] for m in check['framework']['modules']} == {'security'}


def test_expected_sef_covers_unrecognized_sibling_java_module(tmp_path):
    files = {'foundation/' + p: body for p, body in basic_files().items()}
    files.update({'api/build.gradle.kts': 'dependencies {}', 'api/src/main/java/C.java': ADMIN})
    check, findings = scan(tmp_path, files, protected=expectation('admin-boundary'))
    assert check['status'] == 'incomplete'
    assert 'framework_module_unverified' in errors(check)
    assert any(f['locations'][0]['path'] == 'api/src/main/java/C.java' for f in findings)


def test_guard_from_unrelated_module_does_not_suppress_required_inspection(tmp_path):
    files = {'security/' + p: body for p, body in basic_files().items()}
    files['security/src/main/java/W.java'] = WEB.replace('"/adm/**").authenticated()', '"/adm/**").hasRole("ADM")')
    files.update({'api/build.gradle.kts': 'dependencies {}', 'api/src/main/java/C.java': ADMIN})
    check, findings = scan(tmp_path, files, protected=expectation('admin-boundary'))
    assert check['status'] == 'incomplete'
    assert any(f['rule_id'] == 'SEF-ADM-01' and f['locations'][0]['path'].startswith('api/') for f in findings)


def test_partial_inventory_cannot_satisfy_expected_framework_scope(tmp_path):
    inventory = inputs(tmp_path, basic_files())
    inventory['scope'] = 'partial'
    check, _ = framework.run_framework_check(tmp_path, {'framework': expectation('admin-boundary')},
                                             inventory, 'static-release')
    assert check['status'] == 'incomplete'
    assert 'framework_expected_scope_incomplete' in errors(check)


def test_requirement_changes_are_part_of_analysis_contract(tmp_path):
    first, _ = scan(tmp_path, basic_files(), protected=expectation('admin-boundary'))
    second, _ = scan(tmp_path, basic_files(), protected=expectation('admin-boundary', 'jwt-purpose'))
    assert first['engine'] != second['engine']


def test_input_config_is_not_mutated_by_effective_contract(tmp_path):
    cfg = {'framework': expectation('admin-boundary'), '_trusted_policy': {'framework': expectation('jwt-purpose')}}
    before = copy.deepcopy(cfg)
    framework.run_framework_check(tmp_path, cfg, inputs(tmp_path, basic_files()), 'static-release')
    assert cfg == before


def test_module_budget_exhaustion_is_explicit_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(framework, 'MAX_MODULES', 1, raising=False)
    files = {'first/' + p: body for p, body in basic_files().items()}
    files.update({'second/build.gradle.kts': BUILD, 'second/src/main/java/X.java': 'class X {}'})
    check, findings = scan(tmp_path, files, protected=expectation('admin-boundary'))
    assert check['status'] == 'incomplete'
    assert 'framework_resource_limit' in errors(check)
    assert not findings


def test_required_route_with_unresolved_matchers_stays_incomplete(tmp_path):
    files = basic_files()
    files['src/main/java/W.java'] = WEB.replace('"/adm/**"', 'configuredAdminPaths')
    check, _ = scan(tmp_path, files, protected=expectation('route-boundary'))
    assert check['status'] == 'incomplete'
    assert check['framework']['boundary_coverage']['route-boundary']['unsupported'] > 0


def test_schema_contracts_match_runtime_identifiers_and_remediation_kind():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for name in ('project', 'policy'):
        schema = json.loads((root / 'schemas' / (name + '.json')).read_text(encoding='utf-8'))
        schema_contract = schema['properties']['framework']
        assert set(schema_contract['properties']['required_contracts']['items']['enum']) == BOUNDARIES
        assert schema_contract['additionalProperties'] is False
    assert 'remediation-validation' in schema['properties']['trusted_approvals']['items']['properties']['kind']['enum']
