"""Synthetic SEF contracts: observations, never verification or exploit claims."""
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gxsec import framework


BUILD = 'plugins { id("org.springframework.boot") version "3.5.6" }'
METHOD = '''@Configuration @EnableMethodSecurity(prePostEnabled = false)
class MethodSecurityConfig {
 @Bean MethodSecurityExpressionHandler handler() { return new MenuSecurityExpressionHandler(menuService, menuRoleService); }
 @Bean Advisor advisor(MethodSecurityExpressionHandler handler) {
  var manager = new PreAuthorizeAuthorizationManager();
  manager.setExpressionHandler(handler);
  return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(manager);
 }
}'''
WEB = '''@Configuration class WebSecurityConfig {
 @Bean SecurityFilterChain configure(HttpSecurity http) { http.requestMatchers("/adm/**").authenticated()
 .requestMatchers("/api/**").authenticated().anyRequest().permitAll(); return http.build(); }
}'''
ADMIN = '''@RestController @RequestMapping("/adm/users")
class UserAdminController {
 @PutMapping("/{id}/roles") public void changeRole(String id) { users.changeRole(id); }
}'''
TOKEN = '''class JwtTokenProvider {
 String createToken(String user) { return Jwts.builder().subject(user).signWith(key).compact(); }
 String createRefreshToken(String user) { return Jwts.builder().subject(user).signWith(key).compact(); }
 Authentication getAuthentication(String token) { return new UsernamePasswordAuthenticationToken(loadUserByUsername(getUsername(token)), null); }
 boolean validateToken(String token) { Jwts.parser().verifyWith(key).build().parseSignedClaims(token); return true; }
}'''


def inputs(tmp_path, files=None, prefix=''):
    files = files or {'build.gradle.kts': BUILD, 'src/main/java/MethodSecurityConfig.java': METHOD,
                      'src/main/java/WebSecurityConfig.java': WEB,
                      'src/main/java/UserAdminController.java': ADMIN}
    rows = []
    for relative, body in files.items():
        relative = prefix + relative
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding='utf-8')
        raw = path.read_bytes()
        rows.append({'path': relative, 'hash': hashlib.sha256(raw).hexdigest(), 'size': len(raw)})
    return {'files': sorted(r['path'] for r in rows), 'inventory': rows, 'scope_hash': 'scope', 'errors': []}


def run(tmp_path, files=None, prefix=''):
    return framework.run_framework_check(tmp_path, {}, inputs(tmp_path, files, prefix), 'release-check')


def rules(findings):
    return {f['rule_id'] for f in findings}


def test_private_admin_authenticated_is_candidate_with_structured_evidence(tmp_path):
    check, findings = run(tmp_path)
    assert check['framework']['family'] == 'SEF'
    assert check['framework']['variant'] == 'private'
    assert 'SEF-ADM-01' in rules(findings)
    finding = next(f for f in findings if f['rule_id'] == 'SEF-ADM-01')
    assert finding['validation'] == 'candidate' and finding['review_required'] is True
    assert finding['check_id'] == 'framework'
    assert finding['facts'] and finding['prerequisites'] and finding['counterevidence']
    assert all(e['path'] in check['coverage']['files'] and len(e['hash']) == 64 and e['line'] >= 1 for e in finding['evidence_refs'])
    assert check['status'] == 'complete'


@pytest.mark.parametrize('prefix', ['', 'relocated/backend/', 'other/project/'])
def test_public_class_guard_with_active_method_security_is_observed(tmp_path, prefix):
    files = {'build.gradle.kts': BUILD.replace('3.5.6', '2.7.18'),
             'src/main/java/M.java': METHOD, 'src/main/java/W.java': WEB,
             'src/main/java/C.java': ADMIN.replace('@RestController', '@PreAuthorize("hasRole(\'ADM\')") @RestController')}
    check, findings = run(tmp_path, files, prefix)
    assert check['framework']['variant'] == 'public'
    assert 'SEF-ADM-01' not in rules(findings)
    assert any(c['id'] == 'method-security' and c['state'] == 'observed' for c in check['framework']['contracts'])
    assert any(c['id'] == 'admin-boundary' and c['state'] == 'guard-observed' for c in check['framework']['contracts'])


def test_inactive_or_unknown_guards_do_not_become_safety(tmp_path):
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': '@Configuration @EnableMethodSecurity(prePostEnabled=false) class M {}',
             'src/main/java/W.java': WEB, 'src/main/java/C.java': ADMIN.replace('@RestController', '@PreAuthorize("customPolicy()") @RestController'),
             'src/main/java/E.java': 'class E { boolean hasMenuAuthority(String id) { return true; } }'}
    check, findings = run(tmp_path, files)
    assert 'SEF-ADM-01' in rules(findings)
    assert any('unknown' in str(c).lower() for c in check['framework']['contracts'])


def test_mixed_variants_are_per_module_not_directory_names(tmp_path):
    inv1 = inputs(tmp_path, prefix='alpha/')
    inv2 = inputs(tmp_path, {'build.gradle.kts': BUILD.replace('3.5.6', '2.7.18'), 'src/main/java/M.java': METHOD,
                             'src/main/java/W.java': WEB}, prefix='beta/')
    inventory = {**inv1, 'files': inv1['files'] + inv2['files'], 'inventory': inv1['inventory'] + inv2['inventory']}
    check, _ = framework.run_framework_check(tmp_path, {}, inventory, 'check')
    assert check['framework']['variant'] == 'mixed'
    assert {m['path'] for m in check['framework']['modules']} == {'alpha', 'beta'}


def test_non_sef_positive_detection_unit_and_no_name_only_detection(tmp_path):
    check, findings = run(tmp_path, {'src/A.java': 'package com.sqisoft.sef; class Safe {}'})
    assert check['framework']['family'] == 'unknown' and findings == []
    assert check['coverage']['eligible'] == check['coverage']['scanned'] == 1
    assert check['framework']['contracts'][0]['id'] == 'framework-detection'
    assert check['framework']['contracts'][0]['state'] == 'not-detected'


def test_jwt_shared_key_without_consumer_purpose_is_candidate(tmp_path):
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/T.java': TOKEN}
    _, findings = run(tmp_path, files)
    assert 'SEF-JWT-01' in rules(findings)


def test_jwt_explicit_rejecting_purpose_check_is_observed(tmp_path):
    protected = TOKEN.replace('Authentication getAuthentication(String token) {', 'Authentication getAuthentication(String token) { Jwts.parser().require("token_use", "access").parseSignedClaims(token);')
    _, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/T.java': protected})
    assert 'SEF-JWT-01' not in rules(findings)


def test_jwt_unrelated_or_conditional_purpose_check_does_not_hide_consumer(tmp_path):
    protected = TOKEN.replace('Jwts.parser()', 'Jwts.parser().require("token_use", "access")')
    _, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/T.java': protected})
    assert 'SEF-JWT-01' in rules(findings)


@pytest.mark.parametrize('advisor', [
    METHOD.replace('@Bean Advisor', 'Advisor'),
    METHOD.replace('preAuthorize(manager)', 'preAuthorize(otherManager)'),
    METHOD.replace('manager.setExpressionHandler(handler)', 'otherManager.setExpressionHandler(handler)'),
    METHOD.replace('return AuthorizationManager', 'if (flag) return AuthorizationManager'),
])
def test_unregistered_disconnected_or_conditional_advisor_is_unknown(tmp_path, advisor):
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': advisor, 'src/main/java/W.java': WEB,
             'src/main/java/C.java': ADMIN.replace('@RestController', '@PreAuthorize("hasRole(\'ADM\')") @RestController')}
    check, findings = run(tmp_path, files)
    assert 'SEF-ADM-01' in rules(findings)
    assert next(c for c in check['framework']['contracts'] if c['id'] == 'method-security')['state'] == 'unknown'


def test_method_guard_overrides_class_role_and_sibling_guard_does_not_leak(tmp_path):
    controller = ADMIN.replace('@RestController', '@PreAuthorize("hasRole(\'ADM\')") @RestController')
    controller = controller.replace('@PutMapping', '@PreAuthorize("isAuthenticated()") @PutMapping')
    _, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                               'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ADM-01' in rules(findings)


def test_literal_admin_url_role_guard_and_path_startswith_do_not_warn(tmp_path):
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
             'src/main/java/W.java': WEB.replace('"/adm/**").authenticated()', '"/adm/**").hasRole("ADM")'),
             'src/main/java/C.java': ADMIN,
             'src/main/java/F.java': 'class F { public void x() { Path base = root.toRealPath(); Path file = target.toRealPath(); if (!file.startsWith(base)) throw new SecurityException(); } }'}
    _, findings = run(tmp_path, files)
    assert not {'SEF-ADM-01', 'SEF-FILE-01'} & rules(findings)


def test_dynamic_admin_paths_are_explicit_assumptions(tmp_path):
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
             'src/main/java/W.java': WEB.replace('"/adm/**"', 'adminPaths.split(",")'), 'src/main/java/C.java': ADMIN}
    _, findings = run(tmp_path, files)
    candidate = next(f for f in findings if f['rule_id'] == 'SEF-ADM-01')
    assert any(e['fact'] == 'unresolved-or-method-specific-url-matcher' for e in candidate['evidence_refs'])


def test_unknown_contract_semantics_never_grants_verified_or_refuted_state(tmp_path):
    check, findings = run(tmp_path)
    assert all(f['validation'] == 'candidate' and f['lifecycle'] == 'open' for f in findings)
    assert all(c['state'] not in {'source-verified', 'runtime-verified', 'refuted', 'PASS'} for c in check['framework']['contracts'])


def test_renamed_layout_and_packages_use_nearest_selected_build_module(tmp_path):
    files = {'division/build.gradle.kts': BUILD, 'division/code/security/Methods.java': METHOD,
             'division/code/security/Web.java': WEB, 'division/code/users/Users.java': ADMIN}
    check, findings = run(tmp_path, files)
    assert check['framework']['variant'] == 'private'
    assert check['framework']['modules'][0]['path'] == 'division'
    assert 'SEF-ADM-01' in rules(findings)


def test_conditional_url_role_guard_cannot_remove_admin_candidate(tmp_path):
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
             'src/main/java/W.java': '@Profile("secure") ' + WEB.replace('"/adm/**").authenticated()', '"/adm/**").hasRole("ADM")'),
             'src/main/java/C.java': ADMIN}
    _, findings = run(tmp_path, files)
    assert 'SEF-ADM-01' in rules(findings)


def test_unknown_method_route_predicate_preserves_unmatched_route_candidate(tmp_path):
    controller = ADMIN.replace('/adm/users', '/business/users').replace('@PutMapping', '@PreAuthorize("customPolicy()") @PutMapping')
    _, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                               'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ROUTE-01' in rules(findings)


@pytest.mark.parametrize('kind', ['mapping', 'token-helper', 'menu-forwarding'])
def test_unmodeled_contract_preserves_review_or_explicit_incomplete(kind, tmp_path):
    controller = ADMIN
    token = TOKEN
    if kind == 'mapping':
        controller = ADMIN.replace('@PutMapping("/{id}/roles")', '@PutMapping(PATHS)')
    elif kind == 'token-helper':
        token = TOKEN.replace('.signWith(key)', '.signWith(resolveKey())')
    else:
        controller = '''@RestController @RequestMapping("/api/menus/{menuId}/boards") class C {
 @GetMapping("/{boardId}/files/{fileId}") @PreAuthorize("hasMenuAuthority(#menuId, 'R')")
 public void download(String menuId, Long boardId, Long fileId) { files.downloadBoardFile(menuId, boardId, fileId); }
}'''
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                              'src/main/java/W.java': WEB, 'src/main/java/C.java': controller, 'src/main/java/T.java': token})
    if kind == 'mapping':
        assert check['status'] == 'incomplete' and check['errors']
    else:
        assert check['status'] == 'complete'
        assert ('SEF-JWT-01' if kind == 'token-helper' else 'SEF-OBJ-01') in rules(findings)


def test_finding_identity_is_stable_under_line_shifts(tmp_path):
    _, before = run(tmp_path)
    files = {'build.gradle.kts': BUILD, 'src/main/java/MethodSecurityConfig.java': METHOD,
             'src/main/java/WebSecurityConfig.java': WEB, 'src/main/java/UserAdminController.java': '\n\n' + ADMIN}
    _, after = run(tmp_path, files)
    assert {f['finding_id'] for f in before} == {f['finding_id'] for f in after}
    assert before[0]['locations'][0]['line'] + 2 == after[0]['locations'][0]['line']


def test_security_annotations_inside_string_literals_do_not_activate_guards(tmp_path):
    methods = '''class M {
 String description = "@Configuration @EnableMethodSecurity(prePostEnabled = true)";
 String menu = "MenuSecurityExpressionHandler MenuRoleService";
}'''
    controller = ADMIN.replace('@RestController', '@PreAuthorize("hasRole(\'ADM\')") @RestController')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': methods,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ADM-01' in rules(findings)
    assert next(c for c in check['framework']['contracts'] if c['id'] == 'method-security')['state'] == 'unknown'


def test_metadata_description_cannot_invent_request_mapping(tmp_path):
    controller = ADMIN.replace('@PutMapping', '@Operation(summary = "@GetMapping") @PutMapping')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                               'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ADM-01' in rules(findings)
    assert next(c for c in check['framework']['contracts'] if c['id'] == 'admin-boundary')['route'] == '/adm/users/{id}/roles'


@pytest.mark.parametrize('token', [TOKEN.replace('createRefreshToken', 'renewSession'), 'class JwtTokenProvider {}'])
def test_unrecognized_token_contract_structure_is_explicitly_incomplete(tmp_path, token):
    check, _ = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                            'src/main/java/W.java': WEB, 'src/main/java/T.java': token})
    assert check['status'] == 'incomplete'
    assert any(c['id'] == 'jwt-purpose' and c['state'] == 'unknown' for c in check['framework']['contracts'])


def test_record_controller_structure_is_unknown_instead_of_silently_safe(tmp_path):
    controller = ADMIN.replace('class UserAdminController', 'record UserAdminController()')
    check, _ = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                            'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert check['status'] == 'incomplete'


@pytest.mark.parametrize('forward_menu,expected', [(False, True), (True, True)])
def test_menu_object_association_tracks_same_argument_not_helper_name(tmp_path, forward_menu, expected):
    controller = '''@RestController @RequestMapping("/api/menus/{menuId}/boards") class C {
 @GetMapping("/{boardId}/files/{fileId}") @PreAuthorize("hasMenuAuthority(#menuId, 'R')")
 public void download(String menuId, Long boardId, Long fileId) { files.downloadBoardFile(ARGSboardId, fileId); }
}'''.replace('ARGS', 'menuId, ' if forward_menu else '')
    _, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                              'src/main/java/C.java': controller, 'src/main/java/W.java': WEB})
    assert ('SEF-OBJ-01' in rules(findings)) is expected


def test_unmatched_route_and_file_prefix_have_conditional_candidates(tmp_path):
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/W.java': WEB,
             'src/main/java/C.java': ADMIN.replace('/adm/users', '/business/users'),
             'src/main/java/F.java': 'class BoardFileService { void download() { String base = root.getCanonicalPath(); String file = target.getCanonicalPath(); if (!file.startsWith(base)) throw new SecurityException(); } }'}
    _, findings = run(tmp_path, files)
    assert {'SEF-ROUTE-01', 'SEF-FILE-01'} <= rules(findings)
    assert 'path control' in str(next(f for f in findings if f['rule_id'] == 'SEF-FILE-01')['prerequisites']).lower()


def test_commented_out_guards_and_malformed_java_are_not_safety(tmp_path):
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/W.java': WEB,
             'src/main/java/C.java': '// @PreAuthorize("hasRole(\'ADM\')")\n' + ADMIN,
             'src/main/java/Broken.java': 'class Broken { void x( { '}
    check, findings = run(tmp_path, files)
    assert 'SEF-ADM-01' in rules(findings)
    assert any(c['state'] == 'unknown' for c in check['framework']['contracts'])
    assert check['status'] == 'incomplete'


def test_unselected_files_never_influence_detection_and_results_are_deterministic(tmp_path):
    inventory = inputs(tmp_path, {'README.md': 'ordinary project'})
    (tmp_path / 'JwtTokenProvider.java').write_text(TOKEN, encoding='utf-8')
    first = framework.run_framework_check(tmp_path, {}, inventory, 'check')
    assert first == framework.run_framework_check(tmp_path, {}, inventory, 'check')
    assert first[0]['framework']['family'] == 'unknown'


@pytest.mark.parametrize('kind', ['escape', 'duplicate', 'hash', 'inconsistent', 'oversize', 'binary'])
def test_invalid_or_bounded_inputs_fail_explicitly(tmp_path, kind):
    inventory = inputs(tmp_path)
    if kind == 'escape':
        inventory['files'].append('../outside.java')
        inventory['inventory'].append({'path': '../outside.java', 'hash': 'a' * 64})
    elif kind == 'duplicate':
        inventory['files'].append(inventory['files'][0])
        inventory['inventory'].append(inventory['inventory'][0])
    elif kind == 'hash':
        inventory['inventory'][0]['hash'] = '0' * 64
    elif kind == 'inconsistent':
        inventory['files'].pop()
    elif kind == 'oversize':
        inventory = inputs(tmp_path, {'Big.java': 'a' * (framework.MAX_FILE_BYTES + 1)})
    else:
        path = tmp_path / 'Bad.java'
        path.write_bytes(b'\xff\x00')
        inventory = {'files': ['Bad.java'], 'inventory': [{'path': 'Bad.java', 'hash': hashlib.sha256(path.read_bytes()).hexdigest()}]}
    check, findings = framework.run_framework_check(tmp_path, {}, inventory, 'check')
    assert check['status'] == 'incomplete' and check['errors']
    assert findings == []


def test_symlink_input_is_rejected(tmp_path):
    actual = tmp_path / 'Actual.java'
    actual.write_text('class X {}', encoding='utf-8')
    link = tmp_path / 'Link.java'
    try:
        link.symlink_to(actual)
    except OSError:
        pytest.skip('Creating symlinks requires local OS privilege')
    inventory = {'files': ['Link.java'], 'inventory': [{'path': 'Link.java', 'hash': hashlib.sha256(actual.read_bytes()).hexdigest()}]}
    check, _ = framework.run_framework_check(tmp_path, {}, inventory, 'check')
    assert check['status'] == 'incomplete' and check['errors']


@pytest.mark.parametrize('override', ['@PreAuthorize(value="permitAll()")', '@PreAuthorize(POLICY)', '@PreAuthorize(value=POLICY)'])
def test_review_named_or_constant_method_override_never_inherits_class_adm(tmp_path, override):
    controller = ADMIN.replace('@RestController', '@PreAuthorize("hasRole(\'ADM\')") @RestController')
    controller = controller.replace('@PutMapping', override + ' @PutMapping')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ADM-01' in rules(findings)
    boundary = next(c for c in check['framework']['contracts'] if c['id'] == 'admin-boundary')
    assert boundary['state'] == 'unknown' and boundary['predicate_present'] is True


@pytest.mark.parametrize('source_set', ['test', 'testFixtures', 'integrationTest', 'custom'])
def test_review_nonproduction_method_config_cannot_activate_production(tmp_path, source_set):
    controller = ADMIN.replace('@RestController', '@PreAuthorize("hasRole(\'ADM\')") @RestController')
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': 'class MenuSecurityExpressionHandler { MenuRoleService role; }',
             'src/main/java/W.java': WEB, 'src/main/java/C.java': controller,
             f'src/{source_set}/java/TestSecurity.java': METHOD}
    check, findings = run(tmp_path, files)
    assert 'SEF-ADM-01' in rules(findings)
    assert next(c for c in check['framework']['contracts'] if c['id'] == 'method-security')['state'] == 'unknown'


@pytest.mark.parametrize('kind', ['scoped', 'multiple', 'unregistered', 'helper', 'test-source'])
def test_review_inapplicable_filter_chain_cannot_supply_role_guard(tmp_path, kind):
    single = '''@Configuration class WebSecurityConfig {
 @Bean SecurityFilterChain chain(HttpSecurity http) {
  http.requestMatchers("/adm/**").hasRole("ADM").anyRequest().permitAll(); return http.build();
 }
}'''
    if kind == 'scoped':
        web = single.replace('http.requestMatchers', 'http.securityMatcher("/api/**").requestMatchers')
    elif kind == 'multiple':
        web = single[:-1] + '@Bean SecurityFilterChain fallback(HttpSecurity http) { http.anyRequest().permitAll(); return http.build(); } }'
    elif kind == 'unregistered':
        web = single.replace('@Bean ', '')
    elif kind == 'helper':
        web = single.replace('http.requestMatchers("/adm/**").hasRole("ADM").anyRequest().permitAll();', 'http.anyRequest().permitAll();')
        web = web[:-1] + ' void unused(HttpSecurity http) { http.requestMatchers("/adm/**").hasRole("ADM"); } }'
    else:
        web = single
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/C.java': ADMIN,
             ('src/test/java/W.java' if kind == 'test-source' else 'src/main/java/W.java'): web}
    check, findings = run(tmp_path, files)
    assert 'SEF-ADM-01' in rules(findings)
    assert next(c for c in check['framework']['contracts'] if c['id'] == 'admin-boundary')['state'] != 'guard-observed'


@pytest.mark.parametrize('metadata', ['@Operation(tags={"users"})', '@Operation(tags={"users", "roles"}) @RequestPart("payload")'])
def test_review_array_metadata_after_mapping_preserves_method_ownership(tmp_path, metadata):
    controller = ADMIN.replace('@PutMapping("/{id}/roles")', '@PutMapping("/{id}/roles") ' + metadata)
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ADM-01' in rules(findings)
    assert next(c for c in check['framework']['contracts'] if c['id'] == 'admin-boundary')['route'] == '/adm/users/{id}/roles'


@pytest.mark.parametrize('parameters,checked,consumed', [('String trustedToken, String token', 'trustedToken', 'token'),
                                                      ('String token, String otherToken', 'token', 'otherToken'),
                                                      ('String token, String ignored', 'token', 'token')])
def test_review_ambiguous_jwt_parameters_keep_candidate(tmp_path, parameters, checked, consumed):
    token = TOKEN.replace('Authentication getAuthentication(String token) {',
                          'Authentication getAuthentication(' + parameters + ') { Jwts.parser().require("token_use", "access").parseSignedClaims(' + checked + ');')
    token = token.replace('getUsername(token)', 'getUsername(' + consumed + ')')
    _, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/T.java': token})
    assert 'SEF-JWT-01' in rules(findings)


def test_review_distinct_paths_packages_and_overloads_have_unique_stable_ids(tmp_path):
    overloaded = ADMIN.replace('String id) { users.changeRole(id); }',
                              'String id) { users.changeRole(id); }\n @PutMapping("/{id}/roles/number") public void changeRole(Long id) { users.changeRole(id); }')
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/W.java': WEB,
             'src/main/java/a/C.java': 'package a;\n' + overloaded,
             'src/main/java/b/C.java': 'package b;\n' + overloaded}
    _, findings = run(tmp_path, files)
    admin = [f for f in findings if f['rule_id'] == 'SEF-ADM-01']
    assert len(admin) == 4
    assert len({f['finding_id'] for f in admin}) == 4
    shifted = {path: '\n\n' + body for path, body in files.items()}
    _, later = run(tmp_path, shifted)
    assert {f['finding_id'] for f in findings} == {f['finding_id'] for f in later}


def test_review_jwt_and_file_overloads_do_not_collide(tmp_path):
    token = TOKEN.replace('Authentication getAuthentication(String token)', 'Authentication getAuthentication(String token)')
    file_service = '''class BoardFileService {
 public void download(String id) { String base = root.getCanonicalPath(); String file = target.getCanonicalPath(); if (!file.startsWith(base)) throw new SecurityException(); }
 public void download(Long id) { String base = root.getCanonicalPath(); String file = target.getCanonicalPath(); if (!file.startsWith(base)) throw new SecurityException(); }
}'''
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
             'src/main/java/a/T.java': 'package a; ' + token, 'src/main/java/b/T.java': 'package b; ' + token,
             'src/main/java/F.java': file_service}
    _, findings = run(tmp_path, files)
    assert len(findings) == 4
    assert len({f['finding_id'] for f in findings}) == 4


def test_review_dynamic_url_scope_is_one_module_gap_without_per_route_candidates(tmp_path):
    web = WEB.replace('"/adm/**"', 'adminPaths.split(",")').replace('"/api/**"', 'apiPaths.split(",")')
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/W.java': web,
             'src/main/java/C.java': ADMIN.replace('/adm/users', '/api/users'),
             'src/main/java/D.java': ADMIN.replace('UserAdminController', 'OtherController').replace('/adm/users', '/outside/users')}
    check, findings = run(tmp_path, files)
    route_questions = [f for f in findings if f['rule_id'] == 'SEF-ROUTE-01']
    assert len(route_questions) == 1
    assert route_questions[0]['review_required'] is True
    assert route_questions[0]['locations'][0]['symbol'].endswith('.url-scope')
    gaps = [c for c in check['framework']['contracts'] if c['id'] == 'url-scope']
    assert len(gaps) == 1 and gaps[0]['state'] == 'unknown'
    assert check['status'] == 'complete'


def test_review_named_adm_predicate_is_supported_when_it_is_the_actual_override(tmp_path):
    controller = ADMIN.replace('@PutMapping', '@PreAuthorize(value="hasRole(\'ADM\')") @PutMapping')
    _, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                               'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ADM-01' not in rules(findings)


def test_review_consumes_only_mapping_and_requestpart_keep_default_path(tmp_path):
    controller = ADMIN.replace('@PutMapping("/{id}/roles")', '@PostMapping(consumes=MediaType.MULTIPART_FORM_DATA_VALUE) @Operation(tags={"users"})')
    controller = controller.replace('String id)', '@RequestPart("payload") String id)')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ADM-01' in rules(findings)
    assert check['status'] == 'complete'
    assert next(c for c in check['framework']['contracts'] if c['id'] == 'admin-boundary')['route'] == '/adm/users'


def test_review_classes_in_one_file_keep_own_routes_guards_and_ids(tmp_path):
    controller = 'class Helper {}\n' + ADMIN + '\n' + ADMIN.replace('UserAdminController', 'OtherAdminController').replace('/adm/users', '/adm/other')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    admin = [f for f in findings if f['rule_id'] == 'SEF-ADM-01']
    assert len(admin) == 2 and len({f['finding_id'] for f in admin}) == 2
    assert {c['route'] for c in check['framework']['contracts'] if c['id'] == 'admin-boundary'} == {'/adm/users/{id}/roles', '/adm/other/{id}/roles'}


def test_review_single_string_parameter_check_cannot_protect_other_token_field(tmp_path):
    token = TOKEN.replace('Authentication getAuthentication(String token) {',
                          'Authentication getAuthentication(String token) { Jwts.parser().require("token_use", "access").parseSignedClaims(token);')
    token = token.replace('getUsername(token)', 'getUsername(otherToken)')
    _, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/T.java': token})
    assert 'SEF-JWT-01' in rules(findings)


def test_review_mapping_without_supported_method_body_is_explicitly_incomplete(tmp_path):
    controller = '''@RestController @RequestMapping("/adm/users") abstract class UserAdminController {
 @PutMapping("/{id}") public abstract void changeRole(String id);
}'''
    check, _ = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                            'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert check['status'] == 'incomplete'
    assert any(c.get('reason') == 'Request mapping has no supported class/method owner' for c in check['framework']['contracts'])


def test_review_two_providers_in_one_file_preserve_independent_candidates(tmp_path):
    token = TOKEN + '\n' + TOKEN.replace('JwtTokenProvider', 'OtherJwtProvider')
    _, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD, 'src/main/java/T.java': token})
    candidates = [f for f in findings if f['rule_id'] == 'SEF-JWT-01']
    assert len(candidates) == 2 and len({f['finding_id'] for f in candidates}) == 2


def test_review_nested_test_fixture_main_path_cannot_activate_production(tmp_path):
    controller = ADMIN.replace('@RestController', '@PreAuthorize("hasRole(\'ADM\')") @RestController')
    files = {'build.gradle.kts': BUILD, 'src/main/java/M.java': 'class MenuSecurityExpressionHandler { MenuRoleService role; }',
             'src/main/java/W.java': WEB, 'src/main/java/C.java': controller,
             'src/test/fixtures/example/src/main/java/TestSecurity.java': METHOD}
    _, findings = run(tmp_path, files)
    assert 'SEF-ADM-01' in rules(findings)


@pytest.mark.parametrize('mapping', [
    '@RequestMapping(method=RequestMethod.PUT)',
    '@RequestMapping(method=RequestMethod.POST)',
    '@RequestMapping(method=RequestMethod.PATCH)',
    '@RequestMapping(method=RequestMethod.DELETE)',
    '@RequestMapping(method={RequestMethod.GET, RequestMethod.PUT})',
    '@RequestMapping(method={RequestMethod.DELETE})',
    '@RequestMapping',
    '@RequestMapping()',
    '@RequestMapping(method={})',
])
def test_round2_request_mapping_mutating_or_all_verbs_keeps_admin_candidate(tmp_path, mapping):
    controller = ADMIN.replace('@PutMapping("/{id}/roles")', mapping)
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ADM-01' in rules(findings)
    assert check['status'] == 'complete'


@pytest.mark.parametrize('method', ['RequestMethod.GET', 'RequestMethod.HEAD', 'RequestMethod.OPTIONS', '{RequestMethod.GET, RequestMethod.HEAD}'])
def test_round2_request_mapping_known_safe_verbs_do_not_invent_mutation(tmp_path, method):
    controller = ADMIN.replace('@PutMapping("/{id}/roles")', '@RequestMapping(method=' + method + ')')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert 'SEF-ADM-01' not in rules(findings)
    assert check['status'] == 'complete'


@pytest.mark.parametrize('method', ['VERBS', '{RequestMethod.GET, WRITE_VERB}', 'resolveMethods()', 'RequestMethod.UNKNOWN'])
def test_round2_unresolved_request_mapping_verbs_are_explicitly_incomplete(tmp_path, method):
    controller = ADMIN.replace('@PutMapping("/{id}/roles")', '@RequestMapping(method=' + method + ')')
    check, _ = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                            'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert check['status'] == 'incomplete'
    assert any(c.get('reason') == 'Unsupported request method constraint' for c in check['framework']['contracts'])


@pytest.mark.parametrize('class_method', ['RequestMethod.PUT', 'CLASS_VERBS'])
def test_round2_unmodeled_class_and_method_verb_composition_stays_incomplete(tmp_path, class_method):
    controller = ADMIN.replace('@RequestMapping("/adm/users")', '@RequestMapping(value="/adm/users", method=' + class_method + ')')
    controller = controller.replace('@PutMapping("/{id}/roles")', '@RequestMapping(method=RequestMethod.GET)')
    check, _ = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                            'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    assert check['status'] == 'incomplete'
    assert any(c.get('reason') == 'Unsupported request method constraint' for c in check['framework']['contracts'])


@pytest.mark.parametrize('site', ['class', 'method'])
def test_round3_unknown_authorization_literal_is_not_exported_in_check_or_findings(tmp_path, site):
    sentinel = 'SYNTHETIC_LITERAL_6c731f'
    expression = "@gate.allowed('" + sentinel + "')"
    marker = '@RestController' if site == 'class' else '@PutMapping'
    controller = ADMIN.replace(marker, '@PreAuthorize("' + expression + '") ' + marker)
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    exported = json.dumps({'check': check, 'findings': findings})
    assert sentinel not in exported and expression not in exported
    assert 'SEF-ADM-01' in rules(findings)
    boundary = next(c for c in check['framework']['contracts'] if c['id'] == 'admin-boundary')
    assert boundary['state'] == 'unknown' and boundary['predicate_present'] is True
    assert boundary['guard_kind'] == 'custom-or-unsupported'
    assert 'predicate' not in boundary
    assert all(f['validation'] == 'candidate' and f['review_required'] for f in findings)


def test_round3_known_guard_retains_normalized_kind_and_observed_state(tmp_path):
    controller = ADMIN.replace('@RestController', '@PreAuthorize("hasRole(\'ADM\')") @RestController')
    check, findings = run(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                   'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    boundary = next(c for c in check['framework']['contracts'] if c['id'] == 'admin-boundary')
    assert boundary['guard_kind'] == 'adm-role'
    assert boundary['state'] == 'guard-observed' and boundary['predicate_present'] is True
    assert 'SEF-ADM-01' not in rules(findings)
    assert "hasRole('ADM')" not in json.dumps(check)


def test_round3_all_generated_shared_artifacts_omit_custom_authorization_literal(tmp_path):
    from gxsec.reporting import write_reports
    from gxsec.triage import enrich_framework_findings

    sentinel = 'SYNTHETIC_LITERAL_6c731f'
    expression = "@gate.allowed('" + sentinel + "')"
    controller = ADMIN.replace('@PutMapping', '@PreAuthorize("' + expression + '") @PutMapping')
    inventory = inputs(tmp_path, {'build.gradle.kts': BUILD, 'src/main/java/M.java': METHOD,
                                 'src/main/java/W.java': WEB, 'src/main/java/C.java': controller})
    check, findings = framework.run_framework_check(tmp_path, {}, inventory, 'static-release')
    run_data = {'schema_version': 1, 'run_id': 'privacy-framework', 'project_id': 'synthetic',
                'profile': 'static-release', 'source': {**inventory, 'hash': 'synthetic-source'},
                'checks': [check], 'findings': enrich_framework_findings(findings, inventory),
                'gate': {'status': 'INCOMPLETE', 'exit_code': 2}, 'reviews': [], 'exceptions': []}
    output = tmp_path / 'shared'
    artifacts = write_reports(run_data, output)
    assert {'report.html', 'result.json', 'review-packets.json'} <= {p.name for p in artifacts}
    for artifact in artifacts:
        exported = artifact.read_text(encoding='utf-8')
        assert sentinel not in exported and expression not in exported, artifact.name
