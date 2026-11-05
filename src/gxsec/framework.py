"""Bounded, inventory-only SEF source contracts; no code execution or approvals.

This is intentionally a structural recognizer, not a Java compiler, call graph,
Spring configuration evaluator, or runtime exploit test. Facts describe only
the selected snapshot. Even observed guards require an independent review.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .models import content_hash, make_check, make_finding
from .snapshot import _handle_path
from .source import reject_reparse_path


VERSION = '1.0.0'
MAX_FILES = 20000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_METHODS = 20000
RULE_IDS = ['SEF-ADM-01', 'SEF-JWT-01', 'SEF-OBJ-01', 'SEF-ROUTE-01', 'SEF-FILE-01']
LIMITATIONS = [
    'Structural Java/Spring source observations only; no full call graph or runtime verification.',
    'Dynamic matchers, profiles, conditional beans, proxy applicability and custom predicates remain unknown.',
    'Forwarding menu identifiers does not prove a repository or database ownership relation.',
    'Observed snapshot hashes identify inputs, not an approved or historically identified SEF baseline.',
    'Unsupported Java/Kotlin/XML semantics and deployment, policy data, path control and filesystem links require review.',
]
_LEX = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/')
_STRINGS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_DECL = re.compile(r'(?<![@\w])\b(?:(?:public|protected|private)\s+)?(?:(?:static|final|synchronized|abstract|default)\s+)*[\w<>?,.\[\] \t]{1,240}?\s+(\w+)\s*\(')
_AFTER_ARGS = re.compile(r'\s*(?:throws\s+[\w.,\s]{1,500})?\s*\{')
_MAPPING = re.compile(r'@(Request|Get|Post|Put|Delete|Patch)Mapping\b')


def _blank(value):
    return ''.join('\n' if c == '\n' else ' ' for c in value)


def _lex(text):
    """Preserve offsets and newlines while excluding comments from facts."""
    clean = _LEX.sub(lambda m: _blank(m[0]) if m[0].startswith(('//', '/*')) else m[0], text)
    mask = _STRINGS.sub(lambda m: _blank(m[0]), clean)
    return clean, mask


def _pairs(mask):
    stack, pairs = [], {}
    for pos, char in enumerate(mask):
        if char in '({[':
            stack.append((char, pos))
        elif char in ')}]':
            if not stack or stack[-1][0] != {')': '(', '}': '{', ']': '['}[char]:
                raise ValueError('Unbalanced Java delimiters')
            _, start = stack.pop()
            pairs[start] = pos
    if stack:
        raise ValueError('Unbalanced Java delimiters')
    return pairs


def _module(path):
    if '/src/' in '/' + path:
        return ('/' + path).split('/src/', 1)[0].lstrip('/') or '.'
    return str(PurePosixPath(path).parent)


def _is_input(path):
    name = PurePosixPath(path).name
    return path.endswith('.java') or name in {'build.gradle', 'build.gradle.kts', 'pom.xml'}


def _source_set(doc):
    # Use the first source-set boundary relative to the selected build module;
    # a nested test fixture containing src/main is still a test input.
    relative = doc['path']
    if doc['module'] != '.' and relative.startswith(doc['module'] + '/'):
        relative = relative[len(doc['module']) + 1:]
    boundary = re.search(r'(?:^|/)src/([^/]+)/', relative)
    return boundary[1] if boundary else 'unknown'


def _production_source(doc):
    return _source_set(doc) == 'main'


def _load(source, inventory):
    """Validate all names before opening any selected input, and verify its bytes."""
    root = reject_reparse_path(source).resolve(strict=True)
    if not root.is_dir() or not isinstance(inventory, dict):
        raise ValueError('Invalid framework source inventory')
    files, rows = inventory.get('files'), inventory.get('inventory')
    if not isinstance(files, list) or not isinstance(rows, list) or len(files) > MAX_FILES:
        raise ValueError('Invalid or exhausted framework file inventory')
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError('Invalid framework inventory records')
    names = [row.get('path') for row in rows]
    if (not all(isinstance(p, str) for p in files + names)
            or len(set(files)) != len(files) or sorted(files) != sorted(names)):
        raise ValueError('Inconsistent or duplicate framework inventory')
    for row in rows:
        name = row['path']
        path = PurePosixPath(name)
        if (not name or '\\' in name or ':' in name or '\x00' in name or path.is_absolute()
                or any(part in {'', '.', '..', '.git'} for part in name.split('/'))
                or not re.fullmatch(r'[a-f0-9]{64}', str(row.get('hash', '')))):
            raise ValueError('Invalid framework inventory path or digest')
    documents, total = [], 0
    for row in sorted(rows, key=lambda r: r['path']):
        if not _is_input(row['path']):
            continue
        path = reject_reparse_path(root.joinpath(*PurePosixPath(row['path']).parts))
        path.resolve(strict=True).relative_to(root)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('Framework input must be a regular unlinked file')
        if before.st_size > MAX_FILE_BYTES or total + before.st_size > MAX_TOTAL_BYTES:
            raise ValueError('Framework source byte budget exhausted')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(path, flags), 'rb') as handle:
            opened = os.fstat(handle.fileno())
            _handle_path(handle).resolve().relative_to(root)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('Framework input changed while opening')
            raw = handle.read(MAX_FILE_BYTES + 1)
            after = os.fstat(handle.fileno())
            _handle_path(handle).resolve().relative_to(root)
        reject_reparse_path(path)
        if ((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('Framework input changed during read')
        total += len(raw)
        if len(raw) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError('Framework source byte budget exhausted')
        if hashlib.sha256(raw).hexdigest() != row['hash']:
            raise ValueError('Framework input digest differs from snapshot inventory')
        text = raw.decode('utf-8-sig', errors='strict')
        if '\x00' in text:
            raise ValueError('Binary framework source is unsupported')
        clean, mask = _lex(text)
        documents.append({'path': row['path'], 'hash': row['hash'], 'text': text,
                          'clean': clean, 'mask': mask, 'module': _module(row['path'])})
    build_roots = sorted({str(PurePosixPath(d['path']).parent) for d in documents
                          if PurePosixPath(d['path']).name in {'build.gradle', 'build.gradle.kts', 'pom.xml'}},
                         key=lambda p: (-len(PurePosixPath(p).parts), p))
    for doc in documents:
        doc['module'] = next((p for p in build_roots if p == '.' or doc['path'].startswith(p + '/')), doc['module'])
    return documents


def _evidence(doc, offset=0, fact='source-observation'):
    return {'path': doc['path'], 'line': doc['text'].count('\n', 0, offset) + 1,
            'hash': doc['hash'], 'fact': fact}


def _member_start(mask, before, reverse_pairs):
    """Walk past whole annotation arguments before considering member braces."""
    cursor = before - 1
    while cursor >= 0:
        char = mask[cursor]
        if char in ')]' and cursor in reverse_pairs:
            cursor = reverse_pairs[cursor] - 1
        elif char in '{};':
            return cursor + 1
        else:
            cursor -= 1
    return 0


def _classes(doc, pairs):
    mask = doc['mask']
    reverse = {end: start for start, end in pairs.items()}
    package = re.search(r'\bpackage\s+([\w.]+)\s*;', mask)
    classes = []
    for match in re.finditer(r'\bclass\s+(\w+)\b', mask):
        opening = mask.find('{', match.end())
        if opening not in pairs:
            continue
        parents = [c for c in classes if c['opening'] < match.start() < c['end']]
        owner = '.'.join(([package[1]] if package else []) + [c['name'] for c in parents] + [match[1]])
        header_start = _member_start(mask, match.start(), reverse)
        classes.append({'name': match[1], 'owner': owner, 'start': match.start(),
                        'opening': opening, 'end': pairs[opening],
                        'header_start': header_start,
                        'header': doc['clean'][header_start:match.start()]})
    return classes


def _methods(doc, pairs):
    result = []
    reverse = {end: start for start, end in pairs.items()}
    classes = _classes(doc, pairs)
    doc['classes'] = classes
    for match in _DECL.finditer(doc['mask']):
        start = match.end() - 1
        if start not in pairs:
            continue
        end_args = pairs[start]
        after = _AFTER_ARGS.match(doc['mask'], end_args + 1)
        if not after:
            continue
        opening = after.end() - 1
        if opening not in pairs:
            continue
        owner = next((c for c in reversed(classes) if c['opening'] < match.start() < c['end']), None)
        previous = _member_start(doc['mask'], match.start(), reverse)
        result.append({'name': match[1], 'start': match.start(), 'end': pairs[opening] + 1,
                       'owner': owner['owner'] if owner else '<unknown>',
                       'class': owner,
                       'signature': doc['clean'][match.start():opening],
                       'parameters': doc['clean'][start + 1:end_args],
                       'annotations': doc['clean'][previous:match.start()],
                       'annotation_start': previous,
                       'body': doc['clean'][opening + 1:pairs[opening]],
                       'body_mask': doc['mask'][opening + 1:pairs[opening]],
                       'body_start': opening + 1})
    return result


def _annotation(text, name):
    marker = re.search(r'@' + name + r'\b', _lex(text)[1])
    if not marker:
        return False, None
    found = re.match(r'@' + name + r'\b\s*\(\s*(?:value\s*=\s*)?"((?:\\.|[^"\\])*)"\s*\)', text[marker.start():])
    return True, found[1] if found else None


def _mapping(text):
    found = _MAPPING.search(_lex(text)[1])
    if not found:
        return None, False
    tail = text[found.end():]
    if not tail.lstrip().startswith('('):
        return '', True
    # Only one literal path is modeled; arrays and computed paths stay unknown.
    argument = re.match(r'\s*\(\s*(?:(?:value|path)\s*=\s*)?"([^"]*)"', tail)
    if not argument:
        # consumes/produces/headers/params/name do not change the default path.
        clean, mask = _lex(tail)
        opening = mask.find('(')
        try:
            closing = _pairs(mask).get(opening)
        except ValueError:
            closing = None
        if closing is not None:
            args = clean[opening + 1:closing]
            if not args.strip():
                return '', True
            if re.match(r'\s*(?:consumes|produces|headers|params|name|method)\s*=', args) and not re.search(r'\b(?:value|path)\s*=', _lex(args)[1]):
                return '', True
        return None, True
    return argument[1], True


def _mapping_verbs(text, *, reject_class_constraint=False):
    """Finite method constraints only; constants/calls remain unsupported."""
    all_verbs = frozenset({'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE'})
    clean, mask = _lex(text)
    marker = _MAPPING.search(mask)
    if not marker:
        return None
    if marker[1] != 'Request':
        return frozenset({marker[1].upper()})
    cursor = marker.end()
    while cursor < len(mask) and mask[cursor].isspace():
        cursor += 1
    if cursor >= len(mask) or mask[cursor] != '(':
        return all_verbs
    pairs = _pairs(mask)
    closing = pairs.get(cursor)
    if closing is None:
        return None
    argument_mask = mask[cursor + 1:closing]
    constraint = re.search(r'\bmethod\s*=\s*', argument_mask)
    if not constraint:
        return all_verbs
    if reject_class_constraint:
        # Combining class and method conditions is outside this finite model.
        return None
    expression = clean[cursor + 1 + constraint.end():closing]
    if expression.startswith('{'):
        array_end = pairs.get(cursor + 1 + constraint.end())
        if array_end is None:
            return None
        expression = clean[cursor + 2 + constraint.end():array_end]
    else:
        expression = expression.split(',', 1)[0]
    if not expression.strip():
        return all_verbs
    tokens = [part.strip() for part in expression.strip().rstrip(',').split(',')]
    values = []
    for token in tokens:
        value = re.fullmatch(r'(?:org\.springframework\.web\.bind\.annotation\.)?RequestMethod\.(\w+)', token)
        if not value or value[1] not in all_verbs:
            return None
        values.append(value[1])
    return frozenset(values)


def _unowned_mappings(doc):
    contracts = []
    for match in _MAPPING.finditer(doc['mask']):
        class_owned = any(c['header_start'] <= match.start() < c['start'] for c in doc.get('classes', []))
        method_owned = any(m['annotation_start'] <= match.start() < m['start'] for m in doc['methods'])
        if not class_owned and not method_owned:
            contracts.append({'id': 'route-boundary', 'state': 'unknown', 'coverage_error': True,
                              'reason': 'Request mapping has no supported class/method owner',
                              'evidence': [_evidence(doc, match.start(), 'unowned-request-mapping')]})
    return contracts


def _role_guard(expression):
    # An OR branch, custom policy, or authentication alone is not role evidence.
    if not expression or re.search(r'\bor\b|\|\|', expression, re.I):
        return False
    return bool(re.fullmatch(r"\s*(?:isAuthenticated\(\)\s+(?:and|&&)\s+)?has(?:Role|Authority)\(\s*'(?:ROLE_)?ADM'\s*\)\s*", expression))


def _guard_kind(expression, present):
    """Export a fixed category, never arbitrary literal-bearing source text."""
    if not present:
        return 'absent'
    if expression is None:
        return 'unresolved'
    if _role_guard(expression):
        return 'adm-role'
    if expression == 'isAuthenticated()':
        return 'authenticated'
    if expression == 'permitAll()':
        return 'permit-all'
    if re.fullmatch(r"hasMenuAuthority\(\s*#\w+\s*,\s*'[RCUD]'\s*\)", expression):
        return 'menu-authority'
    return 'custom-or-unsupported'


def _detect(documents):
    groups = {}
    for doc in documents:
        groups.setdefault(doc['module'], []).append(doc)
    modules = []
    for path, docs in sorted(groups.items()):
        text = '\n'.join(d['clean'] for d in docs)
        signals = []
        if re.search(r'org\.springframework\.boot|spring-boot-starter', text):
            signals.append('spring-boot-build')
        if re.search(r'\bMenuSecurityExpressionHandler\b|\bhasMenuAuthority\s*\(', text):
            signals.append('menu-security-expression')
        if re.search(r'\bJwtTokenProvider\b', text) and ('Jwts.' in text or 'parseSignedClaims' in text):
            signals.append('jwt-provider')
        if re.search(r'\b(?:WebSecurityConfig|SecurityFilterChain)\b', text) and re.search(r'\.(?:requestMatchers|antMatchers)\s*\(', text):
            signals.append('url-security')
        if re.search(r'\b(?:BoardFileService|ApiResponse|SecurityUser|MenuRoleService)\b', text):
            signals.append('sef-common-types')
        # Require independent build and security signals, not a path/package label.
        detected = ('spring-boot-build' in signals and 'menu-security-expression' in signals
                    and bool({'url-security', 'jwt-provider', 'sef-common-types'} & set(signals)))
        if not detected:
            continue
        boot2 = bool(re.search(r'(?:org\.springframework\.boot[^\n]{0,120}["\']2\.|<version>2\.[^<]*</version>)', text))
        boot3 = bool(re.search(r'(?:org\.springframework\.boot[^\n]{0,120}["\']3\.|<version>3\.[^<]*</version>)', text))
        variant = 'mixed' if boot2 and boot3 else 'public' if boot2 else 'private' if boot3 else 'undetermined'
        modules.append({'path': path, 'variant': variant, 'signals': signals,
                        'evidence': [_evidence(d, fact='framework-signals') for d in docs
                                     if any(s in d['clean'] for s in ('org.springframework.boot', 'MenuSecurityExpressionHandler', 'hasMenuAuthority', 'JwtTokenProvider', 'WebSecurityConfig'))]})
    return modules


def _method_security(docs):
    evidence, active, custom = [], False, False
    eligible = []
    for doc in docs:
        text = doc['clean']
        mask = doc['mask']
        if not _production_source(doc) or '@Configuration' not in mask or re.search(r'@(?:Profile|Conditional\w*)\b', mask):
            continue
        eligible.append(doc)
        enabled = re.search(r'@Enable(?:Global)?MethodSecurity\b(?:\(([^)]*)\))?', mask)
        if enabled and not re.search(r'prePostEnabled\s*=\s*false', enabled[1] or ''):
            # GlobalMethodSecurity differs: prePostEnabled defaults to false.
            if 'EnableGlobalMethodSecurity' not in enabled[0] or re.search(r'prePostEnabled\s*=\s*true', enabled[1] or ''):
                active = True
                evidence.append(_evidence(doc, enabled.start(), 'preauthorize-enabled'))
    handlers = [(doc, method) for doc in eligible for method in doc['methods']
                if re.search(r'@Bean\b', method['annotations'])
                and re.search(r'\bMethodSecurityExpressionHandler\b', method['signature'])
                and re.fullmatch(r'\s*return\s+new\s+MenuSecurityExpressionHandler\s*\([^;{}]*\)\s*;\s*', method['body'])]
    for doc in eligible:
        for method in doc['methods']:
            if not re.search(r'@Bean\b', method['annotations']) or not re.search(r'\bAdvisor\b', method['signature']):
                continue
            parameter = re.search(r'\bMethodSecurityExpressionHandler\s+(\w+)\b', method['parameters'])
            manager = re.fullmatch(r'\s*(?:var|PreAuthorizeAuthorizationManager)\s+(\w+)\s*=\s*new\s+PreAuthorizeAuthorizationManager\s*\(\s*\)\s*;\s*'
                                   r'\1\.setExpressionHandler\s*\(\s*(\w+)\s*\)\s*;\s*'
                                   r'return\s+AuthorizationManagerBeforeMethodInterceptor\.preAuthorize\s*\(\s*\1\s*\)\s*;\s*', method['body'])
            if manager and parameter and manager[2] == parameter[1] and handlers:
                active, custom = True, True
                evidence.append(_evidence(doc, method['start'], 'custom-advisor-and-expression-handler'))
                evidence.extend(_evidence(d, m['start'], 'menu-expression-handler-bean') for d, m in handlers)
    return active, custom, evidence


def _url_rules(docs):
    rules, fallbacks, dynamic = [], [], []
    production = [d for d in docs if _production_source(d)]
    chains = [(doc, method) for doc in production for method in doc['methods']
              if re.search(r'\bSecurityFilterChain\b', method['signature'])]
    for doc in docs:
        text = doc['clean']
        if not re.search(r'\b(?:WebSecurityConfig|SecurityFilterChain)\b', text):
            continue
        if not _production_source(doc):
            # Test/ambiguous source-set configuration is not a production rule.
            if _source_set(doc) not in {'test', 'testFixtures', 'integrationTest'}:
                dynamic.append(_evidence(doc, fact='ambiguous-security-source-set'))
            continue
        doc_chains = [method for chain_doc, method in chains if chain_doc is doc]
        if (len(chains) != 1 or not doc_chains
                or not re.search(r'@Bean\b', _lex(doc_chains[0]['annotations'])[1])
                or doc_chains[0]['class'] is None
                or not re.search(r'@Configuration\b', _lex(doc_chains[0]['class']['header'])[1])
                or re.search(r'\.(?:securityMatcher|securityMatchers|requestMatcher)\s*\(', doc_chains[0]['body_mask'])):
            dynamic.append(_evidence(doc, fact='unregistered-or-scoped-or-multiple-filter-chains'))
        conditional = bool(re.search(r'@(?:Profile|Conditional\w*)\b', doc['mask']))
        if conditional:
            dynamic.append(_evidence(doc, fact='conditional-url-configuration'))
        for match in re.finditer(r'\.(?:requestMatchers|antMatchers)\s*\(', doc['mask']):
            owner = next((m for m in doc['methods'] if m['body_start'] <= match.start() < m['end']), None)
            registered = (len(chains) == 1 and owner is chains[0][1] and doc is chains[0][0]
                          and re.search(r'@Bean\b', _lex(owner['annotations'])[1])
                          and owner['class'] is not None
                          and re.search(r'@Configuration\b', _lex(owner['class']['header'])[1])
                          and not re.search(r'\.(?:securityMatcher|securityMatchers|requestMatcher)\s*\(', owner['body_mask']))
            if not registered:
                dynamic.append(_evidence(doc, match.start(), 'unregistered-or-scoped-or-multiple-filter-chains'))
            opening = match.end() - 1
            closing = doc.get('pairs', {}).get(opening)
            if closing is None:
                continue
            args = text[opening + 1:closing]
            consequence = re.match(r'\s*\.\s*(authenticated|permitAll|denyAll|hasRole|hasAuthority)\s*\(([^)]*)\)', text[closing + 1:])
            if not consequence:
                continue
            # HTTP method constraints cannot be applied to every controller verb.
            if not re.fullmatch(r'\s*"[^"\n]*"(?:\s*,\s*"[^"\n]*")*\s*', args):
                dynamic.append(_evidence(doc, match.start(), 'unresolved-or-method-specific-url-matcher'))
                continue
            for value in re.findall(r'"([^"]*)"', args):
                rules.append({'pattern': value, 'effect': consequence[1], 'argument': consequence[2],
                              'conditional': conditional, 'registered': bool(registered),
                              'evidence': _evidence(doc, match.start(), 'url-matcher')})
        fallback = re.search(r'\.anyRequest\s*\(\s*\)\s*\.permitAll\s*\(', doc['mask'])
        if fallback:
            fallbacks.append(_evidence(doc, fallback.start(), 'permit-all-fallback'))
    return rules, fallbacks, dynamic


def _matches(pattern, route):
    if pattern.endswith('/**'):
        return route == pattern[:-3] or route.startswith(pattern[:-2])
    if '*' in pattern or '?' in pattern or '{' in pattern:
        return False
    return route == pattern


def _candidate(rule, doc, offset, symbol, facts, evidence, prerequisites, counterevidence, guidance, severity='High', site=None):
    owners = [m for m in doc['methods'] if m['start'] <= offset < m['end']]
    method = min(owners, key=lambda m: m['end'] - m['start']) if owners else None
    identity = {'contract': rule, 'path': doc['path'], 'symbol': symbol,
                'owner': method['owner'] if method else '<unknown>',
                'signature': re.sub(r'\s+', '', method['signature']) if method else '<unknown>',
                'site': site}
    finding = make_finding(category={'SEF-ADM-01': 'access-control', 'SEF-JWT-01': 'authentication',
                                    'SEF-OBJ-01': 'access-control', 'SEF-ROUTE-01': 'access-control',
                                    'SEF-FILE-01': 'path-traversal'}[rule], rule=rule,
                           path=doc['path'], line=_evidence(doc, offset)['line'],
                           symbol=symbol, module=doc['module'], identity=identity,
                           severity=severity, title=rule + ' source contract requires review',
                           description='Bounded source observations indicate a possible missing boundary; runtime impact is unverified.',
                           check_id='framework', review_required=True, facts=facts,
                           prerequisites=prerequisites, counterevidence=counterevidence,
                           remediation={'guidance': guidance})
    finding['evidence_refs'] = evidence
    finding['observations'] = facts
    return finding


def _controller_contracts(doc, active, activation, url_rules, fallbacks, dynamic):
    contracts, findings = [], []
    text = doc['clean']
    declaration = re.search(r'\bclass\s+(\w+)', doc['mask'])
    if not declaration and re.search(r'@(?:RestController|Controller)\b', doc['mask']):
        return [{'id': 'route-boundary', 'state': 'unknown', 'coverage_error': True,
                 'reason': 'Unsupported controller declaration', 'evidence': [_evidence(doc)]}], []
    if not any(re.search(r'@(?:RestController|Controller)\b', _lex(owner['header'])[1]) for owner in doc.get('classes', [])):
        return contracts, findings
    for method in doc['methods']:
        owner = method['class']
        if owner is None or not re.search(r'@(?:RestController|Controller)\b', _lex(owner['header'])[1]):
            continue
        base, mapped = _mapping(owner['header'])
        if not mapped:
            base = ''
        class_guard_present, class_guard = _annotation(owner['header'], 'PreAuthorize')
        suffix, present = _mapping(method['annotations'])
        if not present:
            continue
        symbol = owner['owner'] + '.' + method['name']
        entry = _evidence(doc, method['start'], 'controller-entrypoint')
        if base is None or suffix is None:
            contracts.append({'id': 'route-boundary', 'state': 'unknown', 'symbol': symbol,
                              'coverage_error': True,
                              'reason': 'Unsupported or dynamic request mapping', 'evidence': [entry]})
            continue
        verbs = _mapping_verbs(method['annotations'])
        if verbs is None or (mapped and _mapping_verbs(owner['header'], reject_class_constraint=True) is None):
            contracts.append({'id': 'route-boundary', 'state': 'unknown', 'symbol': symbol,
                              'coverage_error': True, 'reason': 'Unsupported request method constraint',
                              'evidence': [entry]})
            continue
        route = '/' + '/'.join(p.strip('/') for p in (base, suffix) if p.strip('/'))
        guard_present, method_guard = _annotation(method['annotations'], 'PreAuthorize')
        # Method-level PreAuthorize overrides its class-level counterpart.
        predicate = method_guard if guard_present else class_guard
        predicate_present = guard_present or class_guard_present
        guard_kind = _guard_kind(predicate, predicate_present)
        explicit_guard = active and _role_guard(predicate)
        matching = next((r for r in url_rules if _matches(r['pattern'], route)), None)
        url_guard = matching and not dynamic and not matching['conditional'] and matching['effect'] in {'hasRole', 'hasAuthority'} and re.fullmatch(r'\s*"(?:ROLE_)?ADM"\s*', matching['argument'])
        admin = route == '/adm' or route.startswith('/adm/') or 'AdminController' in owner['name']
        if admin:
            evidence = [entry] + activation + ([matching['evidence']] if matching else [])
            state = 'guard-observed' if explicit_guard or url_guard else 'unknown' if predicate_present or dynamic else 'guard-not-observed'
            contracts.append({'id': 'admin-boundary', 'state': state, 'symbol': symbol,
                              'route': route, 'guard_kind': guard_kind, 'predicate_present': predicate_present, 'evidence': evidence,
                              'limitations': ['Service-side authorization and proxy applicability require review.']})
            # Emit for routed mutations only; a route/class name is not itself a vulnerability.
            mutation = bool(verbs & {'POST', 'PUT', 'PATCH', 'DELETE'})
            if mutation and not explicit_guard and not url_guard:
                facts = ['Administrator-shaped mutation entrypoint observed at ' + route,
                         'No recognized active ADM role guard at this controller entrypoint.']
                if matching:
                    facts.append('First modeled literal URL matcher effect: ' + matching['effect'])
                findings.append(_candidate('SEF-ADM-01', doc, method['start'], symbol, facts, evidence + dynamic,
                    ['A deployed administrative mutation route and an authenticated non-administrator account.',
                     'No effective service-side, proxy, dynamic URL, or custom-policy denial of this same request.'],
                    ['Authentication may already be enforced; this is not an anonymous access claim.',
                     'Unmodeled service guards, custom annotations and dynamic rules may enforce authorization.',
                     'Observed guard kind: ' + guard_kind],
                    'Enforce the intended administrator permission on the same mutation and independently review the full service path.'))
        recognized_predicate = active and (_role_guard(predicate) or predicate == 'isAuthenticated()'
                                            or bool(re.fullmatch(r"hasMenuAuthority\(\s*#\w+\s*,\s*'[RCUD]'\s*\)", predicate or '')))
        if dynamic:
            contracts.append({'id': 'url-scope-entrypoint', 'state': 'unknown', 'symbol': symbol,
                              'route': route, 'evidence': [entry]})
        if not matching and fallbacks and not recognized_predicate and not dynamic:
            contracts.append({'id': 'route-boundary', 'state': 'unknown' if dynamic else 'unmatched',
                              'symbol': symbol, 'route': route, 'evidence': [entry] + fallbacks + dynamic})
            findings.append(_candidate('SEF-ROUTE-01', doc, method['start'], symbol,
                ['Mapped controller route is outside modeled literal URL matchers: ' + route,
                 'A permitAll fallback is present; no supported active entrypoint authorization predicate was recognized.'],
                [entry] + fallbacks + dynamic,
                ['The route exposes business data or operations and is deployed.',
                 'Unresolved dynamic or HTTP-method matchers and custom authorization do not protect this route.'],
                ['Public endpoints, static resources and SPA routes can be intentionally public.',
                 'Only literal matchers were compared; dynamic configuration and custom guards remain unknown.'],
                'Classify the route intentionally and apply the appropriate URL and method authorization.', severity='Medium'))
        menu = re.search(r'hasMenuAuthority\s*\(\s*#(\w+)\s*,', predicate or '')
        if menu:
            menu_id = menu[1]
            calls = list(re.finditer(r'\b(\w+)\.(\w*(?:download|Download|File|Comment|Detail)\w*)\s*\(([^;{}]*)\)\s*;', method['body']))
            for call in calls:
                if call[1] in {'response', 'ResponseEntity', 'log'} or not re.search(r'\b(?:bbs\w*|board\w*|file\w*|\w*Sq|\w*Id)\b', call[3], re.I):
                    continue
                forwarded = bool(re.search(r'\b' + re.escape(menu_id) + r'\b', call[3]))
                contracts.append({'id': 'menu-object-association', 'state': 'unknown' if forwarded else 'menu-not-forwarded',
                                  'symbol': symbol, 'evidence': [entry],
                                  'reason': 'Menu forwarded; downstream object association is unproven.' if forwarded else 'Menu predicate identifier absent from direct object call arguments.'})
                findings.append(_candidate('SEF-OBJ-01', doc, method['start'], symbol,
                    ['Menu permission predicate references ' + menu_id,
                     ('The menu identifier is forwarded, but its downstream object association is unresolved.' if forwarded else
                      'Direct object service call ' + call[1] + '.' + call[2] + ' does not forward that menu identifier.')],
                    [entry, _evidence(doc, method['body_start'] + call.start(), 'object-service-call')] + activation,
                    ['An authenticated caller has access to one menu and references a real object associated with another menu.',
                     'The callee does not independently bind that same authorized menu to the object.'],
                    ['File-to-board checks may exist without board-to-menu association.',
                     'The service, repository, policy data or thread-bound context may independently enforce the association.',
                     'Method security activation observed: ' + str(active),
                     'Menu argument forwarding observed: ' + str(forwarded)],
                    'Bind the authorized menu to the same board and file/comment in the service and repository query.'))
                break
    return contracts, findings


def _jwt_contracts(doc):
    contracts, findings = [], []
    relevant = [owner for owner in doc.get('classes', []) if owner['name'] == 'JwtTokenProvider'
                or any(m['owner'] == owner['owner'] and 'Jwts.builder' in m['body'] for m in doc['methods'])]
    if not relevant:
        return _jwt_class_contracts(doc)
    for owner in relevant:
        scoped = {**doc, 'methods': [m for m in doc['methods'] if m['owner'] == owner['owner']],
                  'mask': doc['mask'][owner['start']:owner['end'] + 1]}
        observations, items = _jwt_class_contracts(scoped)
        contracts.extend(observations)
        findings.extend(items)
    return contracts, findings


def _jwt_class_contracts(doc):
    methods = doc['methods']
    issuers = [m for m in methods if 'Jwts.builder' in m['body']]
    refresh = [m for m in issuers if 'refresh' in m['name'].lower()]
    access = [m for m in issuers if 'refresh' not in m['name'].lower() and re.search(r'(?:create|generate|issue).*Token', m['name'], re.I)]
    consumers = [m for m in methods if m['name'].startswith(('getAuthentication', 'validateToken'))]
    if not refresh or not access or not consumers:
        if re.search(r'\bclass\s+JwtTokenProvider\b|\bJwts\.builder\s*\(', doc['mask']):
            return [{'id': 'jwt-purpose', 'state': 'unknown', 'coverage_error': True,
                     'reason': 'Unsupported issuer/consumer structure; no purpose safety conclusion.',
                     'evidence': [_evidence(doc)]}], []
        return [], []
    keys = lambda methods: {m[1].strip() for method in methods for m in re.finditer(r'\.signWith\s*\(\s*([\w.]+)\s*[,)]', method['body'])}
    shared = keys(refresh) & keys(access)
    # Only a concrete parser requirement on the selected consumer is recognized.
    authentication = [m for m in consumers if m['name'].startswith('getAuthentication')]
    selected_consumers = authentication or consumers
    purpose = []
    for method in selected_consumers:
        # Multi-parameter consumers are deliberately unsupported: checking the
        # first String does not establish which value creates authentication.
        token = re.fullmatch(r'\s*(?:final\s+)?String\s+(\w+)\s*', method['parameters'])
        parser = re.match(r'\s*(?:(?:var|Claims)\s+\w+\s*=\s*)?Jwts\.parser\s*\(\s*\)([^;{}]*)\s*;', method['body'])
        if (parser and token
                and re.search(r'\.require\s*\(\s*"(?:token_use|tokenType|purpose|type)"\s*,\s*"access"\s*\)', parser[1])
                and re.search(r'\.parse(?:SignedClaims|ClaimsJws)\s*\(\s*' + re.escape(token[1]) + r'\s*\)', parser[1])):
            if method in authentication:
                # The supported same-token consumer is deliberately narrow.
                # A check followed by logging/use of an unrelated field cannot
                # prove which token constructed the authentication object.
                same_consumer = re.fullmatch(
                    r'\s*return\s+new\s+UsernamePasswordAuthenticationToken\s*\(\s*'
                    r'(?:\w+\.)?loadUserByUsername\s*\(\s*(?:\w+\.)?getUsername\s*\(\s*'
                    + re.escape(token[1]) + r'\s*\)\s*\)\s*,\s*null\s*\)\s*;\s*',
                    method['body'][parser.end():])
                if not same_consumer:
                    continue
            purpose.append(method)
    evidence = [_evidence(doc, m['start'], 'jwt-issuer-or-consumer') for m in access + refresh + consumers]
    purpose_guarded = len(purpose) == len(selected_consumers)
    contract = {'id': 'jwt-purpose', 'state': 'guard-observed' if purpose_guarded else 'purpose-not-observed' if shared else 'unknown',
                'evidence': evidence, 'limitations': ['Bearer/filter call path, claim semantics and configuration require independent review.']}
    if purpose_guarded:
        return [contract], []
    findings = [_candidate('SEF-JWT-01', doc, consumers[0]['start'], consumers[0]['name'],
        [('Access-shaped and refresh-shaped JWT issuers use the same signing-key expression.' if shared else
          'Access-shaped and refresh-shaped JWT issuers are present; signing-key material separation is unresolved.'),
         'Authentication/validation consumer methods lack a recognized access-purpose parser requirement.'], evidence,
        ['A valid, unexpired and unrevoked refresh JWT and an authenticatable subject.',
         'A deployed Bearer authentication path invokes these consumers without an external purpose guard.'],
        ['Signature, expiry and revocation validation can still reject invalid tokens.',
         'Refresh endpoint database comparisons do not establish a guard on the Bearer path.',
         'Custom claim checks, separate filters, keys resolved dynamically and issuer/consumer links remain unmodeled.'],
        'Enforce an explicit access-token purpose on the Bearer consumer, retain a separate refresh contract, and test both token types.')]
    return [contract], findings


def _file_contracts(doc):
    contracts, findings = [], []
    for method in doc['methods']:
        body = method['body']
        strings = set(re.findall(r'\bString\s+(\w+)\s*=\s*[^;]*\.getCanonicalPath\s*\(', body))
        for match in re.finditer(r'\b(\w+)\.startsWith\s*\(\s*(\w+)\s*\)', body):
            if match[1] not in strings or match[2] not in strings:
                continue
            offset = method['body_start'] + match.start()
            evidence = [_evidence(doc, offset, 'canonical-string-prefix-check')]
            contracts.append({'id': 'file-confinement', 'state': 'conditional-prefix-weakness', 'evidence': evidence})
            findings.append(_candidate('SEF-FILE-01', doc, offset, method['name'],
                ['Canonical path strings are compared with String.startsWith; sibling names can share a prefix.'], evidence,
                ['Path control through stored paths, migration, new callers or filesystem manipulation.',
                 'A sibling directory shares the configured root string prefix and no independent confinement rejects it.'],
                ['Server-generated directories and sanitized UUID filenames may prevent remote path control.',
                 'No arbitrary path persistence, symlink attack or runtime file disclosure was established.'],
                'Resolve the relevant real paths and enforce directory component containment; review links and path-writing inputs.', severity='Medium',
                site=match[1] + '.startsWith(' + match[2] + ')'))
    return contracts, findings


def run_framework_check(source, config, inventory, profile):
    """Return one required framework check and candidate findings for a snapshot.

    ``config`` cannot provide baseline trust, suppress contracts, or expand reads.
    Resource or malformed-input failures are explicit incomplete coverage.
    """
    check = make_check('framework')
    check['engine'] = {'name': 'gxsec-sef-contracts', 'version': VERSION, 'available': True,
                       'rule_ids': RULE_IDS[:], 'rules_hash': content_hash({'version': VERSION, 'rules': RULE_IDS}),
                       'limitations': LIMITATIONS[:]}
    metadata = {'family': 'unknown', 'variant': 'undetermined', 'modules': [], 'contracts': [],
                'baseline_manifest': [], 'limitations': LIMITATIONS[:]}
    check['framework'] = metadata
    try:
        documents = _load(Path(source), inventory)
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        check['errors'].append({'type': 'framework_input_rejected', 'message': str(exc)})
        return check, []
    selected = [d['path'] for d in documents]
    metadata['baseline_manifest'] = [{'path': d['path'], 'hash': d['hash']} for d in documents]
    check['coverage'].update({'files': selected, 'scanned_files': selected,
                              'eligible': 1 + len(documents), 'scanned': 1 + len(documents),
                              'scope_hash': inventory.get('scope_hash'), 'evaluation_units': ['framework-detection']})
    modules = _detect(documents)
    metadata['modules'] = modules
    metadata['contracts'].append({'id': 'framework-detection', 'state': 'detected' if modules else 'not-detected',
                                  'reason': 'Combined build and source security signatures; no application safety conclusion.'})
    if not modules:
        check['coverage'].update({'eligible': 1, 'scanned': 1})
        check['status'] = 'complete'
        return check, []
    metadata['family'] = 'SEF'
    variants = {m['variant'] for m in modules}
    metadata['variant'] = 'mixed' if len(variants) > 1 or 'mixed' in variants else next(iter(variants))
    findings, method_count = [], 0
    for module in modules:
        docs = [d for d in documents if d['module'] == module['path']]
        for doc in docs:
            doc['methods'], doc['pairs'] = [], {}
            if not doc['path'].endswith('.java'):
                continue
            try:
                doc['pairs'] = _pairs(doc['mask'])
                doc['methods'] = _methods(doc, doc['pairs'])
            except ValueError:
                metadata['contracts'].append({'id': 'source-syntax', 'state': 'unknown',
                                              'reason': 'Unbalanced or unsupported Java source', 'evidence': [_evidence(doc)]})
                check['errors'].append({'type': 'framework_unsupported_syntax', 'path': doc['path']})
            method_count += len(doc['methods'])
            if method_count > MAX_METHODS:
                check['errors'].append({'type': 'framework_resource_limit', 'message': 'Method budget exhausted'})
                check['coverage']['scanned'] = 1
                return check, []
        active, custom, activation = _method_security(docs)
        metadata['contracts'].append({'id': 'method-security', 'state': 'observed' if active else 'unknown',
                                      'module': module['path'], 'custom_advisor': custom, 'evidence': activation,
                                      'limitations': ['Registration observed; runtime bean selection and proxy applicability are unverified.']})
        url_rules, fallbacks, dynamic = _url_rules(docs)
        affected_entries = []
        for doc in docs:
            if _source_set(doc) in {'test', 'testFixtures', 'integrationTest'}:
                continue
            metadata['contracts'].extend(_unowned_mappings(doc))
            for contracts, items in (_controller_contracts(doc, active, activation, url_rules, fallbacks, dynamic),
                                     _jwt_contracts(doc), _file_contracts(doc)):
                affected_entries.extend(c for c in contracts if c['id'] == 'url-scope-entrypoint')
                metadata['contracts'].extend(c for c in contracts if c['id'] != 'url-scope-entrypoint')
                findings.extend(items)
        if dynamic:
            dynamic = list({content_hash(e): e for e in dynamic}.values())
            entry_evidence = [e for c in affected_entries for e in c['evidence']]
            metadata['contracts'].append({'id': 'url-scope', 'state': 'unknown', 'module': module['path'],
                                          'review_required': True, 'evidence': dynamic,
                                          'affected_entrypoints': affected_entries})
            location = next(d for d in docs if d['path'] == dynamic[0]['path'])
            findings.append(_candidate('SEF-ROUTE-01', location, 0, module['path'] + '.url-scope',
                ['Effective URL matcher scope is unresolved for this module.',
                 'Dynamic matchers, uncertain registration or filter-chain scope prevent proving route coverage.'],
                dynamic + entry_evidence,
                ['The affected entrypoints are deployed business routes.',
                 'Independent review resolves active chains, matcher order and actual configuration values.'],
                ['Existing dynamic rules may protect every affected endpoint.',
                 'This is one coverage review question, not evidence of per-endpoint bypass.',
                 'Method, service and custom policy guards may independently protect requests.'],
                'Review effective production filter chains and resolve matcher scope for the listed entrypoints.', severity='Medium'))
    # Static order and semantic identities are independent of inventory order.
    findings.sort(key=lambda f: (RULE_IDS.index(f['rule_id']), f['locations'][0]['path'], f['locations'][0]['line'], f['finding_id']))
    check['findings'] = [f['finding_id'] for f in findings]
    for contract in metadata['contracts']:
        if contract.get('coverage_error'):
            check['errors'].append({'type': 'framework_unsupported_contract', 'contract': contract['id'],
                                    'symbol': contract.get('symbol', '')})
    check['status'] = 'incomplete' if check['errors'] else 'complete'
    if check['errors']:
        check['coverage']['scanned'] = max(1, check['coverage']['scanned'] - len(check['errors']))
    return check, findings
