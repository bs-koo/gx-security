"""Read-only checks for common CI configuration risks in a verified checkout."""
import hashlib
from pathlib import PurePosixPath
import re

import yaml

from .execution import checkpoint
from .models import content_hash, make_check, make_finding
from .settings_data import SettingsLoader

CHECK_ID = 'pipeline'
MAX_CONFIG_BYTES = 512 * 1024
MAX_FILES = 128
LIMITATIONS = [
    'Checks checked-in GitHub Actions YAML, declarative Jenkinsfiles and named Jenkins CasC files only.',
    'Does not evaluate groovy, shell, third-party workflows, shared libraries or effective server privileges.',
]
RULES = {
    'gha-unpinned-dependency': ('Medium', 'Pin remote actions and workflows to an approved commit or container digest.'),
    'gha-write-all': ('High', 'Grant GitHub token write permissions only to the jobs and scopes that need them.'),
    'gha-untrusted-checkout': ('High', 'Keep untrusted PR code out of jobs running with a privileged event context.'),
    'gha-untrusted-run-expression': ('High', 'Pass untrusted event text through scoped environment variables and quote its use.'),
    'gha-remote-inherited-credentials': ('Medium', 'Pass individual required secrets to approved remote reusable workflows.'),
    'jenkins-global-credentials': ('Medium', 'Bind credentials at the narrowest stage or step that needs them.'),
    'jenkins-unsecured-authorization': ('High', 'Require authentication and explicitly authorize Jenkins users.'),
}
PRIVILEGED_EVENTS = {'pull_request_target', 'workflow_run'}
UNTRUSTED_REF = re.compile(
    r'(?:github\.(?:head_ref\b|event\.(?:pull_request\.head\.|workflow_run\.head_))|\brefs/pull/)', re.I)
UNTRUSTED_RUN = re.compile(
    r'\$\{\{[^}]*\bgithub\.(?:head_ref\b|event\.(?:'
    r'pull_request\.(?:title|body|head\.ref)\b|issue\.(?:title|body)\b|comment\.body\b|'
    r'review\.body\b|discussion\.(?:title|body)\b|head_commit\.message\b))', re.I)
GROOVY_TOKEN = re.compile(r"""//[^\n]*|/\*[\s\S]*?\*/|'''[\s\S]*?'''|""" +
    r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _kind(path):
    name = PurePosixPath(path)
    if len(name.parts) == 3 and name.parts[:2] == ('.github', 'workflows') and name.suffix in {'.yml', '.yaml'}:
        return 'github'
    if name.name == 'Jenkinsfile' or name.name.startswith('Jenkinsfile.'):
        return 'jenkins'
    if name.name in {'jenkins.yaml', 'jenkins.yml', 'jenkins-casc.yaml', 'jenkins-casc.yml'}:
        return 'jenkins-casc'
    return None


def _mapping(value):
    if not isinstance(value, dict):
        raise ValueError('Expected a configuration mapping')
    return value


def _pinned(value):
    if value.startswith('./'):
        return True
    if value.startswith('docker://'):
        return re.fullmatch(r'.+@sha256:[a-f0-9]{64}', value) is not None
    return re.fullmatch(r'.+@[a-f0-9]{40}', value) is not None


def _github(workflow):
    on = workflow.get('on')
    if isinstance(on, str):
        events = {on}
    elif isinstance(on, (dict, list)) and all(isinstance(event, str) for event in on):
        events = set(on)
    else:
        raise ValueError('Unsupported workflow event declaration')
    jobs = _mapping(workflow.get('jobs'))
    if not jobs:
        raise ValueError('Workflow jobs are missing')
    if workflow.get('permissions') == 'write-all':
        yield 'gha-write-all'
    for job in jobs.values():
        checkpoint()
        job = _mapping(job)
        if job.get('permissions') == 'write-all':
            yield 'gha-write-all'
        reusable = job.get('uses')
        if reusable is not None:
            if not isinstance(reusable, str):
                raise ValueError('Unsupported reusable workflow reference')
            if not _pinned(reusable):
                yield 'gha-unpinned-dependency'
            if not reusable.startswith('./') and job.get('secrets') == 'inherit':
                yield 'gha-remote-inherited-credentials'
        steps = job.get('steps', [])
        if not isinstance(steps, list) or (not steps and reusable is None):
            raise ValueError('Unsupported workflow steps')
        for step in steps:
            step = _mapping(step)
            action = step.get('uses', '')
            command = step.get('run', '')
            if not isinstance(action, str) or not isinstance(command, str):
                raise ValueError('Unsupported workflow step')
            if action and not _pinned(action):
                yield 'gha-unpinned-dependency'
            if events & PRIVILEGED_EVENTS and action.startswith('actions/checkout@'):
                inputs = _mapping(step.get('with', {}))
                if any(UNTRUSTED_REF.search(str(inputs.get(key, ''))) for key in ('ref', 'repository')):
                    yield 'gha-untrusted-checkout'
            if UNTRUSTED_RUN.search(command):
                yield 'gha-untrusted-run-expression'


def _jenkins(text):
    # Strip comments and strings while preserving newlines and brace offsets.
    code = GROOVY_TOKEN.sub(lambda m: re.sub(r'[^\n]', ' ', m[0]), text)
    pipeline = re.match(r'\s*(?:#![^\n]*\n\s*)?pipeline\s*\{', code)
    if not pipeline:
        raise ValueError('Only declarative Jenkins pipelines are supported')
    environment_blocks = {match.end() - 1 for match in re.finditer(r'\benvironment\s*\{', code)}
    stack = []
    for token in re.finditer(r'[{}]', code):
        checkpoint()
        if token[0] == '{':
            stack.append(token.start())
        elif not stack:
            raise ValueError('Unbalanced Jenkins configuration')
        else:
            start = stack.pop()
            if (len(stack) == 1 and start in environment_blocks
                    and re.search(r'\bcredentials\s*\(', code[start:token.start()])):
                yield 'jenkins-global-credentials'
    if stack:
        raise ValueError('Unbalanced Jenkins configuration')


def _find_rules(kind, text):
    if kind == 'jenkins':
        yield from _jenkins(text)
        return
    data = _mapping(yaml.load(text, Loader=SettingsLoader))
    if kind == 'github':
        yield from _github(data)
    else:
        jenkins = _mapping(data.get('jenkins'))
        strategy = jenkins.get('authorizationStrategy', {})
        if strategy == 'unsecured' or 'unsecured' in _mapping(strategy):
            yield 'jenkins-unsecured-authorization'


def run_pipeline_check(source, inventory):
    selected = [(row, kind) for row in inventory.get('inventory', [])
                if (kind := _kind(row['path']))]
    if not selected:
        return None, []
    check = make_check(CHECK_ID, engine={'name': 'gxsec-ci-configuration',
        'version': 1, 'rules_hash': content_hash(RULES), 'rule_ids': sorted(RULES), 'limitations': LIMITATIONS})
    check['coverage'].update(eligible=len(selected), files=[row['path'] for row, _ in selected])
    if len(selected) > MAX_FILES:
        check['errors'].append({'type': 'pipeline_input_limit'})
        return check, []
    findings = []
    for row, kind in selected:
        checkpoint()
        name = row['path']
        try:
            with (source / name).open('rb') as handle:
                data = handle.read(MAX_CONFIG_BYTES + 1)
            if len(data) > MAX_CONFIG_BYTES or hashlib.sha256(data).hexdigest() != row['hash']:
                raise ValueError('Input exceeded limit or changed')
            rules = sorted(set(_find_rules(kind, data.decode('utf-8-sig'))))
        except (OSError, ValueError, yaml.YAMLError):
            check['errors'].append({'type': 'pipeline_input_unverified', 'path': name})
            continue
        check['coverage']['scanned'] += 1
        for rule in rules:
            severity, guidance = RULES[rule]
            findings.append(make_finding(category='pipeline-configuration', rule=rule, path=name,
                title=guidance, severity=severity, check_id=CHECK_ID, review_required=True,
                remediation={'guidance': guidance}, file_hash=row['hash']))
    if not check['errors']:
        check['status'] = 'complete'
    check['findings'] = [item['finding_id'] for item in findings]
    return check, findings
