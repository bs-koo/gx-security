"""Host-neutral commands for preparation, checks, release evidence and retests."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

import yaml

from . import __version__, adapters, config as configuration, policy
from .redaction import redact
from .models import validate_run
from .reporting import write_reports
from .source import collect_source, runtime_environment, trusted_runtime_tool, reject_reparse_path, selected_paths
from .state import Store
from .handoff import execution_context
from . import execution


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _emit(data):
    print(json.dumps(redact(data), ensure_ascii=False, indent=2))


def _read(path):
    value = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("configuration must be an object")
    return value


def _config(args, source):
    path = Path(args.config).resolve() if getattr(args, "config", None) else source / "gxsec.yaml"
    if getattr(args, 'config', None) and not path.is_file():
        raise ValueError('Explicit config file does not exist')
    data = configuration.load_config(path) if path.exists() else configuration.default_config(source)
    if "_trusted_policy" in data or "_credentials" in data:
        raise ValueError("project config cannot supply trusted policy or credentials")
    data.setdefault("project", {})["source"] = str(source)
    if getattr(args, 'expected_framework', None):
        data['framework'] = configuration.framework_requirement({'expected_family': args.expected_framework})
    return data


def _trusted_policy(args, source):
    if not getattr(args, "policy", None):
        return {}
    path = Path(args.policy).resolve(strict=True)
    if path.is_relative_to(source.resolve()):
        raise ValueError("trusted policy must be outside the inspected source tree")
    raw = path.read_bytes()
    data = yaml.safe_load(raw.decode('utf-8-sig'))
    if not isinstance(data, dict):
        raise ValueError('trusted policy must be an object')
    data["_policy_path"] = str(path)
    data["_policy_sha256"] = hashlib.sha256(raw).hexdigest()
    return data


def _review_records(args):
    path = getattr(args, "review_records", None)
    if not path:
        return [], []
    value = _read(path)
    reviews, exceptions = value.get("reviews", []), value.get("exceptions", [])
    if not isinstance(reviews, list) or not isinstance(exceptions, list):
        raise ValueError("review records require reviews and exceptions arrays")
    return reviews, exceptions


def _base_scope(source, base):
    if not base:
        return {"scope": "full", "requested_scope": "diff", "base": None, "changed_files": [], "strategy": "conservative-full-rescan"}
    git = trusted_runtime_tool("git", source)["executable"]
    git_env = runtime_environment()
    prefix = [git, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=", "-C", str(source)]
    resolved = subprocess.run([*prefix, "rev-parse", "--verify", "--end-of-options", base + "^{commit}"],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, env=git_env)
    if resolved.returncode:
        raise ValueError("base revision is not a valid commit")
    commit = resolved.stdout.strip()
    diff = subprocess.run([*prefix, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "--diff-filter=ACMR", commit, "--"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, env=git_env)
    if diff.returncode:
        raise ValueError("cannot determine changed files")
    return {"scope": "full", "requested_scope": "diff", "base": commit, "changed_files": diff.stdout.splitlines(),
            "strategy": "conservative-full-rescan"}


def _doctor(args):
    source = Path(args.source or ".").resolve()
    config = _config(args, source)
    tools = []
    for tool_id, default in (("semgrep", "semgrep"), ("osv", "osv-scanner"), ("gitleaks", "gitleaks")):
        tool = config.get("tools", {}).get(tool_id, {})
        command = tool.get("command", default)
        info = {"id": tool_id, "command": command, "available": False, "version": None}
        checked = adapters.probe_engine(tool_id, tool, source)
        info["available"] = checked.get("status") == "complete"
        info["version"] = checked.get("engine", {}).get("version")
        info["provenance"] = checked.get("engine", {}).get("provenance", {})
        info["errors"] = checked.get("errors", [])
        tools.append(info)
    for helper in ("git", "python"):
        try:
            proof = trusted_runtime_tool(helper, source)
            tools.append({"id": helper, "available": True, "version": proof.get("version"), "provenance": proof})
        except (OSError, ValueError):
            tools.append({"id": helper, "available": False, "errors": ["Digest-verified runtime helper is unavailable"]})
    framework = {"status": "incomplete", "assessment": "detection-only"}
    try:
        from .framework import run_framework_check
        from .snapshot import verified_snapshot
        from .preflight import collect_framework_signatures
        inventory = collect_framework_signatures(source)
        framework['selection'] = inventory['selection']
        framework['limitation'] = 'Preparation checks named control files only; renamed controls and full security coverage require check/release.'
        with verified_snapshot(source, inventory) as snapshot:
            checked, _ = run_framework_check(snapshot.path, config, inventory, 'check')
            framework.update(checked.get('framework', {}))
            framework['status'] = checked['status'] if snapshot.verify() and not inventory.get('errors') else 'incomplete'
            framework['coverage'] = {**checked.get('coverage', {}), 'scope': 'partial'}
    except (OSError, ValueError, RuntimeError):
        framework['reason'] = 'Source framework detection could not complete.'
    complete = all(t["available"] for t in tools) and framework['status'] == 'complete'
    result = {"schema_version": 1, "status": "PASS" if complete else "INCOMPLETE", "python": sys.version.split()[0],
              "tools": tools, "framework": framework, "data_mode": config.get("data_mode", "local-only"),
              "next": "Doctor verifies preparation and framework detection, not application security. Missing engines require the fixed runtime bundle."}
    if args.json:
        _emit(result)
    else:
        print("실행 환경: " + result["status"])
        print("  SEF 기반: " + str(framework.get('variant', 'undetermined')) + " · 준비 확인이며 보안 판정이 아닙니다.")
        for tool in tools:
            print(f"  {tool['id']}: {'사용 가능' if tool['available'] else '준비 필요'} · {tool.get('version') or tool.get('error')}")
    return 0 if complete else 2


def _init(args):
    source = Path(args.source or ".").resolve(strict=True)
    if not source.is_dir():
        raise ValueError("source must be a directory")
    destination = Path(args.output).resolve() if args.output else source / "gxsec.yaml"
    if destination.exists() and not args.force:
        raise ValueError("profile already exists; use --force only to intentionally replace it")
    ignored = source / ".gitignore"
    if ignored.is_symlink() or (hasattr(ignored, "is_junction") and ignored.is_junction()):
        raise ValueError("generated output exclusions must not follow a symbolic link")
    destination.parent.mkdir(parents=True, exist_ok=True)
    profile = configuration.default_config(source)
    profile["project"]["source"] = "."
    from .reporting import _atomic_write
    _atomic_write(destination, yaml.safe_dump(profile, allow_unicode=True, sort_keys=False))
    contents = ignored.read_bytes() if ignored.exists() else b""
    additions = [name for name in (b".gxsec/", b".gxsec-container/") if name not in contents.splitlines()]
    if additions:
        with ignored.open("ab") as handle:
            handle.write(b"\n# gx-security local generated outputs\n" + b"\n".join(additions) + b"\n")
    print(f"점검 프로파일: {destination}")
    print("비밀값은 저장하지 않습니다. 정적 중심 점검은 release --profile static-release로 실행합니다.")
    return 0


def _execute(args, retest_id=None):
    selected = getattr(args, 'exclude_source_path', None)
    duration = getattr(args, 'max_duration_seconds', None)
    input_bytes = getattr(args, 'max_input_bytes', None)
    previous = None
    if retest_id:
        current_source = reject_reparse_path(args.source or '.').resolve(strict=True)
        state = reject_reparse_path(args.state_dir if args.state_dir else current_source / '.gxsec')
        if not (state / 'state.sqlite3').is_file() or not (state / 'runs').is_dir():
            raise ValueError('Retest requires the original saved state')
        store = Store(state)
        previous = store.get_run(args.run_id) if getattr(args, 'run_id', None) else store.latest_run()
        validate_run(previous)
        saved_source = previous.get('source')
        if (not isinstance(saved_source, dict) or not isinstance(saved_source.get('path'), str)
                or not saved_source['path'] or len(saved_source['path']) > 4096
                or any(ord(char) < 32 for char in saved_source['path'])
                or not Path(saved_source['path']).is_absolute()
                or os.path.normcase(os.path.abspath(saved_source['path'])) != os.path.normcase(str(current_source))):
            raise ValueError('Saved retest source does not match the selected source')
        if selected is None:
            contract = saved_source.get('exclusion_contract', {})
            if not isinstance(contract, dict):
                raise ValueError('Saved source exclusion contract is invalid')
            selected = contract.get('selected_directory_paths', [])
            if not isinstance(selected, list):
                raise ValueError('Saved source exclusions must be a list')
    if previous and (duration is None or input_bytes is None):
        metrics = previous.get('execution_metrics', {})
        if not isinstance(metrics, dict):
            raise ValueError('Saved execution limits must be an object')
        if duration is None:
            duration = metrics.get('max_duration_seconds', 1200)
        if input_bytes is None:
            input_bytes = metrics.get('max_input_bytes', 4 * 1024**3)
    duration = 1200 if duration is None and previous is None else duration
    input_bytes = 4 * 1024**3 if input_bytes is None and previous is None else input_bytes
    if (type(duration) not in (int, float) or not math.isfinite(duration) or not 0 < duration <= 86400
            or type(input_bytes) is not int or not 1 <= input_bytes <= 1024**4):
        raise ValueError('Invalid execution limit: duration must be at most 86400 seconds and working-tree input at most 1 TiB')
    with execution.session(duration, max_input_bytes=input_bytes) as budget:
        with selected_paths(selected or []):
            return _execute_run(args, retest_id, budget, previous_run=previous)


def _execute_run(args, retest_id, budget, *, previous_run=None):
    source = Path(args.source or ".").resolve(strict=True)
    if not source.is_dir():
        raise ValueError("source must be a directory")
    execution_id = getattr(args, "execution_id", None) or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:10]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", execution_id) or execution_id in {".", ".."}:
        raise ValueError("Invalid execution identity")
    trusted = _trusted_policy(args, source)
    cfg = _config(args, source)
    cfg["_trusted_policy"] = trusted
    if getattr(args, "creds_stdin", False):
        raw = sys.stdin.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("credentials input exceeds limit")
        cfg["_credentials"] = json.loads(raw)
        if not isinstance(cfg["_credentials"], dict):
            raise ValueError("credentials must be an identity object")
    reviews, exceptions = _review_records(args)
    state_dir = Path(args.state_dir).resolve() if args.state_dir else source / ".gxsec"
    if state_dir.is_symlink() or (hasattr(state_dir, "is_junction") and state_dir.is_junction()):
        raise ValueError("state directory must not be a symbolic link")
    cfg["_state_dir"] = str(state_dir)
    store = Store(state_dir)
    try:
        existing_execution = store.get_run(execution_id)
    except KeyError:
        existing_execution = None
    if existing_execution:
        raise ValueError("Execution identity already exists; choose a new identity")
    previous = previous_run if retest_id else store.latest_run()
    if retest_id and (not previous or not any(f.get("finding_id") == retest_id for f in previous.get("findings", []))):
        raise ValueError("finding not found in latest saved run")
    expectations = [configuration.framework_requirement(owner['framework'])
                    for owner in (cfg, trusted) if 'framework' in owner]
    if retest_id and previous.get('framework_expectation'):
        expectations.append(configuration.framework_requirement(previous['framework_expectation']))
    if expectations:
        cfg['framework'] = {'expected_family': 'SEF', 'required_contracts': sorted({
            item for expectation in expectations for item in expectation['required_contracts']})}
    profile = args.profile or (previous["profile"] if retest_id else "check" if args.command == "check" else "release")
    if args.execute_dynamic and profile != "release":
        raise ValueError("dynamic execution requires the full release profile")
    started_at = _utc()
    try:
        with execution.phase('source-inventory'):
            inventory = collect_source(source)
    except execution.BudgetExceeded as exc:
        inventory = {'path': str(source), 'files': [], 'inventory': [], 'supported_files': [],
                     'modules': [], 'errors': [exc.diagnostic], 'exclusions': [],
                     'inventory_complete': False, 'scope': 'partial', 'hash': None, 'revision': None}
    run = {"schema_version": 1, "run_id": execution_id,
           "project_id": cfg.get("project", {}).get("id", source.name), "profile": profile,
           "started_at": started_at, "source": inventory, "checks": [], "findings": [],
           "reviews": reviews, "exceptions": exceptions,
           "policy_hash": trusted.get("_policy_sha256"),
           "configuration_hash": hashlib.sha256(json.dumps(redact({k: v for k, v in cfg.items() if not k.startswith('_')}), sort_keys=True, default=str).encode()).hexdigest()}
    run['execution_context'] = execution_context(args, source, state_dir)
    if expectations:
        run['framework_expectation'] = deepcopy(cfg['framework'])
    cfg.setdefault("dynamic", {})["run_id"] = execution_id
    if profile == "check":
        try:
            execution.checkpoint()
            run["scan_scope"] = _base_scope(source, getattr(args, "base", None))
        except (OSError, ValueError, subprocess.SubprocessError, execution.BudgetExceeded) as exc:
            run["scan_scope"] = {"scope": "full", "requested_scope": "diff", "strategy": "conservative-full-rescan", "base_unverified": True}
            run["checks"].append({"id": "change-plan", "status": "incomplete", "required": True,
                "errors": [exc.diagnostic] if isinstance(exc, execution.BudgetExceeded) else ["Change base could not be verified"],
                "coverage": {"eligible": 1, "scanned": 0, "scope": "full"}})
    else:
        run["scan_scope"] = {"scope": "full"}
    selected = inventory.get('exclusion_contract', {}).get('selected_directory_paths', [])
    if selected:
        run['scan_scope'].update(scope='selected', excluded_directory_paths=selected,
                                 limitation='Operator-selected directories require separate review')
    if retest_id:
        run["retest_of"] = {"run_id": previous["run_id"], "finding_id": retest_id,
                            "profile": previous["profile"],
                            "strategy": "same-profile-conservative-rescan" if profile == previous["profile"] else "explicit-profile-override"}
    cfg["_inventory"] = run["source"]
    cfg["_scan_scope"] = run["scan_scope"]
    try:
        execution.checkpoint()
        checks, findings = adapters.run_static_checks(source, cfg, profile)
        if selected:
            for check in checks:
                check.setdefault('coverage', {})['scope'] = 'selected'
        run["checks"].extend(checks)
        run["findings"].extend(findings)
        if profile == "release":
            from .dynamic import run_dynamic_checks
            checks, findings = run_dynamic_checks(source, cfg, execute=bool(args.execute_dynamic))
            run["checks"].extend(checks)
            run["findings"].extend(findings)
    except execution.BudgetExceeded as exc:
        run['checks'].append({'id': 'execution', 'status': 'incomplete', 'required': True,
                              'errors': [exc.diagnostic], 'coverage': {'eligible': 1, 'scanned': 0}})
    except KeyboardInterrupt:
        run["checks"].append({"id": "execution", "status": "cancelled", "required": True,
                              "errors": ["user cancelled"], "coverage": {"eligible": 1, "scanned": 0}})
        run["cancelled"] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        run["checks"].append({"id": "execution", "status": "failed", "required": True,
                              "errors": [type(exc).__name__ + ": " + str(exc)], "coverage": {"eligible": 1, "scanned": 0}})
    try:
        with execution.phase('source-recheck'):
            after = collect_source(source)
        integrity_errors = []
        if any(after.get(k) != run['source'].get(k) for k in ('hash', 'revision', 'dirty', 'scope_hash')):
            integrity_errors.append('Source identity changed during scanning')
        if after.get('errors'):
            integrity_errors.append('Source inventory could not be completely verified')
        stable = not integrity_errors
        run["checks"].append({"id": "source-integrity", "status": "complete" if stable else "incomplete", "required": True,
            "errors": integrity_errors,
            "coverage": {"eligible": 1, "scanned": 1 if stable else 0, "scope": "full"},
            "before_hash": run["source"].get("hash"), "after_hash": after.get("hash")})
    except (OSError, ValueError, execution.BudgetExceeded):
        run["checks"].append({"id": "source-integrity", "status": "failed", "required": True,
            "errors": ["Source identity could not be rechecked"], "coverage": {"eligible": 1, "scanned": 0, "scope": "full"}})
    run["finished_at"] = _utc()
    run['execution_metrics'] = budget.summary()
    if profile == "release":
        if selected:
            run['checks'].append({'id': 'release-scope', 'status': 'incomplete', 'required': True,
                'errors': ['Selected application scope does not establish a full release assessment'],
                'coverage': {'eligible': 1, 'scanned': 0, 'scope': 'selected'}})
        default_reviews = {"role-matrix", "sensitive-data", "external-side-effects", "business-logic"}
        required_reviews = default_reviews | set(trusted.get("required_reviews", []))
        supplied = {r.get("id") for r in reviews if r.get("status") in {"complete", "completed"} and r.get("evidence_refs")}
        pending = sorted(required_reviews - supplied)
        run["checks"].append({"id": "manual-review", "status": "incomplete" if pending else "complete", "required": True,
            "errors": ["Required independent review missing: " + review for review in pending],
            "coverage": {"eligible": len(required_reviews), "scanned": len(required_reviews) - len(pending), "scope": "full"}})
        actual_clean = run["source"].get("dirty") is False
        run["checks"].append({"id": "source-checkout", "status": "complete" if actual_clean else "incomplete", "required": True,
            "errors": [] if actual_clean else ["Official release evidence requires an actual clean checkout"],
            "coverage": {"eligible": 1, "scanned": 1 if actual_clean else 0, "scope": "full"}})
    required_ids = set(cfg.get("profiles", {}).get(profile, {}).get("required_checks", [])) | set(trusted.get("required_checks", []))
    present = {c.get("id") for c in run["checks"]}
    for missing in sorted(required_ids - present):
        run["checks"].append({"id": missing, "status": "unsupported", "required": True,
            "errors": ["Required check was not configured or executed"], "coverage": {"eligible": 0, "scanned": 0, "scope": "full"}})
    from .triage import apply_framework_baseline
    apply_framework_baseline(run, trusted)
    if previous:
        run = store.reconcile(run, previous)
    gate_policy = dict(trusted)
    gate_policy.update({"profile": profile, "run_id": run['run_id'], "source_revision": run["source"].get("revision") or run["source"].get("hash"),
                        "scope_hash": run["source"].get("scope_hash"), "require_trusted_evidence": profile == "release"})
    if profile == "release":
        gate_policy["required_reviews"] = sorted(required_reviews)
    if hasattr(policy, "apply_reviews"):
        run["findings"] = policy.apply_reviews(run["findings"], reviews, policy=gate_policy)
    run["gate"] = policy.evaluate(run["checks"], run["findings"], reviews=reviews, exceptions=exceptions, policy=gate_policy)
    if run.get("cancelled"):
        run["gate"] = {**run["gate"], "status": "INCOMPLETE", "exit_code": 130}
    store.save_run(run)
    output = Path(args.output).resolve() if args.output else state_dir / "reports" / run["run_id"]
    write_reports(run, output)
    if args.json:
        _emit(run)
    else:
        print(f"점검 결과: {run['gate']['status']} · {profile}")
        print(f"실행: {run['run_id']} · 발견사항: {len(run['findings'])}")
        print(f"공유 보고서: {output / 'report.html'}")
    return int(run["gate"].get("exit_code", 2))


def _report(args):
    store = Store(Path(args.state_dir).resolve())
    path = Path(args.run_id)
    imported = path.is_file()
    run = _read(path) if imported else store.get_run(args.run_id)
    if not run:
        raise ValueError("run not found")
    validate_run(run)
    if imported:
        run["unverified_declared_gate"] = deepcopy(run.get("gate", {}))
        run["gate"] = {"status": "INCOMPLETE", "exit_code": 2, "blockers": [],
            "incomplete": ["Imported artifact has no independently verified execution provenance"], "evidence_level": "unverified-import"}
        run["import_provenance"] = {"verified": False, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    output = Path(args.output).resolve() if args.output else Path(args.state_dir).resolve() / "reports" / run["run_id"]
    write_reports(run, output)
    print(f"공유 보고서: {output / 'report.html'}")
    return 0


def _discuss(args):
    """Record advisory intent and investigation without running checks or changing a gate."""
    from .discussion import DiscussionStore
    from .discussion_reporting import write_discussion_reports

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", args.run_id) or args.run_id in {'.', '..'}:
        raise ValueError('Invalid saved run identity')
    if args.record and not args.session_id:
        raise ValueError('A record requires an explicit existing session identity')
    state = reject_reparse_path(args.state_dir)
    if not state.is_dir() or not (state / 'state.sqlite3').is_file() or not (state / 'runs').is_dir():
        raise ValueError('Discussion requires the original existing state directory')
    run = Store(state).get_run(args.run_id)
    discussions = DiscussionStore(state)
    if args.record:
        record_path = reject_reparse_path(args.record)
        if not record_path.is_file() or record_path.stat().st_size > 128 * 1024:
            raise ValueError('Discussion record must be a JSON file of at most 128 KiB')
        record = json.loads(record_path.read_text(encoding='utf-8-sig'))
        if not isinstance(record, dict):
            raise ValueError('Discussion record must be an object')
        session = discussions.record(run, args.session_id, record, source_root=args.source)
    elif args.session_id:
        session = discussions.load(run, args.session_id)
    else:
        session = discussions.create(run)
    output = Path(args.output) if args.output else state / 'discussions' / session['session_id'] / 'report'
    paths = write_discussion_reports(session, run, output)
    if args.json:
        _emit({**session, 'reports': {path.name: str(path.absolute()) for path in paths},
               'original_gate': run.get('gate', {}),
               'notice': 'Advisory discussion of the saved snapshot; original security verdict is unchanged.'})
    else:
        print(f"추가 검토: {session['session_id']} · revision {session['revision']}")
        print('사용자 설명과 조사 제안 기록입니다. 원래 보안 판정은 유지합니다.')
        print(f"공유 기록: {output.absolute() / 'discussion.html'}")
    return 0


def _plan(args):
    from .preflight import inspect_inputs
    with selected_paths(args.exclude_source_path or []), execution.session(
            args.max_duration_seconds, max_input_bytes=4 * 1024**3):
        with execution.phase('input-plan'):
            result = inspect_inputs(args.source)
    _emit(result)
    return 2 if result['errors'] else 0


def build_parser():
    parser = argparse.ArgumentParser(prog="gxsec", description="개발자 실행 · QA/PM 공유용 출시 전 보안 점검")
    parser.add_argument("--version", action="version", version="gx-security " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("init", help="비밀 없는 프로젝트 프로파일 만들기")
    setup.add_argument("source", nargs="?", default=".")
    setup.add_argument("--output")
    setup.add_argument("--force", action="store_true")
    doctor = sub.add_parser("doctor", help="엔진 설치·버전 확인")
    doctor.add_argument("--source", default=".")
    doctor.add_argument("--config")
    doctor.add_argument("--json", action="store_true")
    plan = sub.add_parser('plan', help='내용을 읽지 않고 입력 범위·용량·별도 점검 후보 확인')
    plan.add_argument('source', nargs='?', default='.')
    plan.add_argument('--exclude-source-path', action='append')
    plan.add_argument('--max-duration-seconds', type=float, default=30)
    for command in ("check", "release", "retest"):
        p = sub.add_parser(command, help={"check": "변경분·영향 범위 점검", "release": "전체 출시 프로파일 점검", "retest": "이전 발견사항 수정 재검증"}[command])
        if command == "retest":
            p.add_argument("finding_id")
            p.add_argument("--source", default=".")
            p.add_argument("--run-id", help="참조할 이전 실행; 생략하면 최신 실행")
        else:
            p.add_argument("source", nargs="?", default=".")
        p.add_argument("--config")
        p.add_argument("--profile", choices=("check", "static-release", "release"))
        p.add_argument("--state-dir")
        p.add_argument("--output")
        p.add_argument("--execution-id", help="새 실행의 고유 ID; 외부 실행 허가서와 동일하게 지정")
        p.add_argument("--policy", help="검사 소스 밖의 신뢰하는 조직 정책")
        p.add_argument("--review-records", help="신뢰 정책과 대조할 검토/예외 기록")
        p.add_argument("--expected-framework", choices=('SEF',), help="설정 파일 생성 없이 SEF 필수 경계를 추가 확인")
        p.add_argument('--max-duration-seconds', type=float, help='수집·검사를 합한 전체 시간 예산 (기본 1200초, 재검증은 이전 한도 유지)')
        p.add_argument('--max-input-bytes', type=int, help='검사할 작업 트리 파일 용량 예산 (기본 4GiB, 재검증은 이전 한도 유지; Git 이력·DB 사본 제외)')
        p.add_argument('--exclude-source-path', action='append', help='별도 점검할 상대 디렉터리 (반복 가능, 제외 내역 기록)')
        p.add_argument("--execute-dynamic", action="store_true")
        p.add_argument("--creds-stdin", action="store_true")
        p.add_argument("--json", action="store_true")
        if command == "check":
            p.add_argument("--base")
    report = sub.add_parser("report", help="저장된 결과로 공유본 다시 생성")
    report.add_argument("run_id")
    report.add_argument("--state-dir", default=".gxsec")
    report.add_argument("--output")
    discussion = sub.add_parser('discuss', help='저장된 발견의 질문·답변·추가 조사 기록')
    discussion.add_argument('run_id')
    discussion.add_argument('--state-dir', required=True)
    discussion.add_argument('--session-id')
    discussion.add_argument('--record', help='예상 revision을 포함한 질문·답변·조사 JSON')
    discussion.add_argument('--source', help='질문·조사 근거를 대조할 현재 소스')
    discussion.add_argument('--output')
    discussion.add_argument('--json', action='store_true')
    return parser


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            return _init(args)
        if args.command == "doctor":
            return _doctor(args)
        if args.command == 'plan':
            return _plan(args)
        if args.command == "report":
            return _report(args)
        if args.command == 'discuss':
            return _discuss(args)
        return _execute(args, getattr(args, "finding_id", None))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, yaml.YAMLError) as exc:
        error = {"status": "INCOMPLETE", "error": type(exc).__name__, "detail": str(exc)}
        if getattr(args, "json", False):
            _emit(error)
        else:
            print("점검을 완료하지 못했습니다: " + str(redact(str(exc))), file=sys.stderr)
        return 2
