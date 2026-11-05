"""Generate inert, redacted views of the same immutable scan result."""
from __future__ import annotations

import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from urllib.parse import quote

from .redaction import redact
from .triage import build_review_packets, framework_manifest


LABELS = {"PASS": "통과", "BLOCK": "조치 필요", "INCOMPLETE": "검사 불완전",
          "PASS_WITH_EXCEPTION": "예외 승인 포함"}
CHECK_LABELS = {"complete": "완료", "incomplete": "미완료", "failed": "실행 실패",
                "unsupported": "준비 필요", "degraded": "제한된 검사", "partial": "부분 검사",
                "skipped": "미실행", "cancelled": "취소", "not_applicable": "적용 제외"}
VALIDATION_LABELS = {"candidate": "검토 후보", "source-verified": "소스 확인", "runtime-verified": "실행 확인",
                     "undetermined": "판정 보류", "refuted": "반증 완료"}
CHECK_NAMES = {"sast": "소스 코드", "sca": "의존성 취약점", "secrets": "시크릿 노출",
               "source-integrity": "검사 대상 무결성", "source-checkout": "출시 버전 확인",
               "readiness": "동적 검사 준비", "auth": "인증", "authorization": "권한·소유권",
               "dast": "웹 실행 검사", "manual-review": "필수 독립 검토", "framework": "SEF 기반·보안 경계"}
PROPOSAL_LABELS = {"confirmed": "위험 근거 확인 제안", "not_actionable": "비조치 검토 제안",
                   "needs_review": "추가 검토 필요"}


def _proposal(context):
    value = context.get('proposal') if isinstance(context, dict) else None
    return value if isinstance(value, str) and value in PROPOSAL_LABELS else 'needs_review'


def _coverage_summary(check):
    coverage = check.get("coverage") or {}
    scope = {"full": "전체", "diff": "변경분"}.get(coverage.get("scope"), "범위 미확인")
    return f"{coverage.get('scanned', 0)} / {coverage.get('eligible', 0)} 검사 단위 · {scope}"


def _error_text(error):
    if not isinstance(error, dict):
        return str(error)
    labels = {
        "database_provenance_unverified": "조직이 승인한 오프라인 취약점 DB 근거를 확인해야 합니다.",
        "missing_database": "오프라인 취약점 DB가 준비되지 않았습니다.",
        "unknown_database_age": "취약점 DB의 갱신 시점을 확인할 수 없습니다.",
        "stale_database": "취약점 DB의 유효기간을 확인하고 갱신해야 합니다.",
        "dependency_provenance_unverified": "모든 모듈의 확정 의존성 목록과 해당 버전의 근거가 필요합니다.",
        "missing_history": "Git 이력을 검사하지 못했습니다.",
        "unresolved_dependencies": "확정 의존성 잠금 파일 또는 SBOM이 필요합니다.",
        "advisory_matching_incomplete": "일부 패키지의 취약점 DB 매칭을 확인하지 못했습니다.",
        "framework_baseline_unverified": "조직이 요구한 SEF 기반 버전과 현재 소스·분석기가 일치하지 않습니다.",
        "context_analysis_failed": "문맥 분석이 완료되지 않았습니다. 후보의 근거를 추가 검토해야 합니다.",
    }
    return labels.get(error.get("type"), str(error.get("message") or error.get("type") or "추가 확인 필요"))


def _check_issues(check):
    issues = [_error_text(error) for error in check.get("errors", [])]
    missing = (check.get("coverage") or {}).get("missing") or []
    if missing:
        issues.append("미검사 파일 " + str(len(missing)) + "개: " + ", ".join(map(str, missing[:5]))
                      + (" 외 " + str(len(missing) - 5) + "개" if len(missing) > 5 else ""))
    return issues


def _remediation(finding):
    value = finding.get("remediation")
    if isinstance(value, dict):
        return str(value.get("guidance") or value.get("description") or "근거 검토 후 수정·재검증")
    return str(value or "근거 검토 후 수정·재검증")


def _json(value):
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _text(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value if value is not None else "")


def _md(value):
    text = html.escape(_text(value)).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_\[\]()!|])", r"\\\1", text)


def _location(finding):
    locations = finding.get("locations") or []
    if not locations:
        return ""
    loc = locations[0]
    return str(loc.get("path", loc.get("file", ""))) + (":" + str(loc["line"]) if loc.get("line") else "")


def _title(finding):
    return finding.get("title") or finding.get("semantic_rule_id") or finding.get("rule_id") or finding.get("category", "발견사항")


def _safe_uri(value):
    value = str(value or "").replace("\\", "/")
    if not value or ":" in value or PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts:
        return None
    return quote(value, safe="/.-_~")


def _sarif(run):
    rules, results = {}, []
    for f in run.get("findings", []):
        rule = str(f.get("semantic_rule_id") or f.get("rule_id") or f.get("category") or "gxsec-review")
        rules.setdefault(rule, {"id": rule, "shortDescription": {"text": str(_title(f))}})
        result = {"ruleId": rule, "message": {"text": str(f.get("description") or _title(f))},
                  "level": {"Critical": "error", "High": "error", "Medium": "warning"}.get(f.get("severity"), "note"),
                  "partialFingerprints": {"gxsec/v1": f.get("fingerprint", f.get("finding_id", ""))},
                  "properties": {**{key: f.get(key) for key in ("finding_id", "severity", "validation", "lifecycle")},
                                 "contextProposal": _proposal(f.get("context")),
                                 "contextClassification": (f.get("context") or {}).get("classification") if isinstance(f.get("context"), dict) else None}}
        locations = []
        for loc in f.get("locations", []):
            uri = _safe_uri(loc.get("path", loc.get("file")))
            if uri:
                physical = {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
                if isinstance(loc.get("line"), int) and loc["line"] > 0:
                    physical["region"] = {"startLine": loc["line"]}
                locations.append({"physicalLocation": physical})
        if locations:
            result["locations"] = locations
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "gx-security", "rules": list(rules.values())}},
                      "automationDetails": {"id": run.get("profile", "unknown") + "/" + run.get("run_id", "unknown")},
                      "invocations": [{"executionSuccessful": run.get("gate", {}).get("status") in ("PASS", "PASS_WITH_EXCEPTION", "BLOCK")}],
                      "results": results}]}


def _markdown(run, qa=False):
    gate = run.get("gate", {})
    status = gate.get("status", "INCOMPLETE")
    lines = ["# " + ("QA 보안 확인표" if qa else "개발자 보안 점검 결과"), "",
             f"프로젝트: {_md(run.get('project_id', ''))} · 프로파일: {_md(run.get('profile', ''))}", "",
             f"판정: **{LABELS.get(status, status)} ({_md(status)})** · 실행: {_md(run.get('run_id'))}", "",
             f"버전: {_md(run.get('source', {}).get('commit') or run.get('source', {}).get('hash'))}", "",
             "이 결과는 표시된 프로파일의 검사 범위에 한정됩니다. 최종 출시 승인은 조직 절차를 따릅니다.", "",
             "## 검사 범위와 미완료 항목", ""]
    framework = next((c.get("framework") for c in run.get("checks", []) if c.get("id") == "framework"), None)
    if isinstance(framework, dict):
        lines.extend(["SEF 기반: " + _md(framework.get("family", "unknown")) + " · " + _md(framework.get("variant", "undetermined")), "",
                      "기반 식별은 안전 승인이 아닙니다. 보호 기능의 적용 경로와 프로젝트 변경을 함께 확인합니다.", "",
                      "모듈: " + _md(framework.get("modules", [])), "",
                      "분석 한계: " + _md(framework.get("limitations", [])), ""])
    for check in run.get("checks", []):
        lines.append(f"- {'[ ] ' if qa and check.get('status') != 'complete' else ''}{_md(CHECK_NAMES.get(check.get('id'), check.get('id')))}: {_md(CHECK_LABELS.get(check.get('status'), check.get('status')))} · {_md(_coverage_summary(check))}")
        for issue in _check_issues(check):
            lines.append(f"  - 확인 필요: {_md(issue)}")
    lines.extend(["", "## 발견사항과 수정 확인", ""])
    for f in run.get("findings", []):
        fid = f.get("finding_id", "unknown")
        lines.extend([f"### {_md(fid)} · {_md(_title(f))}", "",
                      f"등급: {_md(f.get('severity', 'unknown'))} · 검증: {_md(f.get('validation'))} · 조치: {_md(f.get('lifecycle'))}", "",
                      f"위치: {_md(_location(f))}", "", _md(f.get("description", "")), "",
                      f"수정 방향: {_md(_remediation(f))}", ""])
        context = f.get("context")
        if isinstance(context, dict):
            lines.extend(["판정 제안: " + _md(PROPOSAL_LABELS[_proposal(context)]), "",
                          "이 제안은 독립 검토·반증 승인을 대신하지 않습니다.", ""])
            for field, label in (("evidence_for", "위험 근거"), ("evidence_against", "반대 근거"),
                                 ("unresolved", "확인할 사항"), ("limitations", "분석 한계")):
                values = context.get(field, [])
                if values:
                    lines.extend([label + ": " + _md(values[:5] if isinstance(values, list) else values), ""])
        elif f.get("evidence_refs"):
            lines.extend(["소스 근거: " + _md(f["evidence_refs"]), ""])
        if qa:
            lines.extend(["- [ ] 대상 버전·계정 역할·테스트 데이터가 일치하는지 확인", "- [ ] 정상 기능과 원래 취약 경로의 방어를 함께 확인",
                          "- [ ] 근거·확인자·결정을 남김. 미확인은 완료로 표시하지 않음", ""])
        else:
            lines.extend([f"재점검: `gxsec retest {_md(fid)} --source <프로젝트> --config <프로파일>`", ""])
    if not run.get("findings"):
        lines.extend(["발견사항이 없어도 필수 검사 미완료 여부를 먼저 확인합니다.", ""])
    lines.extend(["## 예외와 검토", "", _md(run.get("exceptions", [])), "", _md(run.get("reviews", [])), ""])
    return "\n".join(lines)


def _context_html(finding, esc):
    context = finding.get("context")
    if not isinstance(context, dict):
        return ""
    parts = ["<h4>판정 제안 · " + esc(PROPOSAL_LABELS[_proposal(context)]) + "</h4>",
             "<p>근거 검토를 돕는 제안입니다. 독립 검토·반증 승인을 대신하지 않습니다.</p>"]
    for field, label in (("evidence_for", "위험 근거"), ("evidence_against", "반대 근거"),
                         ("unresolved", "확인할 사항"), ("limitations", "분석 한계")):
        values = context.get(field)
        if values:
            parts.append("<details><summary>" + label + "</summary><pre>" + esc(values) + "</pre></details>")
    return "".join(parts)


def _framework_html(run, esc):
    framework = next((c.get("framework") for c in run.get("checks", []) if c.get("id") == "framework"), None)
    if not isinstance(framework, dict):
        return ""
    return ("<section><h2>SEF 기반과 프로젝트 확장</h2><p>" + esc(framework.get("family", "unknown"))
            + " · " + esc(framework.get("variant", "undetermined"))
            + "</p><p>기반 식별은 안전 승인이 아닙니다. 공통 보호 기능과 실제 호출 경로를 함께 검토합니다.</p>"
            + "<details><summary>모듈·보호 조건·분석 한계</summary><pre>" + esc(framework)
            + "</pre></details></section>")


_FILTER_SCRIPT = """const q=document.querySelector('#q'),s=document.querySelector('#severity');function filter(){for(const row of document.querySelectorAll('[data-finding]')){row.hidden=!(row.textContent.toLowerCase().includes(q.value.toLowerCase())&&(!s.value||row.dataset.severity===s.value));}for(const group of document.querySelectorAll('[data-group]')){group.hidden=!group.querySelector('[data-finding]:not([hidden])');if(q.value||s.value)group.open=!group.hidden;}}q.addEventListener('input',filter);s.addEventListener('change',filter);"""


def _html(run):
    import base64
    esc = lambda value: html.escape(_text(value), quote=True)
    gate = run.get("gate", {})
    status = gate.get("status", "INCOMPLETE")
    script_hash = base64.b64encode(hashlib.sha256(_FILTER_SCRIPT.encode()).digest()).decode()
    csp = f"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'; base-uri 'none'; form-action 'none'; img-src 'none'"
    groups = {}
    for f in run.get("findings", []):
        key = (str(f.get('category')), str(f.get('rule_id')))
        group = groups.setdefault(key, {'title': _title(f), 'items': [], 'count': 0, 'high': False})
        group['count'] += 1
        group['high'] = group['high'] or f.get('severity') in {'High', 'Critical'}
        group['items'].append(f"""<article data-finding data-severity="{esc(f.get('severity'))}"><div class="meta">{esc(f.get('finding_id'))} · {esc(f.get('severity') or '위험도 미분류')} · {esc(VALIDATION_LABELS.get(f.get('validation'),f.get('validation')))} · {esc(f.get('lifecycle'))}</div><h3>{esc(_title(f))}</h3><p><code>{esc(_location(f))}</code></p><p>{esc(f.get('description',''))}</p>{_context_html(f, esc)}<h4>수정과 재점검</h4><p>{esc(_remediation(f))}</p><details><summary>관측·증거</summary><pre>{esc(f.get('observations',[]))}\n{esc(f.get('evidence_refs',[]))}</pre></details></article>""")
    cards = [f"<details data-group {'open' if group['high'] or group['count'] <= 3 else ''}><summary><strong>{esc(group['title'])}</strong> · {group['count']}개 위치</summary>{''.join(group['items'])}</details>"
             for group in sorted(groups.values(), key=lambda group: (not group['high'], -group['count']))]
    rows = "".join(f"<tr><th scope='row'>{esc(CHECK_NAMES.get(c.get('id'),c.get('id')))}</th><td>{esc(CHECK_LABELS.get(c.get('status'),c.get('status')))}</td><td>{esc(_coverage_summary(c))}</td><td>{'<br>'.join(esc(issue) for issue in _check_issues(c)) or '—'}</td></tr>" for c in run.get("checks", []))
    next_step = {"INCOMPLETE": "미완료 사유를 해소하고 같은 프로파일로 다시 검사하세요.",
                 "BLOCK": "확인된 차단 사항을 수정하거나 조직의 위험 수용 절차를 진행하세요.",
                 "PASS": "표시된 검사 범위가 완료됐습니다. 조직의 최종 출시 절차를 진행하세요.",
                 "PASS_WITH_EXCEPTION": "승인된 예외의 범위·담당·만료일을 확인하고 출시 절차를 진행하세요."}.get(status, "검사 상태와 근거를 확인하세요.")
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="{html.escape(csp,quote=True)}"><title>gx-security · {esc(run.get('project_id'))}</title>
<style>body{{overflow-wrap:anywhere}}</style>
<style>:root{{color-scheme:light dark;font-family:system-ui,'Malgun Gothic',sans-serif;--accent:#34657b}}body{{max-width:1100px;margin:auto;padding:28px;line-height:1.65}}header{{border-bottom:3px solid var(--accent);padding-bottom:20px}}.meta{{font-size:.9rem}}.status{{font-size:1.45rem;font-weight:700}}article{{border-top:1px solid #8887;padding:20px 0;margin:18px 0}}table{{border-collapse:collapse;width:100%;font-size:.9rem}}th,td{{border-bottom:1px solid #8887;text-align:left;vertical-align:top;padding:12px 9px;overflow-wrap:anywhere}}.table-scroll{{overflow-x:auto}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}p,li{{max-width:75ch}}input,select{{font:inherit;padding:8px;max-width:95%}}h1,h2,h3{{text-wrap:balance;overflow-wrap:anywhere}}h2{{margin-top:35px}}summary{{cursor:pointer}}:focus-visible{{outline:3px solid var(--accent);outline-offset:3px}}::selection{{background:#cce6f0;color:#12303d}}[hidden]{{display:none}}a{{color:inherit}}@media(max-width:600px){{body{{padding:16px}}table{{min-width:620px}}input,select{{margin:6px 0}}}}@media(prefers-color-scheme:dark){{:root{{--accent:#8dcde2}}}}</style></head>
<body><header><h1>{esc(run.get('project_id'))}</h1><p class="status">{esc(LABELS.get(status,status))} · {esc(status)}</p><p>{esc(next_step)}</p><p>프로파일 <strong>{esc(run.get('profile'))}</strong> · 실행 {esc(run.get('run_id'))}</p><p>대상 버전 {esc(run.get('source',{}).get('revision') or run.get('source',{}).get('hash') or run.get('source',{}).get('commit'))}</p><p>이 결과는 해당 프로파일과 버전의 검사 범위에 한정됩니다. 미완료와 예외를 함께 확인하세요.</p></header>
<section><h2>PM 확인</h2><p>차단 {_text(len(gate.get('blockers',[])))}건 · 미완료 {_text(len(gate.get('incomplete',[])))}건 · 발견사항 {_text(len(run.get('findings',[])))}건</p><p>검토 후보는 취약점 확정 건수와 다릅니다. 개발자와 QA가 근거를 확인하고 결정을 기록합니다.</p><details><summary>판정 근거 자세히 보기</summary><pre>{esc(gate)}</pre></details></section>
{_framework_html(run, esc)}<section><h2>검사 범위</h2><div class="table-scroll" role="region" aria-label="검사 범위 표" tabindex="0"><table><thead><tr><th>항목</th><th>실행 상태</th><th>범위</th><th>미완료 사유</th></tr></thead><tbody>{rows}</tbody></table></div><details><summary>파일 목록·엔진·검사 증거</summary><pre>{esc(run.get('checks',[]))}</pre></details></section>
<section><h2>개발자 조치</h2><p>같은 규칙의 위치를 묶었습니다. 묶음을 펼쳐 각 위치의 근거를 확인하세요.</p><label>검색 <input id="q" type="search" placeholder="항목·위치·담당 검색"></label> <label>등급 <select id="severity"><option value="">전체</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option><option value="None">미분류</option></select></label>{''.join(cards) or '<p>발견사항 없음. 검사 완료 상태를 확인하세요.</p>'}</section>
<section><h2>QA 확인</h2><p>qa-checklist.md에 계정·리소스·정상 기능·원래 취약 경로 확인을 기록합니다. 미확인은 완료가 아닙니다.</p><h2>검토·예외</h2><pre>{esc(run.get('reviews') or '등록된 검토 기록 없음')}\n{esc(run.get('exceptions') or '등록된 예외 없음')}</pre></section>
<footer><p>원본 구조화 결과 result.json · 코드 연동 results.sarif · 검토 묶음 review-packets.json · 기반 관측 framework-baseline.json · 무결성 목록 manifest.json</p></footer><script>{_FILTER_SCRIPT}</script></body></html>"""


def write_reports(run: dict, output_dir: Path) -> list[Path]:
    """Write one redacted snapshot and its derived views; never execute evidence."""
    output_dir = Path(output_dir)
    for ancestor in (output_dir, *output_dir.parents):
        if ancestor.is_symlink() or (hasattr(ancestor, "is_junction") and ancestor.is_junction()):
            raise ValueError("report directory must not traverse a symbolic link")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe = redact(run)
    contents = {"result.json": _json(safe), "report.html": _html(safe),
                "developer.md": _markdown(safe), "qa-checklist.md": _markdown(safe, qa=True),
                "results.sarif": _json(_sarif(safe)),
                "review-packets.json": _json(build_review_packets(safe)),
                "framework-baseline.json": _json(framework_manifest(safe)),
                "evidence-manifest.json": _json({"run_id": safe.get("run_id"),
                    "evidence": [{"finding_id": f.get("finding_id"), "refs": f.get("evidence_refs", [])} for f in safe.get("findings", [])]})}
    paths = []
    for name, content in contents.items():
        path = output_dir / name
        _atomic_write(path, content)
        paths.append(path)
    manifest = {"schema_version": 1, "run_id": safe.get("run_id"), "profile": safe.get("profile"),
                "source": safe.get("source"), "gate": safe.get("gate"),
                "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}
    path = output_dir / "manifest.json"
    _atomic_write(path, _json(manifest))
    return paths + [path]


def _atomic_write(path, content):
    descriptor, temporary = tempfile.mkstemp(prefix=".gxsec-export-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
