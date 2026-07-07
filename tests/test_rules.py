"""semgrep 룰 구조 린트 — semgrep 미설치 환경에서도 룰이 '조용히 깨지는' 것을 막는다.

스캐너는 YAML 파싱을 semgrep CLI에 위임하므로, malformed 룰은 semgrep 실행 시에만
드러나고 semgrep이 없으면 grep-폴백으로 빠져 무한정 방치된다. 이 테스트가 그 사각지대를
CI/로컬에서 선제 차단한다. (PyYAML만 사용, semgrep 불필요)

검증 범위: YAML 파싱 + 스키마 키 존재·타입·severity/languages 유효성 + id 유일성까지.
semgrep 패턴의 의미(메타변수 바인딩·실제 매칭 여부)는 검증하지 않는다(semgrep 필요).
"""
import glob
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import yaml

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_RULE_FILES = sorted(glob.glob(os.path.join(_ROOT, "skills", "*", "rules", "*.yml")))

_VALID_SEVERITY = {"ERROR", "WARNING", "INFO"}
_PATTERN_KEYS = {"pattern", "patterns", "pattern-either", "pattern-regex"}
_TAINT_KEYS = {"pattern-sources", "pattern-sinks"}
# semgrep이 인식하는 언어 식별자(현재 룰이 쓰는 것 + 흔한 것). 오타·대소문자 오류를 잡는다.
_VALID_LANGS = {
    "java", "generic", "xml", "json", "yaml", "html",
    "python", "py", "javascript", "js", "typescript", "ts",
    "go", "ruby", "rb", "php", "c", "cpp", "csharp", "scala", "kotlin", "rust", "bash",
}


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class TestRuleFilesDiscovered(unittest.TestCase):
    def test_at_least_nine_rule_files(self):
        self.assertGreaterEqual(len(_RULE_FILES), 9,
                                f"룰 파일을 찾지 못함: {_RULE_FILES}")


class TestRuleFileStructure(unittest.TestCase):
    def test_each_parses_and_is_schema_valid(self):
        for path in _RULE_FILES:
            with self.subTest(file=os.path.relpath(path, _ROOT)):
                try:
                    doc = _load(path)
                except yaml.YAMLError as e:
                    self.fail(f"YAML 파싱 실패 → semgrep 로드 불가(grep 폴백 고착): {e}")
                self.assertIsInstance(doc, dict, "최상위가 매핑이 아님")
                self.assertIn("rules", doc, "최상위 'rules' 키 없음")
                self.assertIsInstance(doc["rules"], list, "'rules'가 리스트가 아님")
                self.assertTrue(doc["rules"], "'rules'가 비어 있음")
                for r in doc["rules"]:
                    self.assertIsInstance(r, dict, f"룰이 매핑(dict)이 아님: {r!r}")
                    rid = r.get("id")
                    self.assertTrue(isinstance(rid, str) and rid.strip(),
                                    f"id 누락/빈문자열: {r!r}")
                    msg = r.get("message")
                    self.assertTrue(isinstance(msg, str) and msg.strip(),
                                    f"{rid}: message 누락/빈문자열")
                    self.assertIn(r.get("severity"), _VALID_SEVERITY,
                                  f"{rid}: severity가 ERROR/WARNING/INFO 아님 → {r.get('severity')!r}")
                    langs = r.get("languages")
                    self.assertTrue(isinstance(langs, list) and langs,
                                    f"{rid}: languages가 비어있거나 리스트 아님")
                    for lang in langs:
                        self.assertIn(lang, _VALID_LANGS,
                                      f"{rid}: 알 수 없는 language {lang!r} (오타/대소문자 — semgrep이 룰을 건너뜀)")
                    if r.get("mode") == "taint":
                        self.assertTrue(_TAINT_KEYS.issubset(r),
                                        f"{rid}: taint 모드인데 sources/sinks 누락")
                    else:
                        self.assertTrue(any(k in r for k in _PATTERN_KEYS),
                                        f"{rid}: pattern/patterns/pattern-either/pattern-regex 중 하나 필요")


class TestRuleIdUniqueness(unittest.TestCase):
    def test_ids_unique_within_each_file(self):
        for path in _RULE_FILES:
            with self.subTest(file=os.path.relpath(path, _ROOT)):
                doc = _load(path)
                if not isinstance(doc, dict):
                    continue   # 구조 검증은 test_each_parses가 담당
                ids = [r.get("id") for r in doc.get("rules", []) if isinstance(r, dict)]
                dups = sorted({i for i in ids if ids.count(i) > 1})
                self.assertEqual(dups, [], f"파일 내 중복 id: {dups}")

    def test_ids_unique_across_all_files(self):
        # semgrep --config <dir> 로 디렉터리 일괄 로드 시 중복 id는 에러가 된다.
        seen = {}
        collisions = []
        for path in _RULE_FILES:
            rel = os.path.relpath(path, _ROOT)
            doc = _load(path)
            if not isinstance(doc, dict):
                continue
            for r in doc.get("rules", []):
                if not isinstance(r, dict):
                    continue
                rid = r.get("id")
                if rid in seen:
                    collisions.append(f"{rid}: {seen[rid]} ↔ {rel}")
                else:
                    seen[rid] = rel
        self.assertEqual(collisions, [], "교차파일 중복 id:\n" + "\n".join(collisions))


@unittest.skipUnless(shutil.which("semgrep"), "semgrep 미설치 → 스킵(CI semgrep-tests job에서 검증)")
class TestRuleFilesSemgrepLoadable(unittest.TestCase):
    """semgrep 실제 로드 검증 — YAML 구조는 통과해도 semgrep 패턴 파서에서 깨지는 룰을 잡는다.

    TestRuleFileStructure 는 PyYAML 구조만 본다. semgrep 의 Java/generic 패턴 파서는 별개라
    세미콜론 누락·잘못된 ellipsis(`... expr ...`) 같은 결함은 semgrep 실행으로만 드러난다.
    (M5: 룰 3파일이 이 사각지대로 파일 전체가 무효화→grep-폴백 강등돼 있었다.)

    semgrep --json 의 errors[] 배열에서 '...parse error' 타입을 기계가독으로 검증한다.
    단일 룰의 파싱 에러 하나가 파일 전체를 무효화하므로, 이 게이트가 전역 파탄 재발을 막는다.
    """

    def test_each_file_loads_without_parse_error(self):
        tmp = tempfile.mkdtemp(prefix="gxsec_ruleload_")
        try:
            # 룰 파싱 에러는 config 로드 시점에 드러나므로 최소 타깃 하나면 충분하다.
            with open(os.path.join(tmp, "D.java"), "w", encoding="utf-8") as fh:
                fh.write("class D {}\n")
            for path in _RULE_FILES:
                with self.subTest(file=os.path.relpath(path, _ROOT)):
                    proc = subprocess.run(
                        ["semgrep", "--config", path, "--json", "--quiet", tmp],
                        capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=180)
                    # semgrep --json: valid=0, findings=0(--json 은 findings 로 rc 안 올림), 룰/설정에러=2.
                    # 비정상 종료 시 stdout 이 비어 'or "{}"' 로 파싱 통과→위양성이 되는 사각지대 차단.
                    if proc.returncode != 0:
                        self.fail(f"semgrep 실행 실패 (rc={proc.returncode}): "
                                  f"{proc.stderr[:500]}")
                    try:
                        data = json.loads(proc.stdout or "{}")
                    except json.JSONDecodeError:
                        self.fail(f"semgrep JSON 파싱 실패 (rc={proc.returncode}): "
                                  f"{proc.stderr[:300]}")
                    parse_errs = [e for e in data.get("errors", [])
                                  if "parse" in (e.get("type", "") or "").lower()]
                    self.assertEqual(
                        parse_errs, [],
                        f"{os.path.relpath(path, _ROOT)}: semgrep 룰 파싱 에러 → "
                        f"파일 전체 무효화(폴백강등). "
                        f"{[e.get('message', '')[:100] for e in parse_errs]}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
