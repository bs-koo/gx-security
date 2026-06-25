"""semgrep 룰 구조 린트 — semgrep 미설치 환경에서도 룰이 '조용히 깨지는' 것을 막는다.

스캐너는 YAML 파싱을 semgrep CLI에 위임하므로, malformed 룰은 semgrep 실행 시에만
드러나고 semgrep이 없으면 grep-폴백으로 빠져 무한정 방치된다. 이 테스트가 그 사각지대를
CI/로컬에서 선제 차단한다. (PyYAML만 사용, semgrep 불필요)
"""
import glob
import os
import unittest

import yaml

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_RULE_FILES = sorted(glob.glob(os.path.join(_ROOT, "skills", "*", "rules", "*.yml")))

_VALID_SEVERITY = {"ERROR", "WARNING", "INFO"}
_PATTERN_KEYS = {"pattern", "patterns", "pattern-either", "pattern-regex"}
_TAINT_KEYS = {"pattern-sources", "pattern-sinks"}


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
                    rid = r.get("id")
                    self.assertIsInstance(rid, str, f"id 누락/비문자열: {r!r}")
                    self.assertIsInstance(r.get("message"), str, f"{rid}: message 누락")
                    self.assertIn(r.get("severity"), _VALID_SEVERITY,
                                  f"{rid}: severity가 ERROR/WARNING/INFO 아님 → {r.get('severity')!r}")
                    langs = r.get("languages")
                    self.assertTrue(isinstance(langs, list) and langs,
                                    f"{rid}: languages가 비어있거나 리스트 아님")
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
                ids = [r.get("id") for r in doc.get("rules", [])]
                dups = sorted({i for i in ids if ids.count(i) > 1})
                self.assertEqual(dups, [], f"파일 내 중복 id: {dups}")

    def test_ids_unique_across_all_files(self):
        # semgrep --config <dir> 로 디렉터리 일괄 로드 시 중복 id는 에러가 된다.
        seen = {}
        collisions = []
        for path in _RULE_FILES:
            rel = os.path.relpath(path, _ROOT)
            for r in _load(path).get("rules", []):
                rid = r.get("id")
                if rid in seen:
                    collisions.append(f"{rid}: {seen[rid]} ↔ {rel}")
                else:
                    seen[rid] = rel
        self.assertEqual(collisions, [], "교차파일 중복 id:\n" + "\n".join(collisions))


if __name__ == "__main__":
    unittest.main()
