"""스캐너 백업 폴더 제외 가드 — .dev/.omc/.humanize 등 백업 사본 이중 스캔 방지.

SQIsoft 관례상 .dev/.omc/.humanize 하위에 원본 백업 사본이 쌓인다. 스캐너가 os.walk에서
이를 건너뛰지 않으면 동일 취약점을 이중 보고한다. 이 테스트는 임시 디렉토리에 .dev 백업
서브트리를 만들고 이중 검증한다:
  (1) 그 서브트리를 직접 루트로 스캔하면 취약 픽스처가 잡힌다 → 픽스처가 실재함을 증명
      (파일이 skip돼도 0이라 '잘못된 이유로 통과'하는 위양성을 배제).
  (2) 부모를 스캔하면 .dev가 prune되어 0이 된다 → 제외 성립.
커밋되는 .dev 파일이 없어 gitignore와 무관하며 결정론적이다.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_SCANNER = os.path.join(_ROOT, "skills", "detecting-sql-injection", "scripts", "scan_sqli.py")
_VULN_MAPPER = "<mapper><select id=\"x\">SELECT * FROM t WHERE a = '${p}'</select></mapper>"


def _scan_abs(target):
    proc = subprocess.run(
        [sys.executable, _SCANNER, target, "--json"],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    return json.loads(proc.stdout)


class TestBackupDirIgnored(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gxsec_ignore_")
        self.dev = os.path.join(self.tmp, ".dev", "checkpoint")
        os.makedirs(self.dev)
        with open(os.path.join(self.dev, "VulnMapper.xml"), "w", encoding="utf-8") as f:
            f.write(_VULN_MAPPER)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_fixture_is_real_when_scanned_directly(self):
        # .dev 서브트리를 직접 루트로 스캔 → prune 미발동 → 취약 픽스처가 잡혀야 한다.
        r = _scan_abs(self.dev)
        self.assertGreaterEqual(
            r["candidate_count"], 1,
            "픽스처가 실재하며 폴더 제외가 없으면 잡혀야 한다(위양성 통과 방지)")

    def test_dev_backup_dir_excluded(self):
        # 부모를 스캔 → os.walk가 .dev를 prune → 취약 픽스처 미검출(0).
        r = _scan_abs(self.tmp)
        self.assertEqual(
            r["candidate_count"], 0,
            ".dev 백업 폴더 하위의 취약 픽스처는 스캔에서 제외되어야 한다")


if __name__ == "__main__":
    unittest.main()
