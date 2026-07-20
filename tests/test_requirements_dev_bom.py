"""requirements-dev.txt의 UTF-8 BOM 보존 회귀 가드.

cp949 로케일의 Windows pip는 BOM/PEP263 coding cookie가 없으면
locale.getpreferredencoding(False)로 폴백해 한글 주석이 포함된 이 파일을
UnicodeDecodeError로 파싱조차 못 한다(커밋 bc38f85에서 실측 재현·수정).
이후 "인코딩 정규화" 같은 편집으로 BOM이 조용히 제거되는 회귀를 막는다.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestRequirementsDevBom(unittest.TestCase):
    def test_utf8_bom_present(self):
        content = (ROOT / "requirements-dev.txt").read_bytes()
        self.assertEqual(
            content[:3],
            b"\xef\xbb\xbf",
            "requirements-dev.txt 선두 UTF-8 BOM이 제거됨 — cp949 Windows pip "
            "UnicodeDecodeError 재발 위험(커밋 bc38f85 참고)",
        )


if __name__ == "__main__":
    unittest.main()
