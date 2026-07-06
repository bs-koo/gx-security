"""scan_secrets 폴백 회귀 (F3 / FR-9 — AC-9).

포맷 기반 시크릿 5종(AWS/GitHub/PEM/JDBC)을 라인-로컬 근사로 후보화한다.
QE-1: 대문자/카멜케이스 플레이스홀더와 공개 인증서는 미탐(방향성 오탐 차단).

주의: run_fallback 이 확장자 필터를 쓰므로 tempfile 픽스처는 실제 확장자
(.key/.pem/.properties 등)로 생성해야 한다.
"""
import importlib.util
import os
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "detecting-sensitive-data-exposure",
                    "scripts", "scan_secrets.py")
_spec = importlib.util.spec_from_file_location("scan_secrets", _MOD)
scan_secrets = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_secrets)


def _rule_ids(filename, body):
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
            fh.write(body)
        findings = scan_secrets.run_fallback(d)
    return [c["rule_id"] for c in findings]


class TestFormatSecretsVuln(unittest.TestCase):
    """5포맷 각각 개별 vuln 케이스 → 해당 rule_id ≥1."""

    def test_aws_access_key_id(self):
        rules = _rule_ids("app.properties", "aws.accessKeyId=AKIAIOSFODNN7EXAMPLE\n")
        self.assertGreaterEqual(rules.count("aws-access-key-id"), 1)

    def test_github_token(self):
        rules = _rule_ids("app.properties",
                          "gh.token=ghp_1234567890abcdefghijklmnopqrstuvwx\n")
        self.assertGreaterEqual(rules.count("github-token"), 1)

    def test_pem_private_key_in_key_file(self):
        # AC-9(d) .key 파일 내용을 pem-private-key 룰이 스캔
        rules = _rule_ids("id_rsa.key", "-----BEGIN RSA PRIVATE KEY-----\n")
        self.assertGreaterEqual(rules.count("pem-private-key"), 1)

    def test_pem_private_key_in_code_file(self):
        # AC-9(c) 포맷 기반 — 확장자 무관. 코드/설정 파일에 임베드된 PRIVATE KEY 마커도
        # 동일 정규식이 스캔한다(.pem/.key 확장자에 의존하지 않음).
        rules = _rule_ids(
            "Config.java",
            'class C { String k = "-----BEGIN EC PRIVATE KEY-----"; }\n')
        self.assertGreaterEqual(rules.count("pem-private-key"), 1)

    def test_jdbc_url_password_plaintext(self):
        rules = _rule_ids("app.properties",
                          "db=jdbc:mysql://db/app?user=a&password=Secret123\n")
        self.assertGreaterEqual(rules.count("jdbc-url-password"), 1)

    def test_pem_encrypted_private_key(self):
        # ENCRYPTED 헤더(PKCS#8)도 pem-private-key 룰이 스캔
        rules = _rule_ids("id_enc.key", "-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
        self.assertGreaterEqual(rules.count("pem-private-key"), 1)


class TestFormatSecretsSafe(unittest.TestCase):
    """QE-1 — 플레이스홀더·공개 인증서는 미탐(==0)."""

    def test_aws_uppercase_placeholder_not_flagged(self):
        rules = _rule_ids("app.properties", "awsKey=${AWS_ACCESS_KEY}\n")
        self.assertEqual(rules.count("aws-access-key-id"), 0)

    def test_jdbc_camelcase_placeholder_not_flagged(self):
        # ${dbPassword}(카멜) → (?!\$\{) 로 차단
        rules = _rule_ids("app.properties",
                          "db=jdbc:mysql://h/app?password=${dbPassword}\n")
        self.assertEqual(rules.count("jdbc-url-password"), 0)

    def test_public_certificate_not_flagged(self):
        # 공개 인증서(BEGIN CERTIFICATE)는 개인키가 아니므로 미탐
        rules = _rule_ids("cert.pem", "-----BEGIN CERTIFICATE-----\n")
        self.assertEqual(rules.count("pem-private-key"), 0)


if __name__ == "__main__":
    unittest.main()
