"""scope_guard 판정 로직 직접 유닛테스트 (코드리뷰 H2 + M8).

안전 게이트(운영 오발사 차단의 최후 방어선)의 classify()/assert_in_scope()를
mock 없이 직접 호출해, IP 위장(정수·8/16진·IPv4-mapped IPv6)·prod/www deny·
메타데이터 절대차단·env 이중게이트·fail-closed·ALLOW_HOSTS suffix 풋건을 고정한다.
기대값은 현재 구현을 실행해 캡처한 ground-truth다(리팩터로 킬스위치가 조용히
깨지면 이 테스트가 실패한다).
"""
import importlib.util
import os
import unittest
from unittest.mock import patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_spec = importlib.util.spec_from_file_location(
    "scope_guard", os.path.join(_ROOT, "tools", "scope_guard.py"))
scope_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scope_guard)
classify = scope_guard.classify
assert_in_scope = scope_guard.assert_in_scope
ScopeError = scope_guard.ScopeError


@patch.dict(os.environ, {}, clear=True)
class TestClassifyNoEnv(unittest.TestCase):
    """env 미설정 기준 classify 판정 매트릭스."""

    ALLOW = ["127.0.0.1", "localhost", "[::1]", "2130706433", "0x7f000001",
             "foo.test", "x.localhost", "y.local", "z.example", "w.invalid"]
    # 위장 IP(정수/16진/IPv4-mapped)·와일드카드·운영패턴·빈 문자열 → 절대 차단
    DENY = ["169.254.169.254", "2852039166", "0xa9fea9fe", "[::ffff:169.254.169.254]",
            "0.0.0.0", "www.company.com", "prod.company.com", "production.company.com", ""]
    # 사설망·공인 IP/도메인 → 자동 허용 안 함(기본 차단, 승인 필요)
    NEEDS = ["10.0.0.5", "192.168.1.1", "8.8.8.8", "api.company.com",
             "staging.company.com", "not a url"]

    def test_allow(self):
        for h in self.ALLOW:
            with self.subTest(host=h):
                self.assertEqual(classify(h)[0], "allow")

    def test_deny_spoofed_and_prod(self):
        for h in self.DENY:
            with self.subTest(host=h):
                self.assertEqual(classify(h)[0], "deny")

    def test_needs_auth(self):
        for h in self.NEEDS:
            with self.subTest(host=h):
                self.assertEqual(classify(h)[0], "needs-authorization")


class TestClassifyEnv(unittest.TestCase):
    """env(ALLOW_PRIVATE/ALLOW_HOSTS) 상호작용 + M8 suffix 풋건."""

    def test_allow_private_opens_private(self):
        with patch.dict(os.environ, {"SECURITY_PLUGIN_ALLOW_PRIVATE": "1"}, clear=True):
            self.assertEqual(classify("10.0.0.5")[0], "allow")

    def test_allow_private_never_opens_metadata(self):
        with patch.dict(os.environ, {"SECURITY_PLUGIN_ALLOW_PRIVATE": "1"}, clear=True):
            self.assertEqual(classify("169.254.169.254")[0], "deny")

    def test_allow_hosts_suffix_and_exact(self):
        with patch.dict(os.environ, {"SECURITY_PLUGIN_ALLOW_HOSTS": "example.com"}, clear=True):
            self.assertEqual(classify("api.example.com")[0], "allow")   # suffix
            self.assertEqual(classify("example.com")[0], "allow")       # exact
            self.assertEqual(classify("notexample.com")[0], "needs-authorization")  # 라벨경계

    def test_allow_hosts_exact_single_label_ok(self):
        # 정확매칭은 단일 라벨(내부 호스트명)도 허용
        with patch.dict(os.environ, {"SECURITY_PLUGIN_ALLOW_HOSTS": "intranet"}, clear=True):
            self.assertEqual(classify("intranet")[0], "allow")

    def test_m8_broad_suffix_footgun_blocked(self):
        # 코드리뷰 M8: 단일 라벨 suffix("com")가 evil.com 을 열면 안 된다
        with patch.dict(os.environ, {"SECURITY_PLUGIN_ALLOW_HOSTS": "com"}, clear=True):
            self.assertEqual(classify("evil.com")[0], "needs-authorization")


class TestAssertInScope(unittest.TestCase):
    """assert_in_scope 게이트: allow=통과, deny/needs-auth(무승인)/파싱실패=차단(fail-closed)."""

    @patch.dict(os.environ, {}, clear=True)
    def test_allow_passes(self):
        self.assertIn("loopback", assert_in_scope("127.0.0.1"))

    @patch.dict(os.environ, {}, clear=True)
    def test_deny_raises(self):
        with self.assertRaises(ScopeError):
            assert_in_scope("169.254.169.254")

    @patch.dict(os.environ, {}, clear=True)
    def test_needs_auth_without_env_raises(self):
        with self.assertRaises(ScopeError):
            assert_in_scope("api.company.com")

    def test_needs_auth_with_flag_and_env_passes(self):
        with patch.dict(os.environ, {"SECURITY_PLUGIN_AUTHORIZED": "1"}, clear=True):
            self.assertTrue(assert_in_scope("api.company.com", authorized_flag=True))

    def test_deny_absolute_even_with_authorization(self):
        # 메타데이터는 --authorized + AUTHORIZED=1 이중승인으로도 뚫리지 않는다
        with patch.dict(os.environ, {"SECURITY_PLUGIN_AUTHORIZED": "1"}, clear=True):
            with self.assertRaises(ScopeError):
                assert_in_scope("169.254.169.254", authorized_flag=True)

    @patch.dict(os.environ, {}, clear=True)
    def test_fail_closed_on_garbage(self):
        with self.assertRaises(ScopeError):
            assert_in_scope("not a url")


if __name__ == "__main__":
    unittest.main()
