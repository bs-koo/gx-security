"""Protected transport lifetimes remain bounded even when clocks/cleanup fail."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from gxsec import transport


@pytest.mark.parametrize('address', [
    '169.254.169.254', '169.254.170.2', '0.0.0.1', '224.0.0.1',
    'fe80::1', '::', 'ff02::1', 'fd00:ec2::254', '::ffff:169.254.169.254',
    '::1%lo',
])
def test_explicit_ip_list_cannot_approve_prohibited_destinations(address):
    with pytest.raises(transport.TransportError):
        transport.BoundedTransport('http://127.0.0.1', paths=['/'], allowed_ips=['127.0.0.1', address])


@pytest.mark.parametrize('target', ['http://[fd00:ec2::254]', 'http://224.0.0.1',
                                  'http://[ff02::1]', 'http://255.255.255.255'])
def test_metadata_multicast_and_broadcast_are_never_legacy_scope_approved(monkeypatch, target):
    from tools import scope_guard
    monkeypatch.setenv('SECURITY_PLUGIN_AUTHORIZED', '1')
    monkeypatch.setenv('SECURITY_PLUGIN_ALLOW_PRIVATE', '1')
    with pytest.raises(scope_guard.ScopeError):
        scope_guard.assert_in_scope(target, authorized_flag=True)


def test_approved_non_metadata_private_ipv6_still_has_a_preflight_path(monkeypatch):
    from tools import scope_guard
    monkeypatch.setenv('SECURITY_PLUGIN_ALLOW_PRIVATE', '1')
    assert scope_guard.assert_in_scope('http://[fd00:42::5]')


def test_lease_cannot_be_extended_by_wall_clock_rollback(monkeypatch):
    clock = {'wall': 1000.0, 'mono': 50.0}
    monkeypatch.setattr(transport, 'time', SimpleNamespace(
        time=lambda: clock['wall'], monotonic=lambda: clock['mono'], sleep=lambda _: None))
    client = transport.BoundedTransport('http://127.0.0.1', paths=['/'], allowed_ips=['127.0.0.1'],
                                        budgets={'max_duration_seconds': 120}, lease_expires_at=1100.0)
    assert client.remaining_seconds() == 100
    clock.update(wall=900, mono=51)
    assert client.remaining_seconds() == 99
    clock.update(wall=1200, mono=52)
    assert client.remaining_seconds() <= 0


@pytest.mark.parametrize('response_failed', [False, True])
def test_cleanup_failure_always_closes_connection_and_preserves_safe_error(monkeypatch, response_failed):
    response = Mock(status=200)
    response.getheaders.return_value = []
    response.read1.side_effect = (transport.TransportError('Response exceeds byte budget')
                                  if response_failed else [b''])
    response.close.side_effect = RuntimeError('private cleanup diagnostic')
    connection = Mock(sock=None)
    connection.getresponse.return_value = response
    monkeypatch.setattr(transport, '_PinnedHTTP', Mock(return_value=connection))
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *_args, **_kwargs:
                        [(2, 1, 6, '', ('127.0.0.1', 80))])
    client = transport.BoundedTransport('http://127.0.0.1', paths=['/'], allowed_ips=['127.0.0.1'])
    with pytest.raises(transport.TransportError) as caught:
        client.request('GET', 'http://127.0.0.1/')
    connection.close.assert_called_once()
    assert 'private cleanup diagnostic' not in str(caught.value)
    if response_failed:
        assert str(caught.value) == 'Response exceeds byte budget'
