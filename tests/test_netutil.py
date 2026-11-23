import pytest

from amenhotep.core.netutil import (
    TargetError,
    is_random_mac,
    normalize_mac,
    parse_ip_addr,
    validate_target,
)


def test_normalize_mac():
    assert normalize_mac("B8-27-EB-00-00-01") == "b8:27:eb:00:00:01"
    assert normalize_mac("garbage") is None
    assert normalize_mac(None) is None


def test_random_mac_detection():
    assert is_random_mac("da:11:22:33:44:55")
    assert not is_random_mac("b8:27:eb:00:00:01")


@pytest.mark.parametrize("target", ["192.168.1.0/24", "10.0.0.0/16", "192.168.1.5"])
def test_valid_targets(target):
    validate_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.0/24",
        "10.0.0.0/8",
        "10.0.0.0/24; rm -rf /",
        "::1",
        "127.0.0.0/24",
        "224.0.0.0/24",
        "",
    ],
)
def test_rejected_targets(target):
    with pytest.raises(TargetError):
        validate_target(target)


def test_parse_ip_addr_skips_loopback_and_public():
    text = (
        "1: lo    inet 127.0.0.1/8 scope host lo\n"
        "5: wlp3s0    inet 192.168.178.97/24 brd 192.168.178.255 scope global wlp3s0\n"
        "6: eth0    inet 8.8.8.8/24 scope global eth0\n"
    )
    assert [str(n) for n in parse_ip_addr(text)] == ["192.168.178.0/24"]
