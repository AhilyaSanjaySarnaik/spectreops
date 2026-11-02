# tests/unit/test_scope.py
import pytest
from spectreops.scope.policy import Policy
from spectreops.scope.validator import ScopeValidator, ScopeViolation


def make_validator(targets, offline=True, mode="active"):
    p = Policy(mode=mode, targets=targets, offline=offline)
    return ScopeValidator(p)


def test_in_scope_host_allowed():
    v = make_validator(["127.0.0.1"])
    assert v.check_host("127.0.0.1")


def test_out_of_scope_denied():
    v = make_validator(["127.0.0.1"])
    assert not v.check_host("example.com")
    with pytest.raises(ScopeViolation):
        v.check_url("http://example.com/")


def test_url_in_scope_passes():
    v = make_validator(["http://127.0.0.1:8080"])
    v.check_url("http://127.0.0.1:8080/login")   # should not raise


def test_exclusion_wins():
    v = make_validator(["10.0.0.0/24"], offline=False)
    v._denied_patterns = ["10.0.0.*"]
    assert not v.check_host("10.0.0.5")


def test_mode_none_blocks_everything():
    v = make_validator(["127.0.0.1"], mode="none")
    with pytest.raises(ScopeViolation):
        v.check_network_action("127.0.0.1", "safe")
