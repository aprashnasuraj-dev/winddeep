"""Offline Rapyd scope / precedence regression tests."""
from scripts.audit import rapyd_scope as scope

def test_config_and_snapshot():
    scope.self_test()

def test_no_official_authorization_implied_by_mirror():
    for host in ("api.rapyd.net", "checkout.rapyd.net", "a.rapyd.org"):
        s=scope.classify(host)
        assert s["candidate"] and not s["live_allowed"]

def test_exclusion_wins_wildcard():
    for host in ("support.rapyd.net", "docs.rapyd.net", "sandbox.rapyd.net"):
        assert scope.classify(host)["status"]=="OUT_OF_SCOPE"

def test_suffix_apex_and_credentials_fail():
    for host in ("rapyd.com","rapyd.net","korta.is","api.rapyd.net.evil.org",
                 "http://api.rapyd.net","https://u:p@api.rapyd.net",
                 "https://api.rapyd.net:444","api_rapyd.net","a.rápyd.net"):
        assert not scope.classify(host)["candidate"],host
