#!/usr/bin/env python3
"""Rapyd program scope: OFFLINE classifier, never makes network requests."""
import argparse
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[2]
POLICY=ROOT/"config/programs/rapyd_bugcrowd.json"
DNS=re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

def load():
    return json.loads(POLICY.read_text(encoding="utf-8"))

def hostname(value):
    if not isinstance(value,str) or not value.strip() or value.startswith("//"):
        raise ValueError("Empty/ambiguous asset")
    u=urlsplit(value if "://" in value else "https://"+value)
    if u.scheme!="https" or u.username is not None or u.password is not None or u.port not in (None,443):
        raise ValueError("HTTPS/credential/port policy violation")
    host=u.hostname
    if not host or not host.isascii() or host.endswith(".") or not DNS.fullmatch(host.lower()):
        raise ValueError("Invalid DNS host")
    host=host.lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Raw IP outside program")
    return host

def match(host,pattern):
    p=pattern.lower()
    return host.endswith(p[1:]) and host!=p[2:] if p.startswith("*.") else host==p

def classify(asset,policy=None):
    cfg=policy if policy is not None else load()
    try:
        host=hostname(asset)
    except ValueError as err:
        return {"host":None,"candidate":False,"live_allowed":False,"status":"INVALID_TARGET","reason":str(err)}
    excluded=[p for p in cfg["out_of_scope"] if p!="3rd party services" and match(host,p)]
    included=[p for p in cfg["in_scope"] if match(host,p)]
    candidate=bool(included and not excluded)
    a=cfg["authorization"]
    verified=all(a.get(k) is True for k in ("official_brief_verified","program_current_rules_verified","researcher_participation_verified","live_target_requests_enabled"))
    live=bool(candidate and verified)
    status="OUT_OF_SCOPE" if excluded else "UNKNOWN_OUT_OF_SCOPE" if not included else "SECONDARY_CANDIDATE_ONLY" if not live else "LOCAL_FLAGS_TRUE_RECONFIRM_OFFICIAL_POLICY"
    return {"host":host,"candidate":candidate,"live_allowed":live,"status":status,"included":included,"excluded":excluded,"redirects_authorized":False}

def self_test():
    p=load()
    assert len(p["in_scope"])==10 and len(p["out_of_scope"])==11
    assert p["authorization"]["live_target_requests_enabled"] is False
    for h in ["api.rapyd.net","dashboard.rapyd.net","verify.rapyd.net","checkout.rapyd.net","a.rapyd.net","b.rapyd.com","a.rapyd.org","a.korta.is","a.kortathjonustan.is","jointhemoment.net"]:
        r=classify(h,p)
        assert r["candidate"] and not r["live_allowed"],h
    for h in ["docs.rapyd.net","support.rapyd.net","community.rapyd.net","sandbox.rapyd.net","ghost.rapyd.net","a.neatcommerce.com","a.neattest.com","a.neat.com.hk","a.neat.hk","a.neat.wtf","korta.is","rapyd.com","api.rapyd.net.evil.example","http://api.rapyd.net","https://test@api.rapyd.net"]:
        assert not classify(h,p)["candidate"],h
    print("RAPYD_OFFLINE_SCOPE_OK; live testing disabled")

def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("asset",nargs="?")
    cli.add_argument("--self-test",action="store_true")
    args=cli.parse_args()
    if args.self_test:self_test()
    elif args.asset:print(json.dumps(classify(args.asset),sort_keys=True,indent=2))
    else:cli.error("Supply asset or --self-test")

if __name__=="__main__":
    main()
