"""A tiny SYNTHETIC directory for access tests: it produces the recorded FreeIPA API answers a replay needs.

The hbactest answer it records follows FreeIPA's documented semantics (enabled rules; category all, a listed name,
or a direct/indirect group). It is test scaffolding only: the product never decides with it, and the live lab
(docs/truth/access-truth-matrix.md) is what checks real FreeIPA behaviour.
"""

from __future__ import annotations

import collections
import json
import pathlib
from typing import Dict, Iterable, List, Optional, Set


def _ancestors(start: Iterable[str], parents: Dict[str, List[str]]) -> Set[str]:
    seen: Set[str] = set()
    queue = collections.deque(start)
    while queue:
        g = queue.popleft()
        if g in seen:
            continue
        seen.add(g)
        queue.extend(parents.get(g, []))
    return seen


def ok(result: dict) -> dict:
    return {"error": None, "result": result, "id": 0, "principal": "admin@LAB.TEST", "version": "4.13.3"}


def not_found(what: str) -> dict:
    return {"error": {"code": 4001, "name": "NotFound", "message": f"{what}: not found"}, "result": None}


class World:
    def __init__(self) -> None:
        self.users: Dict[str, dict] = {}
        self.user_groups: Dict[str, List[str]] = {}
        self.group_parents: Dict[str, List[str]] = {}
        self.hosts: Dict[str, dict] = {}
        self.host_groups: Dict[str, List[str]] = {}
        self.hostgroup_parents: Dict[str, List[str]] = {}
        self.services: Dict[str, List[str]] = {}
        self.rules: List[dict] = []
        self.meta = {"server": "ipa01.lab.test", "domain": "lab.test", "realm": "LAB.TEST",
                     "principal": "admin@LAB.TEST", "api_version": "2.254", "note": "SYNTHETIC test fixture"}
        self.overrides: Dict[tuple, dict] = {}
        self.hbactest_override: Optional[dict] = None

    # ---------------------------------------------------------------- building
    def user(self, name: str, groups: Iterable[str] = (), **attrs) -> "World":
        self.users[name] = attrs
        self.user_groups[name] = list(groups)
        return self

    def group(self, name: str, parents: Iterable[str] = ()) -> "World":
        self.group_parents[name] = list(parents)
        return self

    def host(self, fqdn: str, hostgroups: Iterable[str] = (), **attrs) -> "World":
        self.hosts[fqdn] = attrs
        self.host_groups[fqdn] = list(hostgroups)
        return self

    def hostgroup(self, name: str, parents: Iterable[str] = ()) -> "World":
        self.hostgroup_parents[name] = list(parents)
        return self

    def service(self, name: str, groups: Iterable[str] = ()) -> "World":
        self.services[name] = list(groups)
        return self

    def rule(self, name: str, enabled: bool = True, users=(), groups=(), usercat=False, hosts=(), hostgroups=(),
             hostcat=False, services=(), svcgroups=(), servicecat=False) -> "World":
        self.rules.append(dict(name=name, enabled=enabled, users=list(users), groups=list(groups), usercat=usercat,
                               hosts=list(hosts), hostgroups=list(hostgroups), hostcat=hostcat,
                               services=list(services), svcgroups=list(svcgroups), servicecat=servicecat))
        return self

    # ---------------------------------------------------------------- answers
    def _user_all_groups(self, u: str) -> Set[str]:
        return _ancestors(self.user_groups.get(u, []), self.group_parents)

    def _host_all_groups(self, h: str) -> Set[str]:
        return _ancestors(self.host_groups.get(h, []), self.hostgroup_parents)

    def rule_entry(self, r: dict) -> dict:
        e = {"cn": [r["name"]], "ipaenabledflag": [r["enabled"]]}
        for cat, key in (("usercat", "usercategory"), ("hostcat", "hostcategory"), ("servicecat", "servicecategory")):
            if r[cat]:
                e[key] = ["all"]
        for k, attr in (("users", "memberuser_user"), ("groups", "memberuser_group"), ("hosts", "memberhost_host"),
                        ("hostgroups", "memberhost_hostgroup"), ("services", "memberservice_hbacsvc"),
                        ("svcgroups", "memberservice_hbacsvcgroup")):
            if r[k]:
                e[attr] = r[k]
        return e

    def _matches(self, r: dict, user: str, host: str, svc: str) -> bool:
        ug, hg, sg = self._user_all_groups(user), self._host_all_groups(host), set(self.services.get(svc, []))
        u = r["usercat"] or user in r["users"] or bool(ug & set(r["groups"]))
        h = r["hostcat"] or host in r["hosts"] or bool(hg & set(r["hostgroups"]))
        s = r["servicecat"] or svc in r["services"] or bool(sg & set(r["svcgroups"]))
        return u and h and s

    def hbactest(self, user: str, host: str, svc: str) -> dict:
        enabled = [r for r in self.rules if r["enabled"]]
        matched = [r["name"] for r in enabled if self._matches(r, user, host, svc)]
        notmatched = [r["name"] for r in enabled if r["name"] not in matched]
        return {"summary": f"Access granted: {bool(matched)}", "value": bool(matched), "matched": matched or None,
                "notmatched": notmatched or None, "error": None, "warning": None}

    def calls(self, user: str, host: str, svc: str) -> List[dict]:
        out = []
        for u, attrs in self.users.items():
            direct = self.user_groups[u]
            ind = sorted(self._user_all_groups(u) - set(direct))
            rules_d = [r["name"] for r in self.rules if u in r["users"]]
            rules_i = [r["name"] for r in self.rules if self._user_all_groups(u) & set(r["groups"])]
            entry = {"uid": [u], "nsaccountlock": attrs.get("disabled", False), "memberof_group": direct}
            if "nsaccountlock_absent" in attrs:
                del entry["nsaccountlock"]
            if ind:
                entry["memberofindirect_group"] = ind
            if rules_d:
                entry["memberof_hbacrule"] = rules_d
            if rules_i:
                entry["memberofindirect_hbacrule"] = rules_i
            for k in ("krbprincipalexpiration", "krbpasswordexpiration"):
                if k in attrs:
                    entry[k] = [{"__datetime__": attrs[k]}]
            out.append({"method": "user_show", "args": [u], "response": ok({"result": entry, "value": u})})
        for h, attrs in self.hosts.items():
            direct = self.host_groups[h]
            ind = sorted(self._host_all_groups(h) - set(direct))
            entry = {"fqdn": [h], "has_keytab": attrs.get("has_keytab", True), "memberof_hostgroup": direct}
            if ind:
                entry["memberofindirect_hostgroup"] = ind
            rd = [r["name"] for r in self.rules if h in r["hosts"]]
            ri = [r["name"] for r in self.rules if self._host_all_groups(h) & set(r["hostgroups"])]
            if rd:
                entry["memberof_hbacrule"] = rd
            if ri:
                entry["memberofindirect_hbacrule"] = ri
            out.append({"method": "host_show", "args": [h], "response": ok({"result": entry, "value": h})})
        for s, groups in self.services.items():
            entry = {"cn": [s]}
            if groups:
                entry["memberof_hbacsvcgroup"] = groups
            rd = [r["name"] for r in self.rules if s in r["services"]]
            if rd:
                entry["memberof_hbacrule"] = rd
            out.append({"method": "hbacsvc_show", "args": [s], "response": ok({"result": entry, "value": s})})
        for g, parents in self.group_parents.items():
            out.append({"method": "group_show", "args": [g],
                        "response": ok({"result": {"cn": [g], "memberof_group": parents}, "value": g})})
        for g, parents in self.hostgroup_parents.items():
            out.append({"method": "hostgroup_show", "args": [g],
                        "response": ok({"result": {"cn": [g], "memberof_hostgroup": parents}, "value": g})})
        for r in self.rules:
            out.append({"method": "hbacrule_show", "args": [r["name"]],
                        "response": ok({"result": self.rule_entry(r), "value": r["name"]})})
        out.append({"method": "hbactest", "args": [],
                    "response": ok(self.hbactest_override if self.hbactest_override is not None else self.hbactest(user, host, svc))})
        keyed = {(c["method"], tuple(a.lower() for a in c["args"])): c for c in out}
        for key, resp in self.overrides.items():
            keyed[key] = {"method": key[0], "args": list(key[1]), **resp}
        return list(keyed.values())

    def write(self, directory: pathlib.Path, user: str, host: str, svc: str) -> pathlib.Path:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "access_api.json").write_text(
            json.dumps({"meta": self.meta, "calls": self.calls(user, host, svc)}, indent=1), encoding="utf-8")
        return directory
