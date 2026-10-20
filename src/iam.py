"""Seven years of AWS managed IAM policies: growth, wildcards and privilege-escalation permissions.

Source: the MAMIP/IAMTrail archive (https://github.com/z0ph/MAMIP), which commits every change to every AWS managed
policy's default version, daily since February 2019.

S1  Snapshots on 1 June each year 2019-2026 (and the latest): policy count, actions, wildcard use, Resource "*".
S2  Change events: every commit that modified a policy, classified as expansion (adds grants), contraction (removes),
    or both, using the set of action patterns in Allow statements.
S3  Privilege escalation: which attachable managed policies grant actions from the published IAM privilege-escalation
    method list, unconditionally on all resources, and how that set changed over time.
"""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT / "mamip"
RES = ROOT / "results"
RES.mkdir(exist_ok=True)

# Actions used by the IAM privilege-escalation methods catalogued by Rhino Security Labs (Gietzen, 2018).
PRIVESC = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:CreateAccessKey", "iam:CreateLoginProfile",
           "iam:UpdateLoginProfile", "iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy",
           "iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy", "iam:AddUserToGroup",
           "iam:UpdateAssumeRolePolicy", "iam:PassRole", "lambda:UpdateFunctionCode", "glue:UpdateDevEndpoint"]


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, check=True).stdout


def statements(doc: dict) -> list[dict]:
    st = doc.get("Statement", [])
    return st if isinstance(st, list) else [st]


def as_list(x) -> list[str]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def analyse_doc(doc: dict) -> dict:
    allow = [s for s in statements(doc) if s.get("Effect") == "Allow"]
    actions = [a for s in allow for a in as_list(s.get("Action"))]
    full = any(a == "*" for a in actions)
    service_wild = sum(1 for a in actions if re.fullmatch(r"[\w-]+:\*", a))
    partial_wild = sum(1 for a in actions if "*" in a and a != "*" and not re.fullmatch(r"[\w-]+:\*", a))
    not_action = any("NotAction" in s for s in allow)
    res_star = sum(1 for s in allow if "*" in as_list(s.get("Resource")))
    # Privilege-escalation actions granted on all resources with no condition.
    unconditional = [s for s in allow if "*" in as_list(s.get("Resource")) and not s.get("Condition")]
    pats = [a.lower() for s in unconditional for a in as_list(s.get("Action"))]
    pe = sorted({p for p in PRIVESC if any(fnmatch.fnmatchcase(p.lower(), x) for x in pats)})
    services = {a.split(":")[0] for a in actions if ":" in a}
    return {"n_statements": len(statements(doc)), "n_actions": len(actions), "full_admin": full,
            "service_wildcards": service_wild, "partial_wildcards": partial_wild, "not_action": not_action,
            "allow_statements": len(allow), "resource_star_statements": res_star, "services": len(services),
            "privesc": ";".join(pe), "n_privesc": len(pe), "actions_set": sorted(set(actions))}


def load_meta() -> dict:
    meta = json.loads((REPO / "policies-list.json").read_text())["Policies"]
    return {m["PolicyName"]: m for m in meta}


def snapshot(rev: str) -> pd.DataFrame:
    names = [ln.split("\t")[1].split("/", 1)[1] for ln in git("ls-tree", rev, "policies/").splitlines()]
    rows = []
    for nm in names:
        try:
            d = json.loads(git("show", f"{rev}:policies/{nm}"))
            doc = d["PolicyVersion"]["Document"]
            if isinstance(doc, str):
                doc = json.loads(doc)
        except Exception:
            continue
        r = analyse_doc(doc)
        r["policy"] = nm
        r["version"] = d["PolicyVersion"].get("VersionId")
        rows.append(r)
    return pd.DataFrame(rows)


def main():
    meta = load_meta()
    kind = {n: ("service-linked" if m.get("Path", "").startswith("/aws-service-role/") else
                "service-role" if m.get("Path", "").startswith("/service-role/") else
                "job-function" if m.get("Path", "").startswith("/job-function/") else "other") for n, m in meta.items()}
    head = git("rev-parse", "HEAD").strip()
    snaps = {}
    for y in range(2019, 2027):
        rev = git("rev-list", "-1", f"--before={y}-06-01", "HEAD").strip()
        if rev:
            snaps[f"{y}-06-01"] = rev
    snaps["latest"] = head
    rows = []
    per_policy = {}
    for label, rev in snaps.items():
        df = snapshot(rev)
        df["kind"] = df.policy.map(kind).fillna("unknown (removed)")
        per_policy[label] = df
        rows.append({"snapshot": label, "policies": len(df), "actions_total": int(df.n_actions.sum()),
                     "median_actions": float(df.n_actions.median()), "p95_actions": float(df.n_actions.quantile(0.95)),
                     "full_admin": int(df.full_admin.sum()),
                     "with_service_wildcard": int((df.service_wildcards > 0).sum()),
                     "with_partial_wildcard": int((df.partial_wildcards > 0).sum()),
                     "with_not_action": int(df.not_action.sum()),
                     "share_allow_stmt_resource_star": float(df.resource_star_statements.sum() / max(1, df.allow_statements.sum())),
                     "with_privesc": int((df.n_privesc > 0).sum()),
                     "with_privesc_attachable": int(((df.n_privesc > 0) & df.kind.isin(["other", "job-function", "service-role"])).sum())})
        print(label, rows[-1], flush=True)
    pd.DataFrame(rows).to_csv(RES / "snapshots.csv", index=False)
    latest = per_policy["latest"]
    latest.drop(columns=["actions_set"]).to_csv(RES / "latest_policies.csv", index=False)

    # Growth of policies present in both 2020 and latest.
    a, b = per_policy.get("2020-06-01"), latest
    if a is not None:
        m = a[["policy", "n_actions", "service_wildcards", "n_privesc"]].merge(
            b[["policy", "n_actions", "service_wildcards", "n_privesc", "kind"]], on="policy", suffixes=("_2020", "_now"))
        m.to_csv(RES / "growth_2020_now.csv", index=False)

    # S2: change events.
    log = git("log", "--reverse", "--format=@%H %cs", "--name-status", "--", "policies/")
    events, cur = [], None
    for ln in log.splitlines():
        if ln.startswith("@"):
            h, date = ln[1:].split()
            cur = (h, date)
        elif ln and cur and ln[0] in "AMD":
            st, path = ln.split("\t")[0], ln.split("\t")[-1]
            events.append((cur[0], cur[1], st[0], path.split("/", 1)[1]))
    out = []
    for h, date, st, nm in events:
        if st != "M":
            out.append({"commit": h, "date": date, "status": st, "policy": nm})
            continue
        try:
            new = json.loads(git("show", f"{h}:policies/{nm}"))["PolicyVersion"]["Document"]
            old = json.loads(git("show", f"{h}^:policies/{nm}"))["PolicyVersion"]["Document"]
            if isinstance(new, str):
                new = json.loads(new)
            if isinstance(old, str):
                old = json.loads(old)
        except Exception:
            continue
        na, oa = analyse_doc(new), analyse_doc(old)
        added = set(na["actions_set"]) - set(oa["actions_set"])
        removed = set(oa["actions_set"]) - set(na["actions_set"])
        pe_new = set(filter(None, na["privesc"].split(";"))) - set(filter(None, oa["privesc"].split(";")))
        out.append({"commit": h, "date": date, "status": "M", "policy": nm, "added": len(added), "removed": len(removed),
                    "added_wildcards": sum("*" in x for x in added), "privesc_gained": ";".join(sorted(pe_new)),
                    "actions_before": oa["n_actions"], "actions_after": na["n_actions"],
                    "rstar_before": oa["resource_star_statements"], "rstar_after": na["resource_star_statements"]})
    ev = pd.DataFrame(out)
    ev["kind"] = ev.policy.map(kind).fillna("unknown (removed)")
    ev.to_csv(RES / "events.csv", index=False)
    print(ev.status.value_counts().to_dict())


if __name__ == "__main__":
    main()
