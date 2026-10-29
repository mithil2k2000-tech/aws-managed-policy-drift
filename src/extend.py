"""Extended analyses for the journal version.

E1  Effective permissions: expand every Allow action pattern against the archive's action registry (each action's first
    appearance in any managed policy), as of each snapshot date, to measure growth that happens through wildcards
    without any edit to the policy.
E2  Permissions-management actions (iam-dataset access level) granted unconditionally on all resources, over time.
E3  Direction of change by policy category (service-linked, service-role, job-function, other).
E4  Which services account for the added action patterns.
E5  "Read-only" policies and data access: sensitive data-read actions effectively granted by ReadOnlyAccess,
    ViewOnlyAccess and SecurityAudit, 2020 vs now.
E6  Update cadence: modifications per policy, time between substantive modifications.
"""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from iam import REPO, RES, as_list, git, load_meta, statements  # noqa: E402

REG = json.loads((REPO / "data" / "action-registry.json").read_text())["entries"]
CATALOG = {}  # lower-case action -> first-seen date (YYYY-MM-DD)
for k, v in REG.items():
    if k.startswith("act#"):
        CATALOG[k[4:]] = v["first_seen_at"][:10]
BY_SERVICE = defaultdict(list)
for a in CATALOG:
    BY_SERVICE[a.split(":")[0]].append(a)
PERM_MGMT = set(json.loads((REPO / "data" / "iam-metadata.json").read_text())["permissionsManagement"])

SENSITIVE_READ = ["s3:GetObject", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "secretsmanager:GetSecretValue",
                  "ssm:GetParameter", "ssm:GetParameters", "kms:Decrypt", "logs:GetLogEvents", "logs:FilterLogEvents",
                  "sqs:ReceiveMessage", "kinesis:GetRecords", "athena:GetQueryResults", "lambda:GetFunction",
                  "ec2:GetPasswordData", "codecommit:GetFile", "ecr:BatchGetImage", "rds:DownloadDBLogFilePortion",
                  "cloudformation:GetTemplate", "glue:GetConnection"]
READONLY = ["ReadOnlyAccess", "ViewOnlyAccess", "SecurityAudit"]


def expand(pattern: str, asof: str) -> set[str]:
    p = pattern.lower()
    if "*" not in p and "?" not in p:
        return {p}
    if p == "*":
        cands = CATALOG.keys()
    elif ":" in p and "*" not in p.split(":")[0] and "?" not in p.split(":")[0]:
        cands = BY_SERVICE.get(p.split(":")[0], [])
    else:
        cands = CATALOG.keys()
    return {a for a in cands if CATALOG[a] <= asof and fnmatch.fnmatchcase(a, p)}


def load_docs(rev: str) -> dict[str, dict]:
    out = {}
    for ln in git("ls-tree", rev, "policies/").splitlines():
        nm = ln.split("\t")[1].split("/", 1)[1]
        try:
            d = json.loads(git("show", f"{rev}:policies/{nm}"))["PolicyVersion"]["Document"]
            out[nm] = json.loads(d) if isinstance(d, str) else d
        except Exception:
            pass
    return out


def effective(doc: dict, asof: str) -> tuple[set[str], set[str], bool]:
    """Effective allowed actions (all statements), unconditional-on-* actions, and whether NotAction is used."""
    eff, uncond, notact = set(), set(), False
    for s in statements(doc):
        if s.get("Effect") != "Allow":
            continue
        if "NotAction" in s:
            notact = True
            continue
        acts = set()
        for a in as_list(s.get("Action")):
            acts |= expand(a, asof)
        eff |= acts
        if "*" in as_list(s.get("Resource")) and not s.get("Condition"):
            uncond |= acts
    return eff, uncond, notact


def main():
    meta = load_meta()
    kind = {n: ("service-linked" if m.get("Path", "").startswith("/aws-service-role/") else
                "service-role" if m.get("Path", "").startswith("/service-role/") else
                "job-function" if m.get("Path", "").startswith("/job-function/") else "other") for n, m in meta.items()}
    revs = {}
    for y in range(2020, 2027):
        revs[f"{y}-06-01"] = git("rev-list", "-1", f"--before={y}-06-01", "HEAD").strip()
    revs["2026-10-15"] = git("rev-parse", "HEAD").strip()
    facts = {}

    # E1, E2, E5 per snapshot.
    snap_rows, per = [], {}
    for label, rev in revs.items():
        asof = label
        docs = load_docs(rev)
        rows = []
        for nm, doc in docs.items():
            explicit = {a.lower() for s in statements(doc) if s.get("Effect") == "Allow" for a in as_list(s.get("Action"))}
            eff, unc, notact = effective(doc, asof)
            rows.append({"policy": nm, "kind": kind.get(nm, "removed"), "explicit": len(explicit), "effective": len(eff),
                         "wild": any("*" in a for a in explicit), "not_action": notact,
                         "perm_mgmt_uncond": len(unc & PERM_MGMT), "eff_set": eff})
        df = pd.DataFrame(rows)
        per[label] = df
        attachable = df.kind.isin(["other", "job-function"])
        snap_rows.append({"snapshot": label, "policies": len(df), "explicit_total": int(df.explicit.sum()),
                          "effective_total": int(df.effective.sum()), "catalog_size": sum(1 for d in CATALOG.values() if d <= asof),
                          "perm_mgmt_uncond_policies": int((df.perm_mgmt_uncond > 0).sum()),
                          "perm_mgmt_uncond_attachable": int(((df.perm_mgmt_uncond > 0) & attachable).sum()),
                          "perm_mgmt_uncond_jobfn": int(((df.perm_mgmt_uncond > 0) & (df.kind == "job-function")).sum())})
        print(snap_rows[-1], flush=True)
    sn = pd.DataFrame(snap_rows)
    sn.to_csv(RES / "ext_snapshots.csv", index=False)
    facts["snapshots"] = snap_rows

    # Cohort: policies present in 2020 and now, explicit vs effective growth; silent growth (no edit at all).
    a, b = per["2020-06-01"].set_index("policy"), per["2026-10-15"].set_index("policy")
    common = a.index.intersection(b.index)
    ver_a = {nm: json.loads(git("show", f"{revs['2020-06-01']}:policies/{nm}"))["PolicyVersion"].get("VersionId") for nm in common}
    ver_b = {nm: json.loads(git("show", f"{revs['2026-10-15']}:policies/{nm}"))["PolicyVersion"].get("VersionId") for nm in common}
    coh = pd.DataFrame({"explicit_2020": a.loc[common, "explicit"], "explicit_now": b.loc[common, "explicit"],
                        "effective_2020": a.loc[common, "effective"], "effective_now": b.loc[common, "effective"],
                        "wild": b.loc[common, "wild"], "kind": b.loc[common, "kind"]})
    coh["unchanged_version"] = [ver_a[n] == ver_b[n] for n in common]
    coh.to_csv(RES / "ext_cohort.csv")
    silent = coh[coh.unchanged_version]
    facts["cohort"] = {
        "n": int(len(coh)),
        "explicit": [int(coh.explicit_2020.sum()), int(coh.explicit_now.sum())],
        "effective": [int(coh.effective_2020.sum()), int(coh.effective_now.sum())],
        "unchanged_n": int(len(silent)),
        "unchanged_with_wild": int(silent.wild.sum()),
        "unchanged_grew_effective": int((silent.effective_now > silent.effective_2020).sum()),
        "unchanged_effective_gain": int((silent.effective_now - silent.effective_2020).clip(lower=0).sum()),
        "grew_effective_pct": round(float((coh.effective_now > coh.effective_2020).mean() * 100), 1),
        "shrank_effective_pct": round(float((coh.effective_now < coh.effective_2020).mean() * 100), 1),
    }
    top_silent = silent.assign(gain=silent.effective_now - silent.effective_2020).sort_values("gain", ascending=False).head(8)
    facts["top_silent"] = {n: [int(r.effective_2020), int(r.effective_now)] for n, r in top_silent.iterrows()}

    # E5: read-only policies and sensitive data reads.
    ro = {}
    for nm in READONLY:
        ro[nm] = {}
        for lab in ("2020-06-01", "2026-10-15"):
            d = per[lab].set_index("policy")
            if nm in d.index:
                eff = d.loc[nm, "eff_set"]
                ro[nm][lab] = {"effective": len(eff), "sensitive": sorted(x for x in SENSITIVE_READ if x.lower() in eff)}
    facts["readonly"] = ro

    # E3, E4, E6 from change events.
    ev = pd.read_csv(RES / "events.csv")
    m = ev[ev.status == "M"].copy()
    m["dir"] = "neutral"
    m.loc[(m.added > 0) & (m.removed == 0), "dir"] = "expand"
    m.loc[(m.added == 0) & (m.removed > 0), "dir"] = "contract"
    m.loc[(m.added > 0) & (m.removed > 0), "dir"] = "both"
    sub = m[m.dir != "neutral"]
    bykind = sub.groupby("kind").dir.value_counts().unstack(fill_value=0)
    bykind["total"] = bykind.sum(axis=1)
    bykind["expand_share"] = (bykind.get("expand", 0) / bykind.total).round(3)
    bykind.to_csv(RES / "ext_direction_by_kind.csv")
    facts["direction_by_kind"] = bykind.reset_index().to_dict(orient="records")

    # E4: services of added patterns (requires re-diffing; use per-commit action sets).
    svc = Counter()
    for h, nm in sub[["commit", "policy"]].itertuples(index=False):
        try:
            new = json.loads(git("show", f"{h}:policies/{nm}"))["PolicyVersion"]["Document"]
            old = json.loads(git("show", f"{h}^:policies/{nm}"))["PolicyVersion"]["Document"]
            new = json.loads(new) if isinstance(new, str) else new
            old = json.loads(old) if isinstance(old, str) else old
        except Exception:
            continue
        acts = lambda d: {a for s in statements(d) if s.get("Effect") == "Allow" for a in as_list(s.get("Action"))}
        for a in acts(new) - acts(old):
            svc[a.split(":")[0].lower() if ":" in a else "*"] += 1
    facts["top_services_added"] = svc.most_common(15)
    facts["services_with_additions"] = len(svc)

    # E6: cadence.
    per_pol = sub.groupby("policy").size()
    facts["cadence"] = {"policies_with_substantive_change": int(per_pol.size),
                        "median_changes": float(per_pol.median()), "p90_changes": float(per_pol.quantile(0.9)),
                        "max_changes": [per_pol.idxmax(), int(per_pol.max())]}
    sub = sub.sort_values("date")
    gaps = sub.groupby("policy").date.apply(lambda s: pd.to_datetime(s).diff().dt.days.dropna()).reset_index(drop=True)
    facts["cadence"]["median_gap_days"] = float(gaps.median()) if len(gaps) else None
    by_year = sub.assign(y=sub.date.str[:4]).groupby("y").size().to_dict()
    facts["substantive_by_year"] = {k: int(v) for k, v in by_year.items()}

    (RES / "ext_facts.json").write_text(json.dumps(facts, indent=1, default=str))
    print(json.dumps({k: v for k, v in facts.items() if k != "snapshots"}, indent=1, default=str))


if __name__ == "__main__":
    main()
