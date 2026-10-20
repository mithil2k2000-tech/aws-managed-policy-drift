"""Figures, tables and facts for the managed-policy paper."""
import json
from pathlib import Path

import matplotlib
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RES, FIG, TAB = ROOT / "results", ROOT / "paper" / "figures", ROOT / "paper" / "tables"
FIG.mkdir(parents=True, exist_ok=True)
TAB.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.size": 8, "font.family": "serif", "axes.spines.top": False, "axes.spines.right": False})

s = pd.read_csv(RES / "snapshots.csv")
s["label"] = s.snapshot.str[:4].where(s.snapshot != "latest", "Oct 2026")
e = pd.read_csv(RES / "events.csv")
m = e[e.status == "M"].copy()
m["year"] = m.date.str[:4]
m["type"] = m.apply(lambda r: "both" if r.added > 0 and r.removed > 0 else "expand" if r.added > 0
                    else "contract" if r.removed > 0 else "neutral", axis=1)
sub = m[m.type != "neutral"]
facts = {"snapshots": s.to_dict("records"), "modifications": int(len(m)), "substantive": int(len(sub)),
         "type_share": sub.type.value_counts(normalize=True).round(4).to_dict(),
         "type_counts": sub.type.value_counts().to_dict(),
         "added_actions": int(sub.added.sum()), "removed_actions": int(sub.removed.sum()),
         "events_adding_wildcards": int((sub.added_wildcards > 0).sum()),
         "rstar_up": int((m.rstar_after > m.rstar_before).sum()), "rstar_down": int((m.rstar_after < m.rstar_before).sum()),
         "privesc_gains": e[e.privesc_gained.fillna("") != ""][["date", "policy", "privesc_gained"]].to_dict("records"),
         "new_policies_by_year": e[e.status == "A"].assign(y=lambda x: x.date.str[:4]).groupby("y").size().to_dict()}
g = pd.read_csv(RES / "growth_2020_now.csv")
facts["cohort_2020"] = {"n": len(g), "grew": float((g.n_actions_now > g.n_actions_2020).mean()),
                        "shrank": float((g.n_actions_now < g.n_actions_2020).mean()),
                        "actions_2020": int(g.n_actions_2020.sum()), "actions_now": int(g.n_actions_now.sum())}
lat = pd.read_csv(RES / "latest_policies.csv")
facts["latest_full_wildcard"] = lat[lat.full_admin].policy.tolist()
facts["latest_privesc"] = lat[lat.n_privesc > 0][["policy", "kind", "privesc"]].to_dict("records")
(RES / "facts.json").write_text(json.dumps(facts, indent=1, default=str))

fig, axes = plt.subplots(1, 2, figsize=(6.8, 2.4))
ax = axes[0]
ax.plot(s.label, s.policies, marker="o", ms=3, color="#1f4e79", label="managed policies")
ax.set_ylabel("Policies")
ax2 = ax.twinx()
ax2.plot(s.label, s.actions_total / 1000, marker="s", ms=3, color="#c0504d", label="actions listed (thousands)")
ax2.set_ylabel("Actions listed (thousands)")
ax2.spines["top"].set_visible(False)
ax.tick_params(axis="x", rotation=45, labelsize=6)
h1, l1 = ax.get_legend_handles_labels()
h2, l2 = ax2.get_legend_handles_labels()
ax.legend(h1 + h2, l1 + l2, fontsize=6, frameon=False, loc="upper left")
ax = axes[1]
t = sub.groupby(["year", "type"]).size().unstack(fill_value=0).reindex(columns=["expand", "both", "contract"], fill_value=0)
bottom = None
for col, c in zip(t.columns, ["#c0504d", "#bdbdbd", "#2e8b57"]):
    ax.bar(t.index, t[col], bottom=bottom, color=c, label={"expand": "adds actions only", "both": "adds and removes",
                                                            "contract": "removes actions only"}[col])
    bottom = t[col] if bottom is None else bottom + t[col]
ax.set_ylabel("Policy changes")
ax.tick_params(axis="x", rotation=45, labelsize=6)
ax.legend(fontsize=6, frameon=False)
fig.tight_layout()
fig.savefig(FIG / "growth.pdf")

rows = []
for _, r in s.iterrows():
    rows.append({"Snapshot": r.label, "Policies": r.policies, "Actions listed": f"{r.actions_total:,}",
                 "Median": int(r.median_actions), "95th pct.": f"{r.p95_actions:.0f}",
                 "Service wildcard": r.with_service_wildcard, "Allow stmts on \\texttt{*}": f"{r.share_allow_stmt_resource_star * 100:.0f}\\%"})
(TAB / "snapshots.tex").write_text(
    "\\begin{table}[t]\n\\centering\n\\caption{AWS managed policies on 1 June each year and in October 2026: count, actions listed "
    "in Allow statements (total, median and 95th percentile per policy), policies using a whole-service wildcard such as "
    "\\texttt{s3:*}, and the share of Allow statements whose resource is \\texttt{*}.}\n\\label{tab:snap}\n\\small\n"
    "\\setlength{\\tabcolsep}{3.5pt}\n" + pd.DataFrame(rows).to_latex(index=False, escape=False, column_format="lrrrrrr") + "\\end{table}\n")
print(json.dumps({k: v for k, v in facts.items() if k not in ("snapshots", "latest_privesc")}, indent=1, default=str)[:2500])
