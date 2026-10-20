# A one-way ratchet: seven years of change in AWS managed IAM policies

Longitudinal analysis of every AWS managed policy change recorded by the public
[MAMIP/IAMTrail](https://github.com/z0ph/MAMIP) archive since February 2019. Paper: [`paper/main.pdf`](paper/main.pdf).

* Managed policies grew from 515 (June 2019) to 1,667 (Oct 2026); listed actions grew 6.6× to 65,873.
* Of 2,992 modifications that changed granted actions, **91% only added**, 3% only removed; 28,632 grants added vs 1,796 removed.
* Policies present in 2020 doubled in size; 43% grew, 1% shrank.
* Changes widening statements to `Resource: "*"` outnumbered narrowing ones 13 to 1.
* The `DataScientist` and `SystemAdministrator` job-function policies grant `lambda:UpdateFunctionCode` on all resources;
  `AdministratorAccess-Amplify` gained six escalation actions in 2021.
* `AWSMcpServiceActionsFullAccess` (2025–26) allows `*` on `*`, gated only by `aws:IsMcpServiceAction`.

## Reproduce

```bash
git clone https://github.com/z0ph/MAMIP.git mamip
python src/iam.py        # about 15 minutes
python src/analyse.py
cd paper && latexmk -pdf main.tex
```

## AI assistance

An AI assistant (Claude, Anthropic) helped write analysis code and draft text. The author designed the study,
reviewed the code and results, and is responsible for the content.

## Licence

MIT (code). The MAMIP archive is GPL-3.0 and is not included.
