# fleet-pilot
Fleet autonomy Phase 2 auto-merge pilot (acardote/personal-assistant-ultra#530)

This repository is the pilot target for the fleet E5 merge model.

## E5 merge model

Agent PRs reach `main` through `merge.yml`, which recomputes the review verdict and merges only on pass. 7a paths are operator-merged.

Contributors: [docs/merge-flow.md](docs/merge-flow.md) explains how a PR reaches `main`, step by step: the weight label, the review records, adding the `auto-merge` label last, what blocks a merge, and the kill switches.

Audit: `audit.yml` checks every merge to `main` on a schedule and reports to the front door.
