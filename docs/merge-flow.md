# How a PR reaches `main`

This page is for contributors. It explains how a pull request gets merged in this repository, what can stop it, and who can stop all merges. Nobody merges a PR by hand except the operator. Ordinary PRs are merged by the `auto-merge` workflow (`.github/workflows/merge.yml`), and only after it has worked out for itself that the PR passed review.

Each section names the file it describes. Those files on `main` are the authority. If this page and a file disagree, the file is right, and this page needs fixing.

## The path, in order

1. **Branch and push.** Work on a branch of this repository (PRs from forks never pass) and open a PR against `main`. Each push starts `ci.yml` on your branch.
2. **Wait for CI.** The verdict counts only a successful `push` run of `ci.yml` at your PR's head commit, on your PR's branch. `pull_request` runs do not count. If your branch changes `ci.yml` itself, no run counts, because the verdict requires your `ci.yml` to be identical to `main`'s.
3. **Add one weight label.** Exactly one of `weight:trivial`, `weight:standard` or `weight:heavy` (see [Weight](#weight)).
4. **Get the review records.** Every reviewer in the review set for your PR's weight posts a passing record that names your current head SHA (see [Review records](#review-records)).
5. **Add the `auto-merge` label last.** Add it only after every record for the current head is posted (see [Why the label goes last](#why-the-auto-merge-label-goes-last)).
6. **The workflow merges.** `merge.yml` recomputes the verdict at your head, checks the PR is not a 7a PR, re-reads the kill-switch label, waits for the `review-verdict` check, and squash-merges with `--match-head-commit <head>`, so it can only merge the commit that was reviewed.

If you push a new commit at any point, the head SHA changes. The records for the old SHA no longer count, and the review step starts again at the new head.

Sources: `.github/merge/merge.py` (module docstring, steps 1 to 8), `.github/verdict/verdict.py` (module docstring, conditions 0 to 5), `.github/workflows/ci.yml`.

## Weight

The PR must carry exactly one `weight:<tier>` label. No label, two labels, or an unknown tier fails the verdict.

The verdict also works out an objective weight from the diff and never accepts a label lighter than that:

| Objective weight | When |
|---|---|
| `trivial` | at most 49 changed lines (additions plus deletions) and 1 file |
| `standard` | more than 49 changed lines, or more than 1 file, and at most 500 changed lines |
| `heavy` | more than 500 changed lines, or any file on the security-boundary list (`heavy_paths`, matched case-insensitively), or a changed symlink or submodule, or a binary or mode-only change |

A rename counts both the old and the new path. If your label is lighter than the objective weight, the verdict fails. If it is heavier, the heavier review set applies.

Sources: `.github/verdict/verdict.py` (`declared_weight`, `recompute_weight`), `.github/verdict/config.json` (`weight_thresholds`, `heavy_paths`).

## Review records

### Who must review

| Weight | Review set |
|---|---|
| `trivial` | `pr-challenger` |
| `standard` | `pr-reviewer`, `pr-challenger` |
| `heavy` | `pr-reviewer`, `pr-challenger`, `wario` |

A reviewer that is also an author agent of the PR does not count. The author agents are the ones listed in `author_agents` in the config, plus any name given on an `Author-Agent: <name>` line in the PR body.

### What a record looks like

A record is one line in a PR comment, a submitted review body or an inline review comment. It starts in column 0 and uses the full 40-character SHA:

```text
VERDICT: pass reviewer=<agent> sha=<head sha>
VERDICT: fail reviewer=<agent> sha=<head sha>
CRITICAL: id=<id> reviewer=<agent> sha=<sha>
VERIFY: pass closes=<id> reviewer=<agent> sha=<fix sha>
```

For each reviewer in the set, the latest `VERDICT` at the current head must be `pass`.

The verdict ignores:

- records from anyone outside `trusted_record_authors` (`acardote-fleet[bot]` and `acardote`), whatever they say;
- lines inside fenced code, HTML comments or block quotes, and indented lines. The block above is an example, not a record.

### Criticals

A `CRITICAL` record blocks the merge until it is closed. Only a `VERIFY: pass` record closes it, and only when all of these hold:

- it comes from a reviewer agent that is not an author of the PR;
- its SHA is a later commit of the PR that descends from the critical's SHA.

An author's "fixed" comment closes nothing. If the critical's SHA is no longer a commit of the PR (after a rebase or force-push), no `VERIFY` can close it until the reviewer raises it again at a current SHA. Each critical id belongs to one reviewer; reusing it from another reviewer fails the verdict.

### Do not edit records

Any comment that holds a record and was edited after posting makes the verdict fail. Any edit of a comment by `acardote-fleet[bot]` fails it too, whatever the comment now says. To change your mind, post a new record. Do not edit the old one.

A line whose first word is `critical`, or that names critical next to an `id=`, `reviewer=` or `sha=` field, must be a well-formed live record. Otherwise the verdict fails as an "unparseable critical". The one exception is a line that states zero criticals, such as `Critical: none`. Keep prose like "no critical findings" from starting with the word critical.

Sources: `.github/verdict/verdict.py` (module docstring "Record formats" and "Edits", `VERDICT_RE`, `CRITICAL_RE`, `VERIFY_RE`, `open_criticals`, `author_agents_for`), `.github/verdict/config.json` (`review_sets`, `reviewer_agents`, `author_agents`, `trusted_record_authors`, `machine_record_authors`).

## Why the `auto-merge` label goes last

The `review-verdict` check (`verdict.yml`) runs on PR events only: opened, synchronize (a push), reopened, edited, labeled, unlabeled and ready_for_review. Posting a comment or a review is not one of these events, so the check shows the records as they stood at the last PR event.

`merge.yml` recomputes the verdict inline and does not trust the check. The `e5-main` ruleset, though, still requires a passing `review-verdict` check at merge time. If you add `auto-merge` before the records are in, the check stays red from that earlier event and the merge is refused (`MERGE-REFUSED ... kind=check-stale`). Adding the label after the records gives a fresh PR event, so the check and the inline verdict agree.

If a merge is refused this way, remove the `auto-merge` label and add it again. That is a new PR event, so `verdict.yml` runs again.

`merge.yml` starts on the `labeled` and `synchronize` events of PRs based on `main`, and every 5 minutes on a schedule. A PR that is labelled but not yet passing is picked up by a later run once it passes.

Sources: `.github/workflows/verdict.yml` (`on:`), `.github/workflows/merge.yml` (`on:`), `.github/merge/merge.py` (docstring step 7), `.github/rulesets/e5-main.json`, `docs/operator/apply-e5-main.md` section 7.

## What blocks a merge

`merge.yml` does not merge a PR if any of these holds. Most of them leave the workflow run green: the run did its job and correctly declined to merge.

**The verdict fails at the current head:**

- the PR is closed, is a draft, is not based on `main`, or comes from a fork;
- there is not exactly one weight label, or the label is lighter than the objective weight;
- a reviewer in the set has no `VERDICT` at the head, or the latest one is `fail`;
- a critical is open;
- there is no successful `push` run of `ci.yml` at the head, or the head's `ci.yml` differs from `main`'s;
- a record-bearing comment was edited, or there is an unparseable critical;
- the head moved while the verdict was being computed.

**The PR or the repository is not eligible:**

- the PR has no `auto-merge` label;
- it has the `do-not-auto-merge` label, or the `operator-merge` label;
- it touches a 7a path (see below);
- the `review-verdict` check at the head did not conclude `success` within the bounded wait;
- the head, the base or the labels changed between the checks and the merge call;
- the run reached its 600-second deadline before the merge call;
- the kill switch is off (see below).

**7a PRs never auto-merge.** A PR that changes any path in the 7a set is skipped, both sides of a rename and every deletion included. The same goes for any symlink or submodule change. The 7a set is the `floor_7a` list in `.github/merge/config.json` (it includes all of `.github/**`, `.claude/**`, agent definitions, `CLAUDE.md`, dependency manifests and lockfiles) plus whatever `merge.py` derives from the `derive_roots` on `main`. Label such a PR `operator-merge`. The operator merges it, and the ruleset still requires a passing `review-verdict` for that merge, which for a 7a PR usually means the heavy review set.

A red `auto-merge` run means something went wrong in the system itself: an API or git error, a refused merge, or a 7a derivation that could not be bounded (no PR merges until that is fixed). The run's `RUN-RESULT`, `SKIP ... outcome=error`, `MERGE-REFUSED` and `7A-DERIVE` lines say which.

Sources: `.github/verdict/verdict.py` (`compute_verdict`), `.github/merge/merge.py` (docstring steps 2 to 8, and the `skip(...)` reasons), `.github/merge/config.json`, `docs/operator/apply-e5-main.md` section 7.

## Kill switches

These are operator controls. Contributors and agents do not change them, and the agent policy forbids agents from touching them.

| Switch | Effect |
|---|---|
| Repository variable `AUTO_MERGE_ENABLED` | `merge.yml` merges only if it is exactly `true`. Any other value, or no variable, stops all auto-merges from the next run. A run reads it once at its start and makes no merge call after 600 seconds, which bounds how long an in-flight run can still merge. |
| `do-not-auto-merge` label | Stops one PR. `merge.yml` re-reads the labels immediately before the merge call. |
| Disable `merge.yml` and cancel its runs | Immediate stop: no new runs, and the current run ends. |
| Break-glass: disable the `e5-main` ruleset | Only when `main` is wedged (the verdict machinery itself is broken, so no PR, the fix included, can pass). The operator stops auto-merge first, merges the fix by hand, then re-enables the ruleset. |

The labels are flags, not authority: anyone with write access can add or remove them. The merge audit (`audit.yml`) checks every merge to `main` on a schedule and reports label and setting changes.

Sources: `.github/merge/merge.py` (docstring steps 2, 6 and 7, `RUN_DEADLINE_S`), `.github/merge/config.json` (`kill_label`), `docs/operator/apply-e5-main.md` (introduction and sections 5, 6 and 8).

## See also

- `docs/operator/apply-e5-main.md`: how the operator sets up and runs these controls.
- Design: `docs/design/merge-model.md` in acardote/personal-assistant-ultra.
