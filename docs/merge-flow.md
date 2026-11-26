# How a PR reaches `main`

This page is for anyone who opens PRs here: fleet agents, the operator, and anyone else with write access. It explains how a pull request gets merged, what can stop it, and who can stop all merges. Nobody merges an ordinary PR by hand. The `auto-merge` workflow (`.github/workflows/merge.yml`) merges it, and only after it has worked out for itself that the PR passed review.

Two things to know up front:

- **Only two GitHub logins can post review records that count:** `acardote-fleet[bot]` and `acardote` (`trusted_record_authors`). If you are neither, ask the fleet or the operator to post them.
- **PRs from forks never pass.** Push your branch to this repository.

Each section names the file it describes. Those files on `main` are the authority. If this page and a file disagree, the file is right, and this page needs fixing.

## The path, in order

1. **Branch and push.** Push a branch of this repository and open a PR against `main`. Each push starts `ci.yml` on your branch.
2. **Wait for CI.** The verdict counts only `push` runs of `ci.yml` at your PR's head commit on your PR's branch, and the latest such run must have succeeded. `pull_request` runs do not count. If your branch changes `ci.yml` itself, no run counts, because the verdict requires your `ci.yml` to be identical to `main`'s.
3. **Add one weight label.** Exactly one of `weight:trivial`, `weight:standard` or `weight:heavy` (see [Weight](#weight)).
4. **Get the review records.** Every reviewer in the review set for your PR's weight gets a passing record posted that names your current head SHA, by one of the two trusted logins (see [Review records](#review-records)).
5. **Add the `auto-merge` label last.** Add it only after every record for the current head is posted (see [Why the label goes last](#why-the-auto-merge-label-goes-last)).
6. **The workflow merges.** `merge.yml` recomputes the verdict at your head, checks that the PR is not a 7a PR, waits for the `review-verdict` check to succeed at your head, re-reads the labels, and squash-merges with `--match-head-commit <head>`. It can only merge the commit that was reviewed.

**If you push again**, the head SHA changes. `VERDICT` records for the old SHA no longer count, CI must pass again, and the review step starts again at the new head. An open `CRITICAL` keeps blocking across pushes until it is closed (see [Criticals](#criticals)). The `auto-merge` label stays on through a push, and the push itself re-runs the `review-verdict` check before the new records exist, so that check fails. After the new records are posted, remove `auto-merge` and add it again. Alternatively, remove the label before you push.

**If the PR conflicts with `main`**, the fix is a new push, with everything above. For any other refused merge, read the `MERGE-REFUSED` reason first: the next scheduled run recomputes everything and retries, so push only if the reason is about your code. The ruleset does not require your branch to be up to date with `main` (`strict_required_status_checks_policy` is `false`), and CI is evidence about your head commit alone, not about it merged with `main`.

Sources: `.github/merge/merge.py` (module docstring, steps 1 to 8), `.github/verdict/verdict.py` (module docstring, conditions 0 to 5), `.github/workflows/ci.yml`, `.github/workflows/verdict.yml`, `.github/rulesets/e5-main.json`.

## Weight

The PR must carry exactly one `weight:<tier>` label. No label, two labels, or an unknown tier fails the verdict.

The verdict also works out an objective weight from the diff and never accepts a label lighter than that:

| Objective weight | When |
|---|---|
| `trivial` | at most 49 changed lines (additions plus deletions) and 1 file |
| `standard` | more than 49 changed lines, or more than 1 file, and at most 500 changed lines |
| `heavy` | more than 500 changed lines; or any changed file on the security-boundary list (`heavy_paths`); or a changed symlink or submodule; or any added or modified file with no patch and 0 changed lines (a binary file, a mode-only change, a pure rename, an empty new file); or any symlink anywhere in the tree at a `heavy_paths` location |

A rename counts both the old and the new path, so a one-file rename is at least `standard`, and a rename with no edits is `heavy`. `heavy_paths` is matched case-insensitively after Unicode normalisation. One pattern there, `**/*lock*`, matches any file with "lock" in its name (for example `clock.py`); the same pattern is also in the 7a floor list, so such a PR never auto-merges either.

If your label is lighter than the objective weight, the verdict fails. If it is heavier, the heavier review set applies.

Sources: `.github/verdict/verdict.py` (`declared_weight`, `recompute_weight`), `.github/verdict/config.json` (`weight_thresholds`, `heavy_paths`), `.github/merge/config.json` (`floor_7a`).

## Review records

### Who must review

| Weight | Review set |
|---|---|
| `trivial` | `pr-challenger` |
| `standard` | `pr-reviewer`, `pr-challenger` |
| `heavy` | `pr-reviewer`, `pr-challenger`, `wario` |

The reviewer names must be spelled exactly as above; a differently spelled name is not counted.

**Author agents.** The author agents of a PR are the names in `author_agents` in the verdict config, plus any name on an `Author-Agent: <name>` line in the PR body. If a name in the required review set is an author agent, the verdict cannot be computed and fails, whatever records exist. So never put `pr-reviewer`, `pr-challenger` or `wario` on an `Author-Agent:` line. (A `VERIFY` from an author agent is ignored rather than failing the verdict; see [Criticals](#criticals).)

### What a record looks like

A record is one line in a PR comment, a submitted review body or an inline review comment, posted by `acardote-fleet[bot]` or `acardote`. It starts in column 0, the SHA is the full 40 hexadecimal characters, and names and ids use only letters, digits, `.`, `_` and `-`:

```text
VERDICT: pass reviewer=<agent> sha=<head sha>
VERDICT: fail reviewer=<agent> sha=<head sha>
CRITICAL: id=<id> reviewer=<agent> sha=<sha>
VERIFY: pass closes=<id> reviewer=<agent> sha=<fix sha>
```

For each reviewer in the set, the latest `VERDICT` at the current head must be `pass`.

The verdict ignores:

- records from any other login, whatever they say;
- `VERDICT` and `VERIFY` lines inside fenced code, HTML comments or block quotes, and indented lines.

**Fences do not protect critical-shaped lines.** In a comment by a trusted login, a fenced, quoted, indented or hidden line that looks like a critical record (the word critical plus an `id=`, `reviewer=` or `sha=` field) fails the verdict as an "unparseable critical", unless it quotes a live `CRITICAL` with the same id and SHA. So do not paste the example block above into a PR comment.

### Criticals

A `CRITICAL` record blocks the merge until it is closed. Only a `VERIFY: pass` record closes it, and only when both of these hold:

- it comes from a reviewer agent that is not an author of the PR;
- its SHA is a later commit of the PR that descends from the critical's SHA.

An author's "fixed" comment closes nothing. If the critical's SHA is no longer a commit of the PR (after a rebase or force-push), no `VERIFY` can close it until the reviewer raises it again at a current SHA. Each critical id belongs to one reviewer; reusing it from another reviewer fails the verdict.

A live line whose first word is `critical`, or that names critical next to an `id=`, `reviewer=` or `sha=` field, must be a well-formed record. Otherwise the verdict fails as an "unparseable critical". The one exception is a line that states zero criticals, such as `Critical: none`. Keep prose like "no critical findings" from starting with the word critical.

### Do not edit records

- An issue comment or inline review comment that holds record-like text and was edited after posting fails the verdict.
- Any edit of an issue comment or inline review comment by `acardote-fleet[bot]` fails it too, whatever the comment now says.
- Posting a new record does not clear either failure. Post the records again in a new comment **and delete the edited one**. The merge audit flags deleted record comments for the operator.
- Edits of a submitted review body are not detected by the verdict; only the audit can catch them, and only after the fact. Do not rely on a review body as unchangeable evidence.

To change your mind, post a new record in a new comment. Do not edit the old one.

Sources: `.github/verdict/verdict.py` (module docstring "Record formats" and "Edits", `VERDICT_RE`, `CRITICAL_RE`, `VERIFY_RE`, `parse_records`, `open_criticals`, `author_agents_for`, `compute_verdict` step 2), `.github/verdict/config.json` (`review_sets`, `reviewer_agents`, `author_agents`, `trusted_record_authors`, `machine_record_authors`), `.github/workflows/audit.yml`.

## Why the `auto-merge` label goes last

The `review-verdict` check (`verdict.yml`) runs on PR events only: opened, synchronize (a push), reopened, edited, labeled, unlabeled and ready_for_review. Posting a comment or a review, or CI finishing, is not one of these events, so the check shows the records as they stood at the last PR event.

`merge.yml` recomputes the verdict inline and does not trust the check to grant a merge. But before merging, it waits for the newest `review-verdict` run at your head and never merges past one that did not succeed, and the `e5-main` ruleset also requires that check at merge time.

If you add `auto-merge` before the records are in, the check fails at that event. Later, when the inline verdict passes, `merge.yml` skips the PR with a `SKIP pr=<n> head=<H> outcome=skipped` line whose reason contains `review-verdict check at H concluded` (search the run log for that text). The run stays green, and **every later scheduled run skips the PR the same way**: nothing re-runs the check until a PR event. Remove the `auto-merge` label and add it again. That is a new PR event, so `verdict.yml` runs again with the records in place.

`merge.yml` starts on the `labeled` and `synchronize` events of PRs based on `main`, and on a 5-minute schedule (GitHub runs schedules on a best-effort basis). A scheduled run helps when the check was still running at the last attempt. It does not help when the check failed.

Sources: `.github/workflows/verdict.yml` (`on:`), `.github/workflows/merge.yml` (`on:`), `.github/merge/merge.py` (docstring step 7, and the step 7 skip reasons in `process`), `.github/rulesets/e5-main.json`.

## What blocks a merge

`merge.yml` does not merge a PR if any of the following holds.

**The verdict fails at the current head** (the run stays green):

- the PR is closed, is a draft, is not based on `main`, or comes from a fork;
- there is not exactly one weight label, or the label is lighter than the objective weight;
- a reviewer in the set has no `VERDICT` at the head, or the latest one is `fail`;
- a name in the review set is an author agent;
- a critical is open;
- the latest `push` run of `ci.yml` at the head did not succeed or does not exist, or the head's `ci.yml` differs from `main`'s;
- a record-bearing comment was edited, or there is an unparseable critical;
- the head moved while the verdict was being computed.

**The PR is not eligible** (the run stays green):

- the PR has no `auto-merge` label;
- it has the `do-not-auto-merge` label, or the `operator-merge` label;
- it touches a 7a path (see below);
- the newest `review-verdict` run at the head concluded with anything but success (see [Why the label goes last](#why-the-auto-merge-label-goes-last));
- the head, the base or the labels changed between the checks and the merge call;
- the run reached its 600-second deadline before the merge call;
- the kill switch is off (see below).

**The run turns red** when something went wrong in the system rather than in your PR:

- the `review-verdict` check at the head was still pending, or did not exist, after the bounded wait (the next run retries);
- the merge call was refused (`MERGE-REFUSED`). If the refusal was caused by the check changing during the call (`kind=check-stale`), the run retries once in the same run (`MERGE-RETRY`);
- an API or git error (`SKIP ... outcome=error`);
- a 7a derivation that could not be bounded (`7A-DERIVE`). No PR merges until that is fixed.

The run's `RUN-RESULT` line summarises the outcome.

**7a PRs never auto-merge.** A PR that changes any path in the 7a set is skipped, both sides of a rename and every deletion included. The same goes for any symlink or submodule change. The 7a set is the `floor_7a` list in `.github/merge/config.json` (it includes all of `.github/**`, `.claude/**`, agent definitions, `CLAUDE.md`, dependency manifests and lockfiles) plus whatever `merge.py` derives from the `derive_roots` on `main`. Label such a PR `operator-merge`, never `auto-merge`. The operator merges it, and the ruleset still requires a passing `review-verdict` for that merge. Not every 7a path is in `heavy_paths`, so check the objective weight rather than assuming the heavy review set.

Sources: `.github/verdict/verdict.py` (`compute_verdict`), `.github/merge/merge.py` (docstring steps 2 to 8, the `skip(...)` reasons and outcomes in `process`, `run`), `.github/merge/config.json`, `docs/operator/apply-e5-main.md` section 7.

## Kill switches

These are operator controls. The operator's setup guide says no agent applies them, and contributors do not change them either. To ask for one PR to be held, ask the operator to add `do-not-auto-merge`.

| Switch | Effect |
|---|---|
| Repository variable `AUTO_MERGE_ENABLED` | `merge.yml` merges only if it is exactly `true`. Any other value, or no variable, stops all auto-merges from the next run. A run already in progress reads it once at its start, makes no merge call after 600 seconds, and a merge call can take up to 120 seconds more, so an in-flight run can still merge for up to about 12 minutes. |
| `do-not-auto-merge` label | Stops one PR. `merge.yml` re-reads the labels immediately before the merge call. |
| Disable `merge.yml` and cancel its runs | Immediate stop: no new runs, and the current runs end. |
| Break-glass: disable the `e5-main` ruleset | Only when `main` is wedged (the verdict machinery itself is broken, so no PR, the fix included, can pass). Before disabling the ruleset, the operator sets the variable to `false`, disables `merge.yml`, cancels every unfinished run and confirms none is left. Then the operator merges the fix by hand and re-enables the ruleset. |

The labels are flags, not authority: anyone with write access can add or remove them. The merge audit (`audit.yml`) checks every merge to `main` and reports changes to the kill-switch label, settings and workflow state, and edited or deleted review records.

Sources: `.github/merge/merge.py` (docstring steps 2, 6 and 7, `RUN_DEADLINE_S`), `.github/merge/config.json` (`kill_label`), `docs/operator/apply-e5-main.md` (introduction and sections 5, 6 and 8), `.github/workflows/audit.yml`.

## See also

- `docs/operator/apply-e5-main.md`: how the operator sets up and runs these controls.
- Design: `docs/design/merge-model.md` in acardote/personal-assistant-ultra.
