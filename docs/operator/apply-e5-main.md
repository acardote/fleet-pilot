# Applying the E5 merge controls on fleet-pilot (operator only)

Child issue: acardote/personal-assistant-ultra#580. Design: `docs/design/merge-model.md` sections 1, 3 and 5 in acardote/personal-assistant-ultra. Policy: row 7 and row 13 of `docs/policy/autonomy-v2.md` ("Lead proposes, operator applies").

No agent applies any of this. Every step below changes repository settings or controls the merge model relies on. Policy v2 forbids an agent to write rulesets, the `AUTO_MERGE_ENABLED` variable, the kill-switch label or workflow state. You run these steps yourself, **in this order**. The order matters: the ruleset has no bypass actors, so if `review-verdict` cannot pass when the ruleset goes live, nobody can merge to `main` (you included) until you disable the ruleset (section 5, break-glass).

## 0. Preconditions

1. acardote/fleet-pilot#1 (`verdict.yml`) and #2 (`ci.yml`) are on `main`.
2. This PR (`merge.yml`, `.github/merge/**`, `.github/rulesets/e5-main.json`, the `ci.yml` fix) is merged to `main`, by you, before any ruleset exists.
3. `ci.yml` is **green on `main`**. The verdict requires a successful `push` run of `ci.yml` at the PR head (`required_ci_workflows` in `.github/verdict/config.json`), so a red `ci.yml` fails every verdict:

   ```sh
   gh run list --repo acardote/fleet-pilot --workflow ci --branch main --event push --limit 1 --json conclusion,headSha
   # expect: conclusion "success" at the current main head (gh api repos/acardote/fleet-pilot/commits/main --jq .sha)
   ```

4. Squash merging is enabled (`merge.yml` merges with `--squash`):

   ```sh
   gh api repos/acardote/fleet-pilot --jq .allow_squash_merge   # expect: true
   ```

## 1. Labels

```sh
gh label create auto-merge        --repo acardote/fleet-pilot --color 0e8a16 --description "Lead requests the merge workflow to merge this PR"
gh label create do-not-auto-merge --repo acardote/fleet-pilot --color b60205 --description "Kill switch: the merge workflow never merges this PR"
gh label create operator-merge    --repo acardote/fleet-pilot --color fbca04 --description "7a: the operator merges"
for w in trivial standard heavy; do gh label create "weight:$w" --repo acardote/fleet-pilot; done
```

Every PR needs exactly one `weight:*` label, or its verdict fails.

## 2. Actions settings

- Settings → Actions → General → Workflow permissions: **Read repository contents and packages permissions** (read-only default token). `merge.yml` asks for `contents: write` and `pull-requests: write` itself, and `verdict.yml` asks for read only.
- Leave "Allow GitHub Actions to create and approve pull requests" **off**.

## 3. Pre-flight: prove the verdict can pass (before the ruleset)

Open a throwaway, non-7a PR (for example a one-line `README.md` change on a branch), label it `weight:trivial`, and wait for `ci` on its branch to go green. Post the review set's `VERDICT: pass reviewer=<agent> sha=<head>` records for that head from a trusted author (`acardote` or `acardote-fleet[bot]`), then trigger a PR event (add or remove a label) so `verdict.yml` re-runs. Check:

```sh
gh pr checks <n> --repo acardote/fleet-pilot   # expect: review-verdict pass, ci pass
```

If `review-verdict` does not pass here, stop and fix it first: once the ruleset is active, the fix PR itself would need a passing `review-verdict`. Close the throwaway PR afterwards (or merge it yourself before step 4).

## 4. Ruleset `e5-main`

The definition is `.github/rulesets/e5-main.json`. It targets the default branch with `active` enforcement and **no bypass actors** (admins included); that is the design, so there is no escape hatch inside the ruleset, only the break-glass in section 5. Its rules are deletion, non-fast-forward, PR required (0 approvals: under the shared login the author cannot approve its own PR), and the `review-verdict` check pinned to the GitHub Actions app (integration 15368). `merge.yml` never reads that check and recomputes the verdict itself, but the ruleset still requires it at merge time, for `merge.yml`'s merges too (section 7).

Apply it from a checkout of `main`, only after sections 0 to 3 pass:

```sh
gh api -X POST repos/acardote/fleet-pilot/rulesets --input .github/rulesets/e5-main.json
ID=$(gh api repos/acardote/fleet-pilot/rulesets --jq '.[] | select(.name=="e5-main") | .id')
echo "$ID"   # write the id down next to the break-glass commands below
```

Verify:

```sh
gh api repos/acardote/fleet-pilot/rulesets/$ID --jq '{enforcement, bypass_actors, current_user_can_bypass, rules: [.rules[].type] | sort}'
# expect: enforcement "active", bypass_actors [], current_user_can_bypass "never",
#         rules ["deletion","non_fast_forward","pull_request","required_status_checks"]
gh api repos/acardote/fleet-pilot/rules/branches/main --jq '[.[].type] | sort'
```

Optional negative probes (design section 1): a direct `git push` to `main` must fail with `GH013: Repository rule violations`, and `gh pr merge --admin` on a PR with a red `review-verdict` must fail with `Required status check "review-verdict" is failing`.

Any later change to the ruleset is a 7a change: edit the JSON in a PR, merge it yourself, then `gh api -X PUT repos/acardote/fleet-pilot/rulesets/$ID --input .github/rulesets/e5-main.json`. The audit (#581, R3) flags every ruleset edit.

## 5. Break-glass and rollback

Use this when `main` is wedged: `review-verdict` fails for a reason a PR cannot fix (a bug in `verdict.py`, `verdict.yml` or `ci.yml`, a records problem), so no PR, including the fix, can merge.

```sh
ID=$(gh api repos/acardote/fleet-pilot/rulesets --jq '.[] | select(.name=="e5-main") | .id')
# 1. Stop auto-merges first, so nothing merges while the ruleset is off.
gh variable set AUTO_MERGE_ENABLED --repo acardote/fleet-pilot --body false
# 2. Disable the ruleset (keeps its definition and id).
gh api -X PUT repos/acardote/fleet-pilot/rulesets/$ID -f enforcement=disabled
# 3. Merge the fix PR yourself.
# 4. Re-enable, then re-verify as in section 4.
gh api -X PUT repos/acardote/fleet-pilot/rulesets/$ID -f enforcement=active
gh api repos/acardote/fleet-pilot/rulesets/$ID --jq .enforcement   # expect: "active"
# 5. Re-run the section 3 pre-flight, then set AUTO_MERGE_ENABLED back to true.
```

Full rollback (remove the ruleset entirely; re-apply with section 4):

```sh
gh api -X DELETE repos/acardote/fleet-pilot/rulesets/$ID
```

Both are admin actions on repository settings. The audit (#581, R3) flags them; record why on #580 or its successor.

## 6. Pin the workflow blobs (audit R6), then enable

Record the default-branch blob SHAs of `merge.yml`, `verdict.yml` and `ci.yml` (and later `audit.yml`) in Tier 0's own config, outside this repo, **before** enabling auto-merge:

```sh
for f in merge verdict ci; do gh api "repos/acardote/fleet-pilot/contents/.github/workflows/$f.yml?ref=main" --jq '"\(.path) \(.sha)"'; done
```

Then enable auto-merge, last:

```sh
gh variable set AUTO_MERGE_ENABLED --repo acardote/fleet-pilot --body true
```

`merge.yml` merges only when the value is exactly `true`. Any other value, or deleting the variable, stops all merges from the next run. A run already in progress reads the variable once at its start; for an immediate stop also disable the workflow and cancel the run:

```sh
gh variable set AUTO_MERGE_ENABLED --repo acardote/fleet-pilot --body false   # stop all auto-merges
gh workflow disable merge.yml --repo acardote/fleet-pilot                      # immediate: no new runs
gh run list --repo acardote/fleet-pilot --workflow merge.yml --status in_progress --json databaseId --jq '.[].databaseId' \
  | xargs -n1 gh run cancel --repo acardote/fleet-pilot                       # immediate: stop the current run
gh pr edit <n> --repo acardote/fleet-pilot --add-label do-not-auto-merge      # stop one PR
```

## 7. How PRs reach `main` once this is live

- **Leads label `auto-merge` last**, after every review record for the current head is posted. `verdict.yml` runs on PR events (labels, pushes, edits), not on new comments or reviews, so the `review-verdict` check reflects the records at the last PR event. `merge.yml` recomputes the verdict itself and may pass while the check is still red from an earlier event; the ruleset then refuses the merge, `merge.yml` logs `MERGE-REFUSED ... kind=check-stale` and the run goes red. Fix: remove and re-add `auto-merge` (a PR event re-runs `verdict.yml`).
- **7a PRs** (anything under `.github/`, `.claude/`, the floor and derived set in `.github/merge/config.json`): never label `auto-merge`; label `operator-merge`. `merge.yml` skips them either way.
- **Your own merges of 7a PRs** also need a green `review-verdict` at the head: the ruleset has no bypass. 7a paths are heavy, so that means passing records from the heavy review set (pr-reviewer, pr-challenger, wario) at that head, from a trusted author. A fix to the verdict machinery that cannot pass its own verdict goes through section 5.
- **A red `auto-merge` run** means something systemic: an API or git error, a refused merge, or an unresolvable reference in the 7a derivation (no PR merges until it is fixed). The run's `RUN-RESULT` and `SKIP ... outcome=error` / `MERGE-REFUSED` / `7A-DERIVE unresolved` lines say which. A failing verdict or a 7a skip leaves the run green.

## 8. Known limits

- **The required check is pinned to the GitHub Actions app, not to `verdict.yml`.** A same-repo PR can add a workflow with a job named `review-verdict` that passes; that check satisfies the ruleset, so someone on the shared login could merge that PR by hand. `merge.yml` never merges it (`.github/**` is 7a). The audit catches it only through R1 (merges by the operator login) and R5; R4 (API-created check runs) does not, because a workflow-created job has a runner and steps. The design (`docs/design/merge-model.md` section 6) still lists forged checks as caught by R4; that line needs correcting in acardote/personal-assistant-ultra.
- **Labels are flags, not authority.** `auto-merge`, `operator-merge` and `do-not-auto-merge` can be added or removed by the shared login and by any workflow token with `issues`/`pull-requests: write`, including removing your per-PR kill label. Detection relies on the audit (R3, label events).
- **Logs are the audit trail.** `merge.yml`'s `VERDICT-RECOMPUTED` and `MERGED` lines live in the Actions run logs (default retention 90 days); the #581 audit reads them through the API by run id and must run well inside that window.

## Notes

- A merge made with `GITHUB_TOKEN` does not start `push` workflows on `main` (a GitHub rule that stops workflows from triggering each other). The audit therefore has to run on `schedule`.
- GitHub disables scheduled workflows in a public repo after 60 days without activity. Audit R6(a) checks that the workflows are still `active`.
- `merge.yml` has no `workflow_dispatch`. #530's exit test checks that `gh workflow run merge.yml --ref ws/x` is refused.
