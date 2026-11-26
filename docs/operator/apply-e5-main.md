# Applying the E5 merge controls on fleet-pilot (operator only)

Child issue: acardote/personal-assistant-ultra#580. Design: `docs/design/merge-model.md` sections 1, 3 and 5 in acardote/personal-assistant-ultra. Policy: row 7 and row 13 of `docs/policy/autonomy-v2.md` ("Lead proposes, operator applies").

No agent applies any of this. Every step below changes repository settings or controls the merge model relies on. Policy v2 forbids an agent to write rulesets, the `AUTO_MERGE_ENABLED` variable, the kill-switch label or workflow state. You run these steps yourself, in this order.

## 0. Preconditions

1. acardote/fleet-pilot#1 (`verdict.yml`) is merged to `main`.
2. This PR (`merge.yml`, `.github/merge/**`, `.github/rulesets/e5-main.json`) is merged to `main`.
3. A push-triggered CI workflow exists at `.github/workflows/ci.yml` on `main`. The verdict requires a successful `push` run of that file at the PR head (`required_ci_workflows` in `.github/verdict/config.json`). Without it every verdict fails. Once the ruleset is applied, a failing `review-verdict` blocks your own merges too, since the ruleset has no bypass actors. So add `ci.yml` **before** step 2.

## 1. Labels

```sh
gh label create auto-merge        --repo acardote/fleet-pilot --color 0e8a16 --description "Lead requests the merge workflow to merge this PR"
gh label create do-not-auto-merge --repo acardote/fleet-pilot --color b60205 --description "Kill switch: the merge workflow never merges this PR"
gh label create operator-merge    --repo acardote/fleet-pilot --color fbca04 --description "7a: the operator merges"
for w in trivial standard heavy; do gh label create "weight:$w" --repo acardote/fleet-pilot; done
```

## 2. Ruleset `e5-main`

The definition is `.github/rulesets/e5-main.json`. It targets the default branch with `active` enforcement and **no bypass actors** (admins included). Its rules are deletion, non-fast-forward, PR required (0 approvals: under the shared login the author cannot approve its own PR), and the `review-verdict` check pinned to the GitHub Actions app (integration 15368). The pinned check is a backstop only. `merge.yml` never reads it and recomputes the verdict itself.

Apply it from a checkout of `main`:

```sh
gh api -X POST repos/acardote/fleet-pilot/rulesets --input .github/rulesets/e5-main.json
```

Verify:

```sh
gh api repos/acardote/fleet-pilot/rulesets --jq '.[] | select(.name=="e5-main") | {id, enforcement}'
gh api repos/acardote/fleet-pilot/rulesets/<id> --jq '{enforcement, bypass_actors, current_user_can_bypass, rules: [.rules[].type]}'
# expect: enforcement "active", bypass_actors [], current_user_can_bypass "never",
#         rules ["deletion","non_fast_forward","pull_request","required_status_checks"]
gh api repos/acardote/fleet-pilot/rules/branches/main --jq '[.[].type]'
```

Optional negative probes (design section 1): a direct `git push` to `main` must fail with `GH013: Repository rule violations`, and `gh pr merge --admin` on a PR with a red `review-verdict` must fail with `Required status check "review-verdict" is failing`.

Any later change to the ruleset is a 7a change: edit the JSON in a PR, merge it yourself, then `gh api -X PUT repos/acardote/fleet-pilot/rulesets/<id> --input .github/rulesets/e5-main.json`. The audit (#581, R3) flags every ruleset edit.

## 3. Actions settings

- Settings → Actions → General → Workflow permissions: **Read repository contents and packages permissions** (read-only default token). `merge.yml` asks for `contents: write` and `pull-requests: write` itself, and `verdict.yml` asks for read only.
- Leave "Allow GitHub Actions to create and approve pull requests" **off**.

## 4. Kill switch variable (last)

Enable auto-merge only after steps 0 to 3:

```sh
gh variable set AUTO_MERGE_ENABLED --repo acardote/fleet-pilot --body true
```

`merge.yml` merges only when the value is exactly `true`. Any other value, or deleting the variable, stops all merges at the next run:

```sh
gh variable set AUTO_MERGE_ENABLED --repo acardote/fleet-pilot --body false   # stop all auto-merges
gh pr edit <n> --repo acardote/fleet-pilot --add-label do-not-auto-merge      # stop one PR
```

## 5. After merge: pin the workflow blobs (audit R6)

Record the default-branch blob SHAs of `merge.yml`, `verdict.yml` (and later `audit.yml`) in Tier 0's own config, outside this repo:

```sh
for f in merge verdict; do gh api "repos/acardote/fleet-pilot/contents/.github/workflows/$f.yml?ref=main" --jq '"\(.path) \(.sha)"'; done
```

## Notes

- A merge made with `GITHUB_TOKEN` does not start `push` workflows on `main` (a GitHub rule that stops workflows from triggering each other). The audit therefore has to run on `schedule`.
- GitHub disables scheduled workflows in a public repo after 60 days without activity. Audit R6(a) checks that the workflows are still `active`.
- `merge.yml` has no `workflow_dispatch`. #530's exit test checks that `gh workflow run merge.yml --ref ws/x` is refused.
