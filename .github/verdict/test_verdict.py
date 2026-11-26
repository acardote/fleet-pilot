"""Tests for review-verdict (acardote/personal-assistant-ultra#579).

Run: python3 -m pytest -q .github/verdict

Covers #579's acceptance and falsifiers:
- passes only when the full review set for the recomputed weight returned, no
  critical is open, the reviewed SHA is the head, and CI is green;
- mislabelled (lighter) weight fails  [falsifier 1];
- a critical "closed" by the author's comment, with no verify verdict, fails  [falsifier 2];
and the design's hard rules on the workflow file itself (triggers, permissions,
default-branch-only code, no PR-head checkout).
"""
from __future__ import annotations

import copy
import io
import json
import re
import sys
import urllib.error
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import verdict as v  # noqa: E402

REPO = "acardote/fleet-pilot"
WORKFLOW = HERE.parent / "workflows" / "verdict.yml"
CONFIG = json.loads((HERE / "config.json").read_text())

C1 = "1" * 40  # first commit
C2 = "2" * 40  # second commit
H = "3" * 40   # head
OTHER = "9" * 40
BOT = "acardote-fleet[bot]"


# --------------------------------------------------------------------------
# Workflow file structure
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def wf():
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(WORKFLOW.read_text())
    # PyYAML (YAML 1.1) reads the bare key `on` as boolean True.
    if True in doc and "on" not in doc:
        doc["on"] = doc.pop(True)
    return doc


def test_only_trigger_is_pull_request_target_on_main(wf):
    assert set(wf["on"].keys()) == {"pull_request_target"}
    assert wf["on"]["pull_request_target"]["branches"] == ["main"]


@pytest.mark.parametrize("bad", ["push", "pull_request", "workflow_dispatch", "workflow_run",
                                 "issue_comment", "pull_request_review", "schedule", "workflow_call"])
def test_no_trigger_that_runs_branch_or_pr_definitions(wf, bad):
    assert bad not in wf["on"]


def test_synchronize_and_labeled_rerun_the_verdict(wf):
    types = set(wf["on"]["pull_request_target"]["types"])
    assert {"opened", "synchronize", "reopened", "labeled", "unlabeled", "edited"} <= types


def test_top_level_token_has_no_permissions(wf):
    assert wf["permissions"] == {}


def test_job_is_the_review_verdict_check_with_read_only_token(wf):
    assert list(wf["jobs"].keys()) == ["review-verdict"]
    job = wf["jobs"]["review-verdict"]
    assert job["name"] == "review-verdict"
    assert job["permissions"] == {"contents": "read", "pull-requests": "read",
                                  "issues": "read", "actions": "read"}
    assert all(val == "read" for val in job["permissions"].values())


def test_checkout_is_the_default_branch_workflow_commit_only(wf):
    steps = wf["jobs"]["review-verdict"]["steps"]
    checkouts = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert len(checkouts) == 1
    w = checkouts[0]["with"]
    assert w["ref"] == "${{ github.workflow_sha }}"
    assert w["persist-credentials"] is False
    assert "repository" not in w


def test_no_pr_head_reference_anywhere():
    text = WORKFLOW.read_text()
    for needle in ("pull_request.head", "github.head_ref", "refs/pull/", "merge_commit_sha",
                   "github.event.pull_request.title", "github.event.pull_request.body"):
        assert needle not in text, needle


def test_actions_pinned_to_full_commit_sha(wf):
    for step in wf["jobs"]["review-verdict"]["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", step["uses"]), step["uses"]


def test_no_expression_interpolation_inside_run_scripts(wf):
    for step in wf["jobs"]["review-verdict"]["steps"]:
        if "run" in step:
            assert "${{" not in step["run"], step.get("name")


def test_guard_refuses_non_default_branch_definition(wf):
    steps = wf["jobs"]["review-verdict"]["steps"]
    names = [s.get("name", "") for s in steps]
    guard = steps[names.index("Refuse a definition not on the default branch")]
    assert "@refs/heads/${DEFAULT_BRANCH}" in guard["run"] and "exit 1" in guard["run"]
    assert guard["env"]["DEFAULT_BRANCH"] == "${{ github.event.repository.default_branch }}"
    # The guard runs before any checkout or verdict code.
    checkout_idx = next(i for i, s in enumerate(steps) if "uses" in s)
    assert names.index("Refuse a definition not on the default branch") < checkout_idx


def test_verdict_step_runs_default_branch_verdict_code(wf):
    steps = wf["jobs"]["review-verdict"]["steps"]
    last = steps[-1]
    assert last["run"].startswith("python3 .github/verdict/verdict.py ")
    assert "--config .github/verdict/config.json" in last["run"]
    assert last["env"]["GH_TOKEN"] == "${{ github.token }}"


def test_verdict_code_is_stdlib_only():
    src = (HERE / "verdict.py").read_text()
    imports = set(re.findall(r"^(?:from|import) ([\w.]+)", src, re.MULTILINE))
    allowed = {"__future__", "argparse", "json", "os", "re", "sys", "urllib.error",
               "urllib.parse", "urllib.request", "dataclasses", "typing"}
    assert imports <= allowed, imports - allowed


# --------------------------------------------------------------------------
# Verdict function fixtures
# --------------------------------------------------------------------------

def comment(body, login=BOT, at="2026-11-26T10:00:00Z"):
    return {"body": body, "user": {"login": login}, "created_at": at}


def make_pr(**over):
    pr = {
        "state": "open",
        "head": {"sha": H, "repo": {"full_name": REPO}},
        "labels": [{"name": "weight:standard"}],
        "additions": 120, "deletions": 10, "changed_files": 2, "commits": 3,
        "body": "Implements the thing.\n\nAuthor-Agent: yoshi\n",
    }
    pr.update(over)
    return pr


def make_files(paths=("src/app.py", "tests/test_app.py")):
    return [{"filename": p} for p in paths]


def make_commits():
    return [{"sha": C1}, {"sha": C2}, {"sha": H}]


def ci_run(**over):
    run = {"id": 1, "path": ".github/workflows/ci.yml", "head_sha": H, "event": "pull_request",
           "status": "completed", "conclusion": "success", "created_at": "2026-11-26T09:00:00Z",
           "run_attempt": 1, "head_repository": {"full_name": REPO}}
    run.update(over)
    return run


def passing_comments(sha=H, reviewers=("pr-reviewer", "pr-challenger")):
    return [comment(f"VERDICT: pass reviewer={r} sha={sha}", at=f"2026-11-26T10:0{i}:00Z")
            for i, r in enumerate(reviewers)]


def run(pr=None, files=None, commits=None, comments=None, runs=None, config=None):
    return v.compute_verdict(
        repo=REPO,
        pr=pr if pr is not None else make_pr(),
        files=files if files is not None else make_files(),
        commits=commits if commits is not None else make_commits(),
        comments=comments if comments is not None else passing_comments(),
        runs=runs if runs is not None else [ci_run()],
        config=config if config is not None else CONFIG,
    )


def failed_with(res, fragment):
    assert not res.passed, res.render()
    assert any(fragment in r for r in res.reasons), res.render()


# --------------------------------------------------------------------------
# Acceptance: passes only when all four conditions hold
# --------------------------------------------------------------------------

def test_baseline_passes():
    res = run()
    assert res.passed, res.render()
    assert res.weight == "standard"


def test_incomplete_review_set_fails():
    failed_with(run(comments=passing_comments(reviewers=("pr-reviewer",))), "no VERDICT from pr-challenger")


def test_verdict_at_older_sha_does_not_count():
    failed_with(run(comments=passing_comments(sha=C2)), "no VERDICT from pr-reviewer at head")


def test_latest_verdict_fail_at_head_fails():
    cs = passing_comments() + [comment(f"VERDICT: fail reviewer=pr-challenger sha={H}", at="2026-11-26T11:00:00Z")]
    failed_with(run(comments=cs), "latest VERDICT from pr-challenger")


def test_verdict_from_untrusted_author_is_ignored():
    cs = [comment(f"VERDICT: pass reviewer={r} sha={H}", login="mallory") for r in ("pr-reviewer", "pr-challenger")]
    res = run(comments=cs)
    failed_with(res, "no VERDICT from pr-reviewer")
    assert any("untrusted author 'mallory'" in n for n in res.notes)


def test_quoted_verdict_line_is_not_a_record():
    cs = [comment(f"> VERDICT: pass reviewer={r} sha={H}") for r in ("pr-reviewer", "pr-challenger")]
    failed_with(run(comments=cs), "no VERDICT from pr-reviewer")


@pytest.mark.parametrize("bad_run,frag", [
    (None, "no pull_request run"),
    ({"conclusion": "failure"}, "completed/failure"),
    ({"status": "in_progress", "conclusion": None}, "in_progress/None"),
    ({"path": ".github/workflows/other.yml"}, "no pull_request run"),
    ({"event": "push"}, "no pull_request run"),
    ({"head_sha": C2}, "no pull_request run"),
    ({"head_repository": {"full_name": "evil/fork"}}, "no pull_request run"),
])
def test_ci_not_green_at_head_fails(bad_run, frag):
    runs = [] if bad_run is None else [ci_run(**bad_run)]
    failed_with(run(runs=runs), frag)


def test_ci_latest_rerun_wins():
    runs = [ci_run(id=1, conclusion="failure", created_at="2026-11-26T09:00:00Z"),
            ci_run(id=2, conclusion="success", created_at="2026-11-26T09:30:00Z")]
    assert run(runs=runs).passed
    runs[0]["conclusion"], runs[1]["conclusion"] = "success", "failure"  # newer run failed
    failed_with(run(runs=runs), "completed/failure")


def test_no_required_ci_configured_fails_closed():
    cfg = copy.deepcopy(CONFIG)
    cfg["required_ci_workflows"] = []
    failed_with(run(config=cfg), "no required CI workflows configured")


def test_fork_pr_never_passes():
    failed_with(run(pr=make_pr(head={"sha": H, "repo": {"full_name": "evil/fleet-pilot"}})), "fork PRs never pass")


def test_closed_pr_fails():
    failed_with(run(pr=make_pr(state="closed")), "not open")


# --------------------------------------------------------------------------
# A7: independent weight recompute, fails closed; lighter label fails  [falsifier 1]
# --------------------------------------------------------------------------

def test_mislabelled_lighter_by_loc_fails():
    pr = make_pr(labels=[{"name": "weight:trivial"}])
    failed_with(run(pr=pr), "labelled weight:trivial is lighter than objective weight standard")


def test_mislabelled_lighter_by_security_path_fails():
    pr = make_pr(labels=[{"name": "weight:standard"}], additions=3, deletions=0, changed_files=1)
    files = make_files([".github/workflows/ci.yml"])
    failed_with(run(pr=pr, files=files), "lighter than objective weight heavy")


def test_mislabelled_lighter_by_size_fails():
    pr = make_pr(additions=600)
    failed_with(run(pr=pr), "lighter than objective weight heavy")


def test_rename_out_of_security_path_counts_old_side():
    pr = make_pr(additions=0, deletions=0, changed_files=1, labels=[{"name": "weight:trivial"}])
    files = [{"filename": "docs/x.yml", "previous_filename": ".github/workflows/x.yml"}]
    failed_with(run(pr=pr, files=files), "lighter than objective weight heavy")


def test_heavier_label_requires_heavier_review_set():
    pr = make_pr(labels=[{"name": "weight:heavy"}])
    res = run(pr=pr)
    failed_with(res, "no VERDICT from wario")
    assert res.weight == "heavy"
    assert run(pr=pr, comments=passing_comments(reviewers=("pr-reviewer", "pr-challenger", "wario"))).passed


def test_trivial_pr_correctly_labelled_needs_only_trivial_set():
    pr = make_pr(labels=[{"name": "weight:trivial"}], additions=5, deletions=1, changed_files=1)
    res = run(pr=pr, files=make_files(["src/app.py"]), comments=passing_comments(reviewers=("pr-challenger",)))
    assert res.passed, res.render()


@pytest.mark.parametrize("labels,frag", [
    ([], "expected exactly one 'weight:<tier>' label, found 0"),
    ([{"name": "weight:trivial"}, {"name": "weight:heavy"}], "found 2"),
    ([{"name": "weight:light"}], "unknown weight label"),
])
def test_weight_label_missing_or_ambiguous_fails_closed(labels, frag):
    failed_with(run(pr=make_pr(labels=labels)), frag)


@pytest.mark.parametrize("over,files,frag", [
    ({"changed_files": 3}, None, "file list incomplete"),
    ({"changed_files": 3000}, None, "3000-file API cap"),
    ({"additions": None}, None, "'additions' missing or invalid"),
    ({}, [{"filename": ""}, {"filename": "x"}], "has no filename"),
])
def test_weight_uncomputable_fails_closed(over, files, frag):
    failed_with(run(pr=make_pr(**over), files=files), frag)


@pytest.mark.parametrize("path,heavy", [
    ("uv.lock", True), ("web/package-lock.json", True), ("CLAUDE.md", True),
    ("docs/CLAUDE.md", False), ("agents/daisy.md", True), ("db/migrations/001.py", True),
    ("src/app.py", False), ("requirements-dev.txt", True), ("svc/requirements.txt", True),
])
def test_heavy_path_globs(path, heavy):
    assert v.matches_any(path, CONFIG["heavy_paths"]) is heavy


# --------------------------------------------------------------------------
# A9: critical closure only by verify-only reviewer verdict at the fix SHA  [falsifier 2]
# --------------------------------------------------------------------------

CRIT = f"CRITICAL: id=c1 reviewer=pr-challenger sha={C1}"


def with_crit(*extra):
    return [comment(CRIT, at="2026-11-26T09:00:00Z")] + list(extra) + passing_comments()


def test_open_critical_fails():
    failed_with(run(comments=with_crit()), "critical 'c1' is open")


def test_author_claims_fix_in_prose_fails():
    cs = with_crit(comment(f"Fixed c1 in {C2}, closing.", at="2026-11-26T09:30:00Z"))
    failed_with(run(comments=cs), "critical 'c1' is open")


def test_author_agent_verify_record_does_not_close():
    cs = with_crit(comment(f"VERIFY: pass closes=c1 reviewer=yoshi sha={C2}", at="2026-11-26T09:30:00Z"))
    res = run(comments=cs)
    failed_with(res, "critical 'c1' is open")
    assert any("author agent 'yoshi'" in n for n in res.notes)


def test_pr_declared_author_agent_cannot_verify():
    pr = make_pr(body="Author-Agent: wario\n")
    cs = with_crit(comment(f"VERIFY: pass closes=c1 reviewer=wario sha={C2}", at="2026-11-26T09:30:00Z"))
    res = run(pr=pr, comments=cs)
    failed_with(res, "critical 'c1' is open")
    assert any("author agent 'wario'" in n for n in res.notes)


def test_pr_declared_author_agent_in_review_set_fails_closed():
    pr = make_pr(body="Author-Agent: pr-reviewer\n")
    failed_with(run(pr=pr), "names author agent 'pr-reviewer'")


def test_untrusted_login_verify_does_not_close():
    cs = with_crit(comment(f"VERIFY: pass closes=c1 reviewer=pr-reviewer sha={C2}", login="mallory",
                           at="2026-11-26T09:30:00Z"))
    failed_with(run(comments=cs), "critical 'c1' is open")


def test_verify_at_critical_sha_does_not_close():
    cs = with_crit(comment(f"VERIFY: pass closes=c1 reviewer=pr-reviewer sha={C1}", at="2026-11-26T09:30:00Z"))
    failed_with(run(comments=cs), "critical 'c1' is open")


def test_verify_at_sha_outside_pr_does_not_close():
    cs = with_crit(comment(f"VERIFY: pass closes=c1 reviewer=pr-reviewer sha={OTHER}", at="2026-11-26T09:30:00Z"))
    failed_with(run(comments=cs), "critical 'c1' is open")


def test_verify_fail_keeps_critical_open():
    cs = with_crit(comment(f"VERIFY: fail closes=c1 reviewer=pr-reviewer sha={C2}", at="2026-11-26T09:30:00Z"))
    failed_with(run(comments=cs), "critical 'c1' is open")


def test_verify_before_critical_does_not_close():
    cs = [comment(f"VERIFY: pass closes=c1 reviewer=pr-reviewer sha={C2}", at="2026-11-26T08:00:00Z"),
          comment(CRIT, at="2026-11-26T09:00:00Z")] + passing_comments()
    failed_with(run(comments=cs), "critical 'c1' is open")


def test_reviewer_verify_at_fix_sha_closes_critical():
    cs = with_crit(comment(f"VERIFY: pass closes=c1 reviewer=pr-reviewer sha={C2}", at="2026-11-26T09:30:00Z"))
    res = run(comments=cs)
    assert res.passed, res.render()


def test_reraised_critical_after_verify_is_open_again():
    cs = with_crit(comment(f"VERIFY: pass closes=c1 reviewer=pr-reviewer sha={C2}", at="2026-11-26T09:30:00Z"),
                   comment(f"CRITICAL: id=c1 reviewer=pr-challenger sha={C2}", at="2026-11-26T09:45:00Z"))
    failed_with(run(comments=cs), "critical 'c1' is open")


def test_incomplete_commit_list_fails_closed():
    failed_with(run(pr=make_pr(commits=4)), "commit list incomplete")


# --------------------------------------------------------------------------
# I/O layer: head pinning and fail-closed errors
# --------------------------------------------------------------------------

class FakeGH(v.GitHub):
    def __init__(self, pr_seq, comments=None, runs=None, fail=False):
        super().__init__("t")
        self.pr_seq = list(pr_seq)
        self.comments = comments if comments is not None else passing_comments()
        self.runs = runs if runs is not None else [ci_run()]
        self.fail = fail

    def get(self, path):
        if self.fail:
            raise v.VerdictError("GET failed")
        return self.pr_seq.pop(0) if len(self.pr_seq) > 1 else self.pr_seq[0]

    def paged(self, path, key=None, limit=100):
        if path.endswith("/files"):
            return make_files()
        if path.endswith("/commits"):
            return make_commits()
        if path.endswith("/comments"):
            return self.comments
        if "actions/runs" in path:
            assert f"head_sha={H}" in path and "event=pull_request" in path
            return self.runs
        raise AssertionError(path)


def test_fetch_and_compute_passes_when_head_is_stable():
    assert v.fetch_and_compute(FakeGH([make_pr()]), REPO, 1, CONFIG).passed


def test_head_moved_during_computation_fails():
    moved = make_pr(head={"sha": OTHER, "repo": {"full_name": REPO}})
    failed_with(v.fetch_and_compute(FakeGH([make_pr(), moved]), REPO, 1, CONFIG), "head moved")


def test_main_without_token_fails_closed(monkeypatch, capsys):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert v.main(["--repo", REPO, "--pr", "1", "--config", str(HERE / "config.json")]) == 2


def test_main_api_error_fails_closed(monkeypatch, capsys):
    monkeypatch.setenv("GH_TOKEN", "t")

    def boom(*a, **k):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(v.urllib.request, "urlopen", boom)
    rc = v.main(["--repo", REPO, "--pr", "1", "--config", str(HERE / "config.json")])
    assert rc == 2
    assert "fail closed" in capsys.readouterr().out


def test_pagination_follows_link_next():
    pages = {
        "https://api.example/x?per_page=100": ([1, 2], '<https://api.example/x?page=2>; rel="next"'),
        "https://api.example/x?page=2": ([3], None),
    }

    class Resp(io.BytesIO):
        def __init__(self, data, link):
            super().__init__(json.dumps(data).encode())
            self.headers = {"Link": link} if link else {}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout):
        data, link = pages[req.full_url]
        return Resp(data, link)

    gh = v.GitHub("t", "https://api.example", opener=opener)
    assert gh.paged("x") == [1, 2, 3]
