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
CI_PATH = ".github/workflows/ci.yml"
CI_BLOB = "c" * 40
HEAD_REF = "ws/feature"


# --------------------------------------------------------------------------
# Workflow file structure
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def wf():
    import yaml  # required, never skipped: ci.yml installs PyYAML (fleet-pilot#3 review, I4)
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
    allowed = {"__future__", "argparse", "json", "os", "re", "sys", "time", "unicodedata",
               "urllib.error", "urllib.parse", "urllib.request", "dataclasses", "typing"}
    assert imports <= allowed, imports - allowed


# --------------------------------------------------------------------------
# Verdict function fixtures
# --------------------------------------------------------------------------

def comment(body, login=BOT, at="2026-11-26T10:00:00Z"):
    return {"body": body, "user": {"login": login}, "created_at": at}


def make_pr(**over):
    pr = {
        "state": "open",
        "draft": False,
        "head": {"sha": H, "ref": HEAD_REF, "repo": {"full_name": REPO}},
        "base": {"ref": "main", "repo": {"full_name": REPO, "default_branch": "main"}},
        "labels": [{"name": "weight:standard"}],
        "additions": 120, "deletions": 10, "changed_files": 2, "commits": 3,
        "body": "Implements the thing.\n\nAuthor-Agent: yoshi\n",
    }
    pr.update(over)
    return pr


def make_files(paths=("src/app.py", "tests/test_app.py")):
    return [{"filename": p, "status": "modified", "additions": 5, "deletions": 1, "patch": "@@ -1 +1 @@"}
            for p in paths]


def make_commits():
    """Linear history C1 <- C2 <- H."""
    return [{"sha": C1, "parents": [{"sha": "0" * 40}]}, {"sha": C2, "parents": [{"sha": C1}]},
            {"sha": H, "parents": [{"sha": C2}]}]


def make_tree(extra=(), ci_blob=CI_BLOB):
    entries = [{"path": ".github", "mode": "040000", "type": "tree", "sha": "a" * 40},
               {"path": CI_PATH, "mode": "100644", "type": "blob", "sha": ci_blob},
               {"path": "src/app.py", "mode": "100644", "type": "blob", "sha": "b" * 40}]
    return {"sha": "d" * 40, "truncated": False, "tree": entries + list(extra)}


def ci_run(**over):
    run = {"id": 1, "path": CI_PATH, "head_sha": H, "event": "push", "head_branch": HEAD_REF,
           "status": "completed", "conclusion": "success", "created_at": "2026-11-26T09:00:00Z",
           "run_attempt": 1, "head_repository": {"full_name": REPO}, "repository": {"full_name": REPO}}
    run.update(over)
    return run


def passing_comments(sha=H, reviewers=("pr-reviewer", "pr-challenger")):
    return [comment(f"VERDICT: pass reviewer={r} sha={sha}", at=f"2026-11-26T10:0{i}:00Z")
            for i, r in enumerate(reviewers)]


def run(pr=None, files=None, commits=None, comments=None, runs=None, config=None,
        reviews=(), review_comments=(), tree=None, default_ci_blobs=None):
    return v.compute_verdict(
        repo=REPO,
        pr=pr if pr is not None else make_pr(),
        files=files if files is not None else make_files(),
        commits=commits if commits is not None else make_commits(),
        comments=comments if comments is not None else passing_comments(),
        reviews=list(reviews),
        review_comments=list(review_comments),
        tree=tree if tree is not None else make_tree(),
        default_ci_blobs=default_ci_blobs if default_ci_blobs is not None else {CI_PATH: CI_BLOB},
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
    (None, "no push run"),
    ({"conclusion": "failure"}, "completed/failure"),
    ({"status": "in_progress", "conclusion": None}, "in_progress/None"),
    ({"path": ".github/workflows/other.yml"}, "no push run"),
    ({"event": "pull_request"}, "no push run"),
    ({"event": "pull_request_target"}, "no push run"),
    ({"head_sha": C2}, "no push run"),
    ({"head_branch": "ws/other"}, "no push run"),
    ({"head_repository": {"full_name": "evil/fork"}}, "no push run"),
    ({"repository": {"full_name": "evil/fork"}}, "no push run"),
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
    failed_with(run(pr=make_pr(head={"sha": H, "ref": HEAD_REF, "repo": {"full_name": "evil/fleet-pilot"}})),
                "fork PRs never pass")


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
    files = [{"filename": "docs/x.yml", "previous_filename": ".github/workflows/x.yml", "status": "renamed",
              "additions": 0, "deletions": 0, "patch": ""}]
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
    def __init__(self, pr_seq, comments=None, runs=None, fail=False, reviews=(), review_comments=(),
                 contents_error=False):
        super().__init__("t")
        self.pr_seq = list(pr_seq)
        self.comments = comments if comments is not None else passing_comments()
        self.reviews = list(reviews)
        self.review_comments = list(review_comments)
        self.runs = runs if runs is not None else [ci_run()]
        self.fail = fail
        self.contents_error = contents_error
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        if self.fail:
            raise v.VerdictError("GET failed")
        if "/git/trees/" in path:
            assert path.endswith(f"/git/trees/{H}?recursive=1"), path
            return make_tree()
        if "/contents/" in path:
            assert "ref=main" in path, path
            if self.contents_error:
                raise v.VerdictError("HTTP 404")
            return {"type": "file", "sha": CI_BLOB}
        return self.pr_seq.pop(0) if len(self.pr_seq) > 1 else self.pr_seq[0]

    def paged(self, path, key=None, limit=100):
        self.paths.append(path)
        if path.endswith("/files"):
            return make_files()
        if path.endswith("/commits"):
            return make_commits()
        if path.endswith("/issues/1/comments"):
            return self.comments
        if path.endswith("/pulls/1/comments"):
            return self.review_comments
        if path.endswith("/reviews"):
            return self.reviews
        if "actions/runs" in path:
            assert f"head_sha={H}" in path and "event=push" in path
            return self.runs
        raise AssertionError(path)


def test_fetch_and_compute_passes_when_head_is_stable():
    assert v.fetch_and_compute(FakeGH([make_pr()]), REPO, 1, CONFIG).passed


def test_head_moved_during_computation_fails():
    moved = make_pr(head={"sha": OTHER, "ref": HEAD_REF, "repo": {"full_name": REPO}})
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


# --------------------------------------------------------------------------
# Review round 1 (fp1-challenger.md, fp1-wario.md)
# --------------------------------------------------------------------------

def verify(sha, cid="c1", reviewer="pr-reviewer", at="2026-11-26T09:30:00Z", result="pass"):
    return comment(f"VERIFY: {result} closes={cid} reviewer={reviewer} sha={sha}", at=at)


# Critical 1: a critical closes only on a VERIFY at a descendant of its SHA in the PR's current commits.

def test_critical_at_sha_gone_from_pr_stays_open_whatever_verify():
    gone = "8" * 40  # e.g. the commit was amended / force-pushed away
    for fix in (C1, C2, H):
        cs = [comment(f"CRITICAL: id=c1 reviewer=pr-challenger sha={gone}", at="2026-11-26T09:00:00Z"),
              verify(fix)] + passing_comments()
        res = run(comments=cs)
        failed_with(res, "critical 'c1' is open")
        assert any("not a commit of this PR" in n for n in res.notes), res.render()


def test_critical_reraised_at_current_sha_after_rebase_can_close():
    gone = "8" * 40
    cs = [comment(f"CRITICAL: id=c1 reviewer=pr-challenger sha={gone}", at="2026-11-26T09:00:00Z"),
          comment(f"CRITICAL: id=c1 reviewer=pr-challenger sha={C2}", at="2026-11-26T09:10:00Z"),
          verify(H)] + passing_comments()
    assert run(comments=cs).passed


def merge_history():
    """Two branches from base, A and B, merged at H. List order puts B after A."""
    A, B = "a" * 40, "b" * 40
    base = "0" * 40
    commits = [{"sha": A, "parents": [{"sha": base}]}, {"sha": B, "parents": [{"sha": base}]},
               {"sha": H, "parents": [{"sha": A}, {"sha": B}]}]
    return A, B, commits


def test_verify_later_in_list_but_not_descendant_does_not_close():
    A, B, commits = merge_history()
    cs = [comment(f"CRITICAL: id=c1 reviewer=pr-challenger sha={A}", at="2026-11-26T09:00:00Z"),
          verify(B)] + passing_comments()
    res = run(commits=commits, comments=cs)
    failed_with(res, "critical 'c1' is open")
    assert any("not a descendant" in n for n in res.notes)


def test_verify_at_merge_descendant_closes():
    A, B, commits = merge_history()
    cs = [comment(f"CRITICAL: id=c1 reviewer=pr-challenger sha={A}", at="2026-11-26T09:00:00Z"),
          verify(H)] + passing_comments()
    assert run(commits=commits, comments=cs).passed


def test_commit_list_order_is_not_assumed():
    # Head not last, list reversed: ancestry comes from parent links, not positions.
    commits = list(reversed(make_commits()))
    cs = with_crit(verify(C2))
    assert run(commits=commits, comments=cs).passed


def test_commits_without_parent_links_cannot_close_a_critical():
    commits = [{"sha": C1}, {"sha": C2}, {"sha": H}]
    failed_with(run(commits=commits, comments=with_crit(verify(C2))), "critical 'c1' is open")


def test_head_missing_from_commit_list_fails_closed():
    commits = [{"sha": C1, "parents": []}, {"sha": C2, "parents": [{"sha": C1}]}, {"sha": OTHER, "parents": []}]
    failed_with(run(commits=commits), "does not contain the head SHA")


# Critical 2: CI counts only from a push run whose definition (H's blob) is the default branch's.

def test_ci_run_from_pr_rewriting_ci_definition_does_not_count():
    # H carries its own ci.yml (e.g. `exit 0`); its green push run must not count.
    res = run(tree=make_tree(ci_blob="e" * 40))
    failed_with(res, "is not the default branch's")


def test_ci_definition_missing_on_default_branch_fails_closed():
    failed_with(run(default_ci_blobs={CI_PATH: None}), "no blob on the default branch")
    failed_with(run(default_ci_blobs={}), "no blob on the default branch")


def test_ci_definition_missing_at_head_fails_closed():
    tree = make_tree()
    tree["tree"] = [e for e in tree["tree"] if e["path"] != CI_PATH]
    failed_with(run(tree=tree), "is not the default branch's")


def test_ci_symlinked_definition_at_head_does_not_count():
    tree = make_tree()
    for e in tree["tree"]:
        if e["path"] == CI_PATH:
            e["mode"] = "120000"
    failed_with(run(tree=tree), "is not the default branch's")


def test_green_pull_request_run_from_another_pr_base_never_counts():
    # wario C1: another PR with the same head and a base carrying a trivial ci.yml.
    # Its run is a newer, green pull_request run at H; it must not satisfy CI,
    # and it must not mask the real push run's failure either.
    attacker = ci_run(id=9, event="pull_request", created_at="2026-11-26T12:00:00Z", pull_requests=[])
    failed_with(run(runs=[attacker]), "no push run")
    real_failed = ci_run(id=1, conclusion="failure")
    failed_with(run(runs=[real_failed, attacker]), "completed/failure")


def test_fetch_reads_default_branch_blob_and_push_runs():
    gh = FakeGH([make_pr()])
    assert v.fetch_and_compute(gh, REPO, 1, CONFIG).passed
    assert any(p.startswith(f"repos/{REPO}/contents/.github/workflows/ci.yml?") for p in gh.paths), gh.paths
    assert any("actions/runs?" in p and "event=push" in p for p in gh.paths)


def test_fetch_default_blob_unreadable_fails_closed():
    failed_with(v.fetch_and_compute(FakeGH([make_pr()], contents_error=True), REPO, 1, CONFIG),
                "no blob on the default branch")


# Challenger I2 / wario N2: hidden, fenced, indented and quoted records are not records.

@pytest.mark.parametrize("wrap", [
    "```\n{}\n```", "~~~text\n{}\n~~~", "<!--\n{}\n-->", "<!-- {} -->", "    {}", "  {}", "> {}",
    "````\n```\n{}\n````",
])
def test_non_live_verdict_lines_are_not_records(wrap):
    cs = [comment(wrap.format(f"VERDICT: pass reviewer={r} sha={H}")) for r in ("pr-reviewer", "pr-challenger")]
    failed_with(run(comments=cs), "no VERDICT from pr-reviewer")


def test_unclosed_fence_hides_the_rest():
    body = "```\n" + "\n".join(f"VERDICT: pass reviewer={r} sha={H}" for r in ("pr-reviewer", "pr-challenger"))
    failed_with(run(comments=[comment(body)]), "no VERDICT from pr-reviewer")


def test_quoted_known_critical_in_rereview_does_not_reopen_or_fail():
    cs = with_crit(verify(C2), comment(f"Re-review. Previously:\n```\n{CRIT}\n```\nnow fixed.",
                                       at="2026-11-26T09:40:00Z"))
    res = run(comments=cs)
    assert res.passed, res.render()


@pytest.mark.parametrize("wrap", ["```\n{}\n```", "<!-- {} -->", "> {}", "    {}"])
def test_critical_only_in_hidden_or_quoted_form_fails_closed(wrap):
    body = wrap.format(f"CRITICAL: id=new reviewer=wario sha={C2}")
    res = run(comments=passing_comments() + [comment(body, at="2026-11-26T11:00:00Z")])
    assert not res.passed, res.render()
    assert any("critical" in r and "'new'" in r or "unparseable critical" in r for r in res.reasons), res.render()


# Wario I1: CRITICAL parsing fails closed, not open.

def test_crlf_records_parse():
    cs = [comment(f"VERDICT: pass reviewer={r} sha={H}\r\nnotes\r\n") for r in ("pr-reviewer", "pr-challenger")]
    assert run(comments=cs).passed
    crit = comment(f"CRITICAL: id=c1 reviewer=pr-challenger sha={C1}\r\nDetails\r\n", at="2026-11-26T09:00:00Z")
    failed_with(run(comments=[crit] + passing_comments()), "critical 'c1' is open")


def test_uppercase_hex_sha_parses():
    crit = comment(f"CRITICAL: id=c1 reviewer=pr-challenger sha={C1.upper().replace('1', 'A')}",
                   at="2026-11-26T09:00:00Z")
    failed_with(run(comments=[crit] + passing_comments()), "critical 'c1' is open")


@pytest.mark.parametrize("line", [
    f"CRITICAL: id=c1 reviewer=pr-challenger sha={C1} (see below)",
    f"**CRITICAL:** id=c1 reviewer=pr-challenger sha={C1}",
    f"- CRITICAL: id=c1 reviewer=pr-challenger sha={C1}",
    f"CRITICAL: id=c1 reviewer=pr-challenger sha={C1[:12]}",
    f"critical: id=c1 reviewer=pr-challenger sha={C1}",
    f"CRITICAL id=c1 sha={C1}",
])
def test_malformed_critical_fails_closed(line):
    failed_with(run(comments=passing_comments() + [comment(line, at="2026-11-26T11:00:00Z")]),
                "unparseable critical")


def test_critical_prose_without_fields_is_not_a_critical():
    body = "## Critical (0)\nNo critical findings. Verdict below.\n"
    assert run(comments=passing_comments() + [comment(body, at="2026-11-26T11:00:00Z")]).passed


def test_untrusted_malformed_critical_is_ignored():
    body = f"**CRITICAL:** id=x reviewer=wario sha={C1}"
    assert run(comments=passing_comments() + [comment(body, login="mallory", at="2026-11-26T11:00:00Z")]).passed


def test_records_in_review_bodies_and_review_comments_count():
    reviews = [{"body": f"VERDICT: pass reviewer=pr-reviewer sha={H}", "user": {"login": BOT},
                "submitted_at": "2026-11-26T10:00:00Z", "state": "COMMENTED"}]
    cs = [comment(f"VERDICT: pass reviewer=pr-challenger sha={H}")]
    assert run(comments=cs, reviews=reviews).passed
    rc = [{"body": f"CRITICAL: id=r1 reviewer=pr-challenger sha={C1}", "user": {"login": BOT},
           "created_at": "2026-11-26T09:00:00Z", "updated_at": "2026-11-26T09:00:00Z"}]
    failed_with(run(review_comments=rc), "critical 'r1' is open")


def test_pending_review_is_not_read():
    reviews = [{"body": f"VERDICT: pass reviewer=pr-reviewer sha={H}", "user": {"login": BOT},
                "submitted_at": None, "state": "PENDING"}]
    cs = [comment(f"VERDICT: pass reviewer=pr-challenger sha={H}")]
    failed_with(run(comments=cs, reviews=reviews), "no VERDICT from pr-reviewer")


def test_fetch_reads_reviews_and_review_comments():
    rc = [{"body": f"CRITICAL: id=r1 reviewer=pr-challenger sha={C1}", "user": {"login": BOT},
           "created_at": "2026-11-26T09:00:00Z", "updated_at": "2026-11-26T09:00:00Z"}]
    failed_with(v.fetch_and_compute(FakeGH([make_pr()], review_comments=rc), REPO, 1, CONFIG),
                "critical 'r1' is open")


# Wario I2: records in an edited comment fail closed.

def test_edited_record_comment_fails_closed():
    c = comment(f"VERDICT: pass reviewer=pr-challenger sha={H}", at="2026-11-26T10:01:00Z")
    c["updated_at"] = "2026-11-26T12:00:00Z"
    failed_with(run(comments=passing_comments(reviewers=("pr-reviewer",)) + [c]), "was edited")


def test_edited_human_comment_without_records_is_fine():
    c = comment("typo fixed in prose", login="acardote", at="2026-11-26T10:05:00Z")
    c["updated_at"] = "2026-11-26T12:00:00Z"
    assert run(comments=passing_comments() + [c]).passed


def test_unedited_comment_with_equal_timestamps_passes():
    cs = passing_comments()
    for c in cs:
        c["updated_at"] = c["created_at"]
    assert run(comments=cs).passed


# Challenger I6: critical ids are unique per PR.

def test_critical_id_reused_by_another_reviewer_fails_closed():
    cs = with_crit(verify(C2), comment(f"CRITICAL: id=c1 reviewer=wario sha={C2}", at="2026-11-26T09:45:00Z"))
    failed_with(run(comments=cs), "was reused by 'wario'")


# Challenger I3: PR context checks and the importer contract.

def test_draft_pr_fails():
    failed_with(run(pr=make_pr(draft=True)), "draft")


def test_pr_not_based_on_default_branch_fails():
    failed_with(run(pr=make_pr(base={"ref": "ws/x-base", "repo": {"full_name": REPO, "default_branch": "main"}})),
                "is not the default branch")


def test_default_branch_unknown_fails_closed():
    failed_with(run(pr=make_pr(base={"ref": "main", "repo": {"full_name": REPO}})), "default branch unknown")


def test_compute_verdict_never_raises_on_garbage():
    res = run(pr=make_pr(labels=["weight:standard"]))  # labels as strings: AttributeError inside
    failed_with(res, "cannot compute verdict (fail closed): AttributeError")


class Resp(io.BytesIO):
    def __init__(self, data, link=None):
        super().__init__(json.dumps(data).encode())
        self.headers = {"Link": link} if link else {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def url_opener(routes, calls):
    """Fake urlopen keyed by URL path (query ignored except for paging)."""
    def opener(req, timeout):
        calls.append(req.full_url)
        path = req.full_url.split("https://api.example/", 1)[1].split("?")[0]
        val = routes[path]
        if callable(val):
            return val()
        return Resp(val)
    return opener


def api_routes():
    base = f"repos/{REPO}"
    return {
        f"{base}/pulls/1": make_pr(),
        f"{base}/pulls/1/files": make_files(),
        f"{base}/pulls/1/commits": make_commits(),
        f"{base}/issues/1/comments": passing_comments(),
        f"{base}/pulls/1/reviews": [],
        f"{base}/pulls/1/comments": [],
        f"{base}/git/trees/{H}": make_tree(),
        f"{base}/contents/.github/workflows/ci.yml": {"type": "file", "sha": CI_BLOB},
        f"{base}/actions/runs": {"workflow_runs": [ci_run()]},
    }


def test_importable_from_another_cwd_and_end_to_end(tmp_path, monkeypatch):
    import importlib.util
    monkeypatch.chdir(tmp_path)
    spec = importlib.util.spec_from_file_location("verdict_import_probe", HERE / "verdict.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, mod)  # required before exec (dataclasses)
    spec.loader.exec_module(mod)
    calls = []
    gh = mod.GitHub("t", "https://api.example", opener=url_opener(api_routes(), calls), sleep=lambda s: None)
    res = mod.fetch_and_compute(gh, REPO, 1, CONFIG)
    assert res.passed, res.render()


def test_transport_errors_become_verdict_error_after_retries():
    import http.client
    calls, sleeps = [], []

    def boom():
        raise http.client.IncompleteRead(b"x")

    routes = api_routes()
    routes[f"repos/{REPO}/pulls/1"] = boom
    gh = v.GitHub("t", "https://api.example", opener=url_opener(routes, calls), sleep=sleeps.append)
    with pytest.raises(v.VerdictError, match="after 3 attempts"):
        v.fetch_and_compute(gh, REPO, 1, CONFIG)
    assert len(calls) == 3 and sleeps == [1, 2]


def test_transient_5xx_is_retried_then_succeeds():
    calls, state = [], {"n": 0}
    routes = api_routes()
    pr = routes[f"repos/{REPO}/pulls/1"]

    def flaky():
        state["n"] += 1
        if state["n"] == 1:
            raise urllib.error.HTTPError("u", 503, "busy", {}, None)
        return Resp(pr)

    routes[f"repos/{REPO}/pulls/1"] = flaky
    gh = v.GitHub("t", "https://api.example", opener=url_opener(routes, calls), sleep=lambda s: None)
    assert v.fetch_and_compute(gh, REPO, 1, CONFIG).passed


def test_404_is_not_retried():
    calls = []

    def nf():
        raise urllib.error.HTTPError("u", 404, "nf", {}, None)

    routes = api_routes()
    routes[f"repos/{REPO}/pulls/1"] = nf
    gh = v.GitHub("t", "https://api.example", opener=url_opener(routes, calls), sleep=lambda s: None)
    with pytest.raises(v.VerdictError, match="HTTP 404"):
        v.fetch_and_compute(gh, REPO, 1, CONFIG)
    assert len(calls) == 1


def test_pagination_refuses_next_link_to_another_host():
    def opener(req, timeout):
        return Resp([1], '<https://evil.example/x?page=2>; rel="next"')

    gh = v.GitHub("t", "https://api.example", opener=opener)
    with pytest.raises(v.VerdictError, match="refusing to send the token"):
        gh.paged("x")


def test_main_catches_any_exception(monkeypatch, capsys):
    monkeypatch.setenv("GH_TOKEN", "t")

    def boom(*a, **k):
        raise RuntimeError("weird")

    monkeypatch.setattr(v, "fetch_and_compute", boom)
    assert v.main(["--repo", REPO, "--pr", "1", "--config", str(HERE / "config.json")]) == 2
    assert "fail closed" in capsys.readouterr().out


# Wario I3: symlinks and submodules.

def test_changed_symlink_is_heavy():
    pr = make_pr(labels=[{"name": "weight:trivial"}], additions=1, deletions=0, changed_files=1)
    files = make_files(["docs/link"])
    tree = make_tree([{"path": "docs/link", "mode": "120000", "type": "blob", "sha": "f" * 40}])
    failed_with(run(pr=pr, files=files, tree=tree, comments=passing_comments(reviewers=("pr-challenger",))),
                "lighter than objective weight heavy")


def test_existing_symlink_at_heavy_path_makes_later_edits_heavy():
    pr = make_pr(labels=[{"name": "weight:trivial"}], additions=1, deletions=0, changed_files=1)
    files = make_files(["docs/hooks/pre-commit"])  # target of .husky -> docs/hooks
    tree = make_tree([{"path": ".husky", "mode": "120000", "type": "blob", "sha": "f" * 40}])
    res = run(pr=pr, files=files, tree=tree, comments=passing_comments(reviewers=("pr-challenger",)))
    failed_with(res, "lighter than objective weight heavy")
    assert any("symlink at a security-boundary path" in n for n in res.notes)


def test_submodule_bump_is_heavy():
    pr = make_pr(labels=[{"name": "weight:trivial"}], additions=1, deletions=1, changed_files=1)
    files = make_files(["vendor/lib"])
    tree = make_tree([{"path": "vendor/lib", "mode": "160000", "type": "commit", "sha": "f" * 40}])
    failed_with(run(pr=pr, files=files, tree=tree), "lighter than objective weight heavy")


def test_truncated_tree_fails_closed():
    tree = make_tree()
    tree["truncated"] = True
    failed_with(run(tree=tree), "truncated")
    failed_with(run(tree={"tree": []}), "truncated")


# Wario I4/I5: case-insensitive matching, bare dirs, wider manifest coverage.

@pytest.mark.parametrize("path,heavy", [
    (".Claude/settings.json", True), (".CLAUDE/settings.local.json", True), ("Agents/x.md", True),
    ("claude.md", True), (".husky", True), (".Husky", True),
    ("web/package.json", True), ("svc/pyproject.toml", True), (".gitmodules", True), ("setup.py", True),
    ("pkg/setup.cfg", True), ("web/.npmrc", True), ("Dockerfile", True), ("svc/Dockerfile.dev", True),
    ("Makefile", True), ("conftest.py", True), ("tests/conftest.py", True), ("tests/fixtures/a.json", True),
    ("tools/lint-x.py", True), ("tools/_common.py", True), ("docs/policy/autonomy-v2.md", True),
    ("scripts/pa-session", True), ("src/app.py", False), ("docs/readme.md", False), ("tools/run.py", False),
])
def test_heavy_path_globs_round1(path, heavy):
    assert v.matches_any(path, CONFIG["heavy_paths"]) is heavy


# Wario I6: binary and mode-only changes.

def test_binary_or_mode_only_change_is_heavy():
    pr = make_pr(labels=[{"name": "weight:trivial"}], additions=0, deletions=0, changed_files=1)
    files = [{"filename": "bin/tool", "status": "modified", "additions": 0, "deletions": 0}]
    res = run(pr=pr, files=files, comments=passing_comments(reviewers=("pr-challenger",)))
    failed_with(res, "lighter than objective weight heavy")
    assert any("binary or mode-only" in n for n in res.notes)


def test_removed_binary_is_not_heavy_by_itself():
    pr = make_pr(labels=[{"name": "weight:trivial"}], additions=0, deletions=0, changed_files=1)
    files = [{"filename": "bin/old.png", "status": "removed", "additions": 0, "deletions": 0}]
    assert run(pr=pr, files=files, comments=passing_comments(reviewers=("pr-challenger",))).passed


# Verify I-a: a trusted line whose first word is "critical" and is not a strict record fails closed.

@pytest.mark.parametrize("line", [
    f"CRITICAL: id 1 reviewer pr-challenger sha {C1}",
    f"Critical: id: x reviewer: pr-challenger sha: {C1}",
    "CRITICAL - auth bypass in handler",
    "critical: auth bypass in handler",
    "**Critical** auth bypass in handler",
    "- **CRITICAL**: auth bypass in handler",
    "1. Critical: auth bypass in handler",
    "### CRITICAL: auth bypass in handler",
    "- [ ] `critical` auth bypass",
    "<b>CRITICAL</b> auth bypass",
    "CRITICAL",
    "## Critical",
    "## Critical (1)",
    "CRITICAL\u2014auth bypass",
])
def test_critical_led_line_fails_closed(line):
    failed_with(run(comments=passing_comments() + [comment(line, at="2026-11-26T11:00:00Z")]),
                "unparseable critical")


def test_critical_led_line_in_review_body_fails_closed():
    reviews = [{"body": "CRITICAL - auth bypass in handler", "user": {"login": BOT},
                "submitted_at": "2026-11-26T11:00:00Z", "state": "COMMENTED"}]
    failed_with(run(comments=passing_comments(), reviews=reviews), "unparseable critical")


@pytest.mark.parametrize("body", [
    "No critical findings.",
    "no critical findings",
    "Not critical; just a nit.",
    "## Critical (0)",
    "**Critical:** none",
    "Critical issues: 0",
    "- Critical findings (0)",
    "critical-path analysis looks fine",
    "Criticality is low.",
    "The critical path is unchanged.",
])
def test_prose_not_led_by_critical_passes(body):
    assert run(comments=passing_comments() + [comment(body, at="2026-11-26T11:00:00Z")]).passed


def test_strict_critical_record_is_a_record_not_unparseable():
    res = run(comments=with_crit())
    failed_with(res, "critical 'c1' is open")
    assert not any("unparseable" in r for r in res.reasons), res.render()


def test_untrusted_critical_led_line_is_ignored():
    c = comment("CRITICAL - auth bypass in handler", login="mallory", at="2026-11-26T11:00:00Z")
    assert run(comments=passing_comments() + [c]).passed


# Verify I-b: any edit of a machine-written comment fails closed, whatever it now says.

def test_edited_bot_comment_without_records_fails_closed():
    c = comment("all good now", at="2026-11-26T10:05:00Z")
    c["updated_at"] = "2026-11-26T12:00:00Z"
    failed_with(run(comments=passing_comments() + [c]), "machine-written comments are never edited")


def test_edited_bot_review_comment_fails_closed():
    rc = [{"body": "all good now", "user": {"login": BOT},
           "created_at": "2026-11-26T09:00:00Z", "updated_at": "2026-11-26T12:00:00Z"}]
    failed_with(run(comments=passing_comments(), review_comments=rc), "was edited")


def test_unedited_bot_comment_passes():
    c = comment("all good now", at="2026-11-26T10:05:00Z")
    c["updated_at"] = c["created_at"]
    assert run(comments=passing_comments() + [c]).passed


def test_missing_machine_authors_config_fails_closed():
    cfg = copy.deepcopy(CONFIG)
    del cfg["machine_record_authors"]
    failed_with(run(config=cfg), "cannot compute verdict")
