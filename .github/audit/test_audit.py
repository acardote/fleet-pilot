"""Tests for merge-audit (acardote/personal-assistant-ultra#581).

Run: python3 -m pytest -q -p no:cacheprovider .github/audit

Covers #581's acceptance and falsifiers against a stubbed GitHub API, plus the
review findings on fleet-pilot#4 (challenger C1-C2/I1-I9, wario C1-C3/I1-I13):
- a planted direct push is flagged (R2), including one laundered as a merge
  and one that is also a commit of a later-merged PR; a merge not made by
  merge.yml is flagged, including the #540 route (R1);
- a clean default-branch merge.yml merge that logged its recomputation passes;
- the state chain: deletion, rollback, run deletion, foreign audit code and
  anchor tampering are detected and fail closed; rebaseline is explicit;
- no list read can wedge the audit (bounded, resumable paging);
and the workflow file's hard rules.

The fake client honours query strings: a route registered with a query only
answers that query, so the parameters the audit sends are tested too.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import re
import sys
import urllib.error
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit as au  # noqa: E402

REPO = "acardote/fleet-pilot"
CFG = json.loads((HERE / "config.json").read_text())
WORKFLOW = HERE.parent / "workflows" / "audit.yml"
BASE = CFG["baseline_sha"]
M1 = "a" * 40      # squash merge commit
H1 = "b" * 40      # PR head at merge
D1 = "d" * 40      # direct push
OTHER = "e" * 40
WSHA = "f" * 40    # the commit that defined this audit run
REF = f"{REPO}/.github/workflows/merge.yml@refs/heads/main"
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
MERGED_AT = "2026-11-27T11:30:00Z"
CODE = {p: str(i) * 40 for i, p in enumerate(au.CODE_PATHS, start=1)}
WF_BLOBS = {p: "9" * 40 for p in CFG["watched_workflows"]}


class Incomplete(list):
    """A route value that `collect` reports as truncated (more pages exist)."""


class FakeGH(au.GitHub):
    def __init__(self, routes: dict):
        super().__init__("t")
        self.routes = routes
        self.posts: list = []
        self.patches: list = []
        self.calls: list = []

    def _lookup(self, path: str):
        self.calls.append(path)
        self.count += 1          # the API budget counts calls, as GitHub._call does
        for key in (path, path.split("?")[0]):
            if key in self.routes:
                v = self.routes[key]
                if isinstance(v, Exception):
                    raise v
                return copy.deepcopy(v)
        raise au.NotFound(f"no route {path}")

    def get(self, path):
        return self._lookup(path)

    def collect(self, path, key=None, max_pages=10, stop=None):
        raw = self.routes.get(path, self.routes.get(path.split("?")[0]))
        d = self._lookup(path)
        items = d.get(key) if key and isinstance(d, dict) else d
        complete = not isinstance(raw if not (key and isinstance(raw, dict)) else raw.get(key), Incomplete)
        out = []
        for it in items:
            if stop is not None and stop(it):
                return out, True
            out.append(it)
        return out, complete

    def download(self, path, max_bytes):
        return self._lookup(path)

    def post(self, path, body):
        self.posts.append((path, body))
        return {"number": 7}

    def patch(self, path, body):
        self.patches.append((path, body))
        return {}


def logzip(*lines: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("merge/1_merge.txt", "\n".join(f"2026-11-27T11:29:59.1234567Z {x}" for x in lines))
    return buf.getvalue()


def good_log(run_id=100, pr=5, head=H1, ref=REF):
    return logzip(f"workflow_ref={ref} run_id={run_id} event=schedule",
                  f"VERDICT-RECOMPUTED pr={pr} head={head} result=pass",
                  f"MERGED pr={pr} head={head} run_id={run_id} workflow_ref={ref}")


def merge_run(rid=100, event="schedule", branch="main", prs=None, status="completed", conclusion="success",
              created="2026-11-27T11:29:00Z", path=".github/workflows/merge.yml", head=BASE):
    return {"id": rid, "event": event, "head_branch": branch, "path": path, "status": status, "head_sha": head,
            "conclusion": conclusion, "created_at": created, "repository": {"full_name": REPO},
            "head_repository": {"full_name": REPO}, "pull_requests": prs or []}


def commit(sha, parents, committer="web-flow", verified=True, date="2026-11-27T11:30:00Z", author="acardote"):
    return {"sha": sha, "parents": [{"sha": p} for p in parents], "committer": {"login": committer},
            "author": {"login": author},
            "commit": {"verification": {"verified": verified}, "committer": {"date": date}, "author": {"name": author}}}


def cmp(commits, base=BASE, status="ahead"):
    return {"status": status, "total_commits": len(commits), "merge_base_commit": {"sha": base}, "commits": commits}


def tree(blobs):
    return {"truncated": False, "tree": [{"path": p, "sha": s, "type": "blob"} for p, s in blobs.items()]}


def world(**over) -> dict:
    """A repo where main moved from BASE to M1, a bot squash merge of PR #5."""
    r = {
        f"repos/{REPO}": {"default_branch": "main", "id": 1},
        f"repos/{REPO}/issues": [],
        f"repos/{REPO}/actions/workflows/audit.yml/runs": {"workflow_runs": []},
        f"repos/{REPO}/git/trees/{WSHA}": tree(CODE),
        f"repos/{REPO}/git/trees/main": tree(WF_BLOBS),
        f"repos/{REPO}/branches/main": {"commit": {"sha": M1}, "protected": True, "protection": {"enabled": True}},
        f"repos/{REPO}/compare/{BASE}...{M1}": cmp([commit(M1, [BASE])]),
        f"repos/{REPO}/commits/{M1}/pulls": [{"number": 5, "merged_at": MERGED_AT, "merge_commit_sha": M1}],
        f"repos/{REPO}/pulls/5": {"number": 5, "merged_at": MERGED_AT, "merged_by": {"login": "github-actions[bot]"},
                                  "head": {"sha": H1}, "state": "closed", "closed_at": MERGED_AT,
                                  "title": "feat: x", "labels": []},
        f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [merge_run()]},
        f"repos/{REPO}/actions/runs/100/logs": good_log(),
        f"repos/{REPO}/compare/{BASE}...main": {"status": "ahead"},
        f"repos/{REPO}/events": [],
        f"repos/{REPO}/rulesets": [{"id": 9, "name": "e5-main", "enforcement": "active",
                                    "updated_at": "2026-11-27T10:00:00Z", "target": "branch", "source_type": "Repository"}],
        f"repos/{REPO}/rulesets/9": {"id": 9, "rules": [{"type": "deletion"}]},
        f"repos/{REPO}/rules/branches/main": [{"type": "deletion"}],
        f"repos/{REPO}/actions/workflows": {"workflows": [{"path": p, "state": "active", "updated_at": "u"}
                                                          for p in CFG["watched_workflows"]]},
        f"repos/{REPO}/labels/do-not-auto-merge": {"id": 3, "name": "do-not-auto-merge", "color": "ff0000"},
        f"repos/{REPO}/issues/events": [],
        f"repos/{REPO}/issues/comments": [],
        f"repos/{REPO}/pulls/comments": [],
        f"repos/{REPO}/pulls": [],
        f"repos/{REPO}/actions/runs": {"workflow_runs": []},
        f"repos/{REPO}/branches": [{"name": "main", "commit": {"sha": M1}}],
    }
    r.update(over)
    return r


def auditor(routes, **kw) -> au.Auditor:
    return au.Auditor(FakeGH(routes), REPO, CFG, now=NOW, sleep=kw.pop("sleep", lambda s: None), **kw)


def rules_of(a):
    return [f["rule"] + ":" + f["key"].split(":")[1] for f in a.findings]


def env(rid=300, number=2, event="schedule", **kw):
    return au.RunEnv(rid, number, WSHA, "acardote", event, **kw)


# ---------------------------------------------------------------- R1 / R2

def test_clean_merge_yml_merge_passes():
    a = auditor(world())
    assert a.audit_commits(None, M1) == M1
    assert a.findings == []
    assert a.ledger == [f"{M1[:12]} PR #5 merged by github-actions[bot]: verified by run 100"]


def test_merge_run_window_query_is_sent():
    a = auditor(world())
    a.audit_commits(None, M1)
    q = [c for c in a.gh.calls if "merge.yml/runs" in c][0]
    assert "created=2026-11-27T10%3A30%3A00Z..2026-11-27T11%3A32%3A00Z" in q


def test_pull_request_target_run_based_on_main_is_trusted():
    run = merge_run(event="pull_request_target", branch="ws/x", prs=[{"number": 5, "base": {"ref": "main"}}])
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]}}))
    a.audit_commits(None, M1)
    assert a.findings == []


def test_falsifier_540_route_dispatch_from_branch_is_flagged():
    """#540 f-iii(1b): merge.yml dispatched on ws/x merged; its log is perfect. Still FLAG."""
    run = merge_run(event="workflow_dispatch", branch="ws/f-mod")
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]}}))
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:provenance"]
    assert "untrusted: event 'workflow_dispatch'" in a.findings[0]["summary"]
    assert f"repos/{REPO}/actions/runs/100/logs" not in a.gh.calls   # never read an untrusted run's log


def test_merge_by_other_workflow_is_flagged():
    """#540 f-iii(3): a ws push workflow merged; no merge.yml run at all."""
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": []}}))
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:provenance"]


@pytest.mark.parametrize("run", [
    merge_run(event="schedule", branch="ws/x"),
    merge_run(event="pull_request_target", prs=[]),
    merge_run(event="pull_request_target", prs=[{"number": 5, "base": {"ref": "ws/x"}}]),
    merge_run(event="push"),
    merge_run(path=".github/workflows/other.yml"),
    {**merge_run(), "repository": {"full_name": "evil/fork"}},
])
def test_untrusted_runs(run):
    assert au.merge_run_untrusted(run, REPO, "main", ".github/workflows/merge.yml") is not None


@pytest.mark.parametrize("log,why", [
    (logzip(f"MERGED pr=5 head={H1} run_id=100 workflow_ref={REF}"), "no VERDICT-RECOMPUTED"),
    (logzip(f"VERDICT-RECOMPUTED pr=5 head={H1} result=pass"), "no MERGED"),
    (good_log(head=OTHER), "no VERDICT"),
    (good_log(run_id=101), "no MERGED"),
    (good_log(ref=f"{REPO}/.github/workflows/merge.yml@refs/heads/ws/x"), "no MERGED"),
    (logzip(f"echo MERGED pr=5 head={H1} run_id=100 workflow_ref={REF}",
            f"x VERDICT-RECOMPUTED pr=5 head={H1} result=pass"), "no VERDICT"),
    (logzip(f"VERDICT-RECOMPUTED pr=5 head={H1} result=fail",
            f"MERGED pr=5 head={H1} run_id=100 workflow_ref={REF}"), "no VERDICT"),
    # the runner's echo of the step script (wario N1): markers there prove nothing
    (logzip("##[group]Run cat <<EOF", f"VERDICT-RECOMPUTED pr=5 head={H1} result=pass",
            f"MERGED pr=5 head={H1} run_id=100 workflow_ref={REF}", "##[endgroup]"), "no VERDICT"),
    (b"not a zip", "unreadable"),
])
def test_trusted_run_without_proof_is_flagged(log, why):
    a = auditor(world(**{f"repos/{REPO}/actions/runs/100/logs": log}))
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:provenance"]
    assert why in a.findings[0]["summary"]


def test_failed_merge_run_with_its_own_markers_proves_the_merge():
    """verify V-I3: fleet-pilot#3 exits 1 when ANOTHER candidate errored or was refused,
    after merging and logging this one. Its MERGED line still proves this merge."""
    run = merge_run(conclusion="failure")
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]}}))
    a.audit_commits(None, M1)
    assert a.findings == [] and "verified by run 100" in a.ledger[0]


def test_failed_merge_run_without_markers_is_still_flagged():
    run = merge_run(conclusion="failure")
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]},
                         f"repos/{REPO}/actions/runs/100/logs": logzip("merge refused: pr=5")}))
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:provenance"]


def test_run_created_after_merge_does_not_count():
    run = merge_run(created="2026-11-27T11:31:00Z")
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]}}))
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:provenance"]


def test_pending_merge_run_defers_the_commit():
    run = merge_run(status="in_progress", created="2026-11-27T11:29:00Z")
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]}}))
    assert a.audit_commits(None, M1) == BASE
    assert a.findings == [] and "still in progress" in a.notes[0]


def test_stuck_pending_run_is_flagged_after_the_limit():
    run = merge_run(status="in_progress", created="2026-11-27T08:00:00Z")
    r = world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]}})
    r[f"repos/{REPO}/pulls/5"]["merged_at"] = "2026-11-27T08:30:00Z"
    a = auditor(r)
    assert a.audit_commits(None, M1) == M1
    assert rules_of(a) == ["R1:provenance"] and "still 'in_progress'" in a.findings[0]["summary"]


def direct_world(**kw):
    return world(**{
        f"repos/{REPO}/branches/main": {"commit": {"sha": D1}},
        f"repos/{REPO}/compare/{M1}...{D1}": cmp([commit(D1, [M1], committer="acardote", verified=False, **kw)], base=M1),
        f"repos/{REPO}/commits/{D1}/pulls": [],
    })


def test_planted_direct_push_is_flagged():
    a = auditor(direct_world())
    assert a.audit_commits(M1, D1) == D1
    assert rules_of(a) == ["R2:direct"]
    assert "'acardote'" in a.findings[0]["summary"]


def test_laundered_direct_push_of_a_pr_head_is_flagged():
    """wario I6: pushing a PR's head to main marks the PR merged by the pusher."""
    r = world(**{
        f"repos/{REPO}/branches/main": {"commit": {"sha": H1}},
        f"repos/{REPO}/compare/{M1}...{H1}": cmp([commit(H1, [M1], committer="acardote", verified=False)], base=M1),
        f"repos/{REPO}/commits/{H1}/pulls": [{"number": 6, "merged_at": MERGED_AT, "merge_commit_sha": H1}],
        f"repos/{REPO}/pulls/6": {"number": 6, "merged_at": MERGED_AT, "merged_by": {"login": "acardote"},
                                  "head": {"sha": H1}, "title": "feat [7a]", "labels": []},
    })
    a = auditor(r)
    a.audit_commits(M1, H1)
    assert {"R2:not-github-merge", "R2:laundered", "R1:operator"} <= set(rules_of(a))


def test_direct_push_of_a_commit_of_a_later_merged_pr_is_still_flagged():
    """wario I7 / challenger nit 6: the carrier rule only excuses GitHub-made rebase commits."""
    c = "c" * 40
    r = world(**{
        f"repos/{REPO}/compare/{BASE}...{M1}": cmp([commit(c, [BASE], committer="acardote", verified=False),
                                                    commit(M1, [c])]),
        f"repos/{REPO}/commits/{c}/pulls": [{"number": 5, "merged_at": MERGED_AT, "merge_commit_sha": M1}],
    })
    a = auditor(r)
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R2:direct"] and a.findings[0]["key"] == f"R2:direct:{c}"


def test_rebase_merge_commits_made_by_github_pass():
    c = "c" * 40
    r = world(**{
        f"repos/{REPO}/compare/{BASE}...{M1}": cmp([commit(c, [BASE]), commit(M1, [c])]),
        f"repos/{REPO}/commits/{c}/pulls": [{"number": 5, "merged_at": MERGED_AT, "merge_commit_sha": M1}],
    })
    a = auditor(r)
    a.audit_commits(None, M1)
    assert a.findings == []


def test_second_parent_commits_of_a_merge_commit_are_not_audited_one_by_one():
    side = "5" * 40
    r = world(**{f"repos/{REPO}/compare/{BASE}...{M1}": cmp([commit(side, [BASE], committer="x", verified=False),
                                                             commit(M1, [BASE, side])])})
    a = auditor(r)
    a.audit_commits(None, M1)
    assert a.findings == [] and f"repos/{REPO}/commits/{side}/pulls" not in a.gh.calls


def test_first_parent_chain_not_reaching_the_base_is_flagged():
    """A merge whose FIRST parent is the side branch (not a GitHub merge)."""
    side = "5" * 40
    r = world(**{f"repos/{REPO}/compare/{BASE}...{M1}": cmp([commit(side, ["7" * 40], committer="x", verified=False),
                                                             commit(M1, [side, BASE])]),
                 f"repos/{REPO}/commits/{side}/pulls": []})
    a = auditor(r)
    a.audit_commits(None, M1)
    assert "R2:first-parent-break" in rules_of(a) and "R2:direct" in rules_of(a)


@pytest.mark.parametrize("title,labels,want", [
    ("feat(audit): x [7a]", [], "R1:operator"),
    ("feat(merge): y (#580, 7a, depends on #1)", [], "R1:operator"),
    ("feat: z", [{"name": "7a"}], "R1:operator"),
    ("feat: #17a fix", [], "R1:operator-unmarked"),
    ("feat: ordinary", [], "R1:operator-unmarked"),
])
def test_operator_merge_is_flagged_and_7a_marking_is_worded_apart(title, labels, want):
    r = world()
    r[f"repos/{REPO}/pulls/5"].update(merged_by={"login": "acardote"}, title=title, labels=labels)
    a = auditor(r)
    a.audit_commits(None, M1)
    assert rules_of(a) == [want]


def test_other_merger_is_flagged():
    r = world()
    r[f"repos/{REPO}/pulls/5"]["merged_by"] = {"login": "acardote-fleet[bot]"}
    a = auditor(r)
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:merger"]


@pytest.mark.parametrize("status", ["diverged", "behind"])
def test_force_push_is_flagged_once_and_the_head_moves_on(status):
    r = world(**{f"repos/{REPO}/compare/{OTHER}...{M1}": cmp([commit(M1, [BASE])] if status == "diverged" else [],
                                                             status=status)})
    a = auditor(r)
    assert a.audit_commits(OTHER, M1) == M1     # the next run does not re-flag the same rewrite
    assert "R2:rewrite" in rules_of(a)


def test_vanished_base_is_flagged_and_falls_back_to_listing():
    r = world(**{f"repos/{REPO}/commits": [commit(M1, [BASE]), commit(BASE, [])]})
    a = auditor(r)
    assert a.audit_commits(OTHER, M1) == M1
    assert rules_of(a)[0] == "R2:base-gone" and "R2:first-parent-break" not in rules_of(a)


def test_huge_range_is_flagged_not_wedged():
    """challenger C2/I3: over max_range_commits the audit FLAGs the unaudited remainder and goes on."""
    r = world(**{f"repos/{REPO}/compare/{BASE}...{M1}": {**cmp([]), "total_commits": 50000},
                 f"repos/{REPO}/commits": [commit(M1, ["7" * 40])]})
    a = auditor(r)
    assert a.audit_commits(BASE, M1) == M1
    assert rules_of(a)[0] == "R2:range-too-large"


def test_long_range_is_audited_over_several_runs():
    shas = [str(i) * 40 for i in range(1, 6)]
    commits = [commit(s, [p]) for s, p in zip(shas, [BASE] + shas[:-1])]
    r = world(**{f"repos/{REPO}/compare/{BASE}...{shas[-1]}": cmp(commits)})
    for s in shas:
        r[f"repos/{REPO}/commits/{s}/pulls"] = []
    cfg = {**CFG, "max_commits_per_run": 2}
    a = au.Auditor(FakeGH(r), REPO, cfg, now=NOW, sleep=lambda s: None)
    assert a.audit_commits(BASE, shas[-1]) == shas[1]
    assert len(a.findings) == 2 and "per-run budget" in a.notes[0]


def test_time_budget_stops_and_saves_progress():
    a = auditor(direct_world(), deadline=10, clock=lambda: 1000)
    assert a.audit_commits(M1, D1) == M1 and a.findings == []


def test_direct_pushes_sleep_at_most_once_per_run():
    """challenger C2: a 15 s sleep per direct commit wedged the audit on a batch."""
    shas = [str(i) * 40 for i in range(1, 9)]
    commits = [commit(s, [p], committer="x", verified=False, date="2026-11-27T11:58:00Z")
               for s, p in zip(shas, [BASE] + shas[:-1])]
    r = world(**{f"repos/{REPO}/compare/{BASE}...{shas[-1]}": cmp(commits)})
    for s in shas:
        r[f"repos/{REPO}/commits/{s}/pulls"] = []
    slept = []
    a = auditor(r, sleep=slept.append)
    a.audit_commits(BASE, shas[-1])
    assert slept == [15] and len(a.findings) == 8


def test_old_direct_commits_never_sleep():
    slept = []
    a = auditor(direct_world(), sleep=slept.append)
    a.audit_commits(M1, D1)
    assert slept == []


def test_push_events_flag_non_merge_pushes_with_actor():
    r = world(**{
        f"repos/{REPO}/events": [
            {"id": "13", "type": "PushEvent", "actor": {"login": "x"}, "payload": {"ref": "refs/heads/ws/a", "head": D1}},
            {"id": "12", "type": "PushEvent", "actor": {"login": "github-actions[bot]"}, "created_at": "t",
             "payload": {"ref": "refs/heads/main", "head": M1, "before": BASE}},
            {"id": "11", "type": "PushEvent", "actor": {"login": "acardote"}, "created_at": "t",
             "payload": {"ref": "refs/heads/main", "head": D1, "before": M1}},
            {"id": "9", "type": "PushEvent", "actor": {"login": "old"}, "payload": {"ref": "refs/heads/main", "head": D1}},
        ],
        f"repos/{REPO}/commits/{D1}/pulls": [],
    })
    a = auditor(r)
    cursor, seen = a.push_events(10, [])
    assert cursor == 13 and [f["key"] for f in a.findings] == ["R2:push:11"]
    assert "'acardote'" in a.findings[0]["summary"]


def test_late_event_below_the_cursor_is_still_read():
    """wario N8: an event surfacing late with an id below the cursor is not skipped."""
    late = {"id": "105", "type": "PushEvent", "actor": {"login": "acardote"},
            "payload": {"ref": "refs/heads/main", "head": D1}}
    r = world(**{f"repos/{REPO}/events": [{"id": "110", "type": "WatchEvent"}, late,
                                          {"id": "100", "type": "WatchEvent"}],
                 f"repos/{REPO}/commits/{D1}/pulls": []})
    a = auditor(r)
    cursor, seen = a.push_events(110, [100, 110])
    assert [f["key"] for f in a.findings] == ["R2:push:105"] and 105 in seen


def test_push_events_first_run_sets_cursor_only():
    r = world(**{f"repos/{REPO}/events": [{"id": "11", "type": "PushEvent", "payload": {"ref": "refs/heads/main", "head": D1}}]})
    a = auditor(r)
    assert a.push_events(None, [])[0] == 11 and a.findings == []


# ---------------------------------------------------------------- R3

def controls_snapshot(r, var="true"):
    return auditor(r).controls(None, {"AUTO_MERGE_ENABLED": var, "SECRETISH": "s3cr3t-value"})


def test_controls_unchanged_no_flags():
    r = world()
    snap = controls_snapshot(r)
    a = auditor(r)
    a.controls(snap, {"AUTO_MERGE_ENABLED": "true", "SECRETISH": "s3cr3t-value"})
    assert a.findings == [] and a.conditions == {}


def test_variable_values_are_hashed_except_public_ones():
    """wario I12 / challenger nit 5: raw values never reach the public state, log or comment."""
    snap = controls_snapshot(world())
    assert snap["vars"]["AUTO_MERGE_ENABLED"] == "true"
    assert "s3cr3t" not in json.dumps(snap) and snap["vars"]["SECRETISH"].startswith("hash:")
    a = auditor(world())
    a.controls(snap, {"AUTO_MERGE_ENABLED": "true", "SECRETISH": "other"})
    assert "s3cr3t" not in json.dumps(a.findings) and "other" not in json.dumps(a.findings)


@pytest.mark.parametrize("mutate,var,want", [
    (lambda r: r[f"repos/{REPO}/rulesets"][0].update(updated_at="2026-11-27T11:00:00Z"), "true", "R3:rulesets"),
    (lambda r: r[f"repos/{REPO}/rulesets/9"].update(rules=[]), "true", "R3:rulesets"),
    (lambda r: r.update({f"repos/{REPO}/rules/branches/main": []}), "true", "R3:rules"),
    (lambda r: None, "false", "R3:vars"),
    (lambda r: r[f"repos/{REPO}/actions/workflows"]["workflows"][2].update(updated_at="u2"), "true", "R3:workflows"),
])
def test_control_changes_are_flagged(mutate, var, want):
    r = world()
    snap = controls_snapshot(r)
    mutate(r)
    a = auditor(r)
    a.controls(snap, {"AUTO_MERGE_ENABLED": var, "SECRETISH": "s3cr3t-value"})
    assert want in rules_of(a)


@pytest.mark.parametrize("mutate,want", [
    (lambda r: r[f"repos/{REPO}/rulesets"][0].update(enforcement="disabled"), "R3:ruleset-missing"),
    (lambda r: r.update({f"repos/{REPO}/labels/do-not-auto-merge": au.NotFound("x")}), "R3:label-missing:do-not-auto-merge"),
    (lambda r: r[f"repos/{REPO}/actions/workflows"]["workflows"][2].update(state="disabled_manually"),
     "R3:workflow-state:.github/workflows/audit.yml"),
    (lambda r: r[f"repos/{REPO}/actions/workflows"]["workflows"].pop(0), "R3:workflow-missing:.github/workflows/merge.yml"),
])
def test_bad_control_states_are_open_conditions_even_without_history(mutate, want):
    r = world()
    mutate(r)
    a = auditor(r)
    a.controls(None, {})
    assert want in a.conditions


def test_a_repeated_toggle_is_flagged_every_time():
    """wario I2: change FLAG keys are unique per run, so false->true twice gives two FLAGs."""
    r = world()
    on, off = controls_snapshot(r, "true"), controls_snapshot(r, "false")
    keys = []
    for seq, (old, new) in enumerate([(off, "true"), (on, "false"), (off, "true")], start=1):
        a = auditor(r, seq=seq)
        a.controls(old, {"AUTO_MERGE_ENABLED": new, "SECRETISH": "s3cr3t-value"})
        keys += [f["key"] for f in a.findings]
    assert len(keys) == 3 and len(set(keys)) == 3


def test_kill_switch_label_events_are_flagged_and_read_only_down_to_the_cursor():
    r = world(**{f"repos/{REPO}/issues/events": [
        {"id": 52, "event": "labeled", "label": {"name": "auto-merge"}, "actor": {"login": "x"}, "issue": {"number": 4}},
        {"id": 51, "event": "unlabeled", "label": {"name": "do-not-auto-merge"}, "actor": {"login": "acardote"},
         "issue": {"number": 4}, "created_at": "t"},
        {"id": 40, "event": "labeled", "label": {"name": "do-not-auto-merge"}, "actor": {"login": "x"}, "issue": {"number": 1}},
    ]})
    a = auditor(r)
    assert a.label_events(50) == 52
    assert [f["key"] for f in a.findings] == ["R3:label-event:51"]


def test_issue_events_history_longer_than_the_bound_flags_a_gap_instead_of_failing():
    """wario I1 (confirmed live: PAU has 50 pages of issue events)."""
    r = world(**{f"repos/{REPO}/issues/events": Incomplete([{"id": 900, "event": "closed"}])})
    a = auditor(r)
    assert a.label_events(10) == 900
    assert rules_of(a) == ["R3:issue-events-gap"]


# ---------------------------------------------------------------- R7

def cm(cid, body, user="acardote-fleet[bot]", edited=False, pr=5):
    return {"id": cid, "body": body, "user": {"login": user}, "created_at": "2026-11-27T10:00:00Z",
            "updated_at": "2026-11-27T10:05:00Z" if edited else "2026-11-27T10:00:00Z",
            "html_url": f"https://github.com/{REPO}/pull/{pr}#issuecomment-{cid}",
            "issue_url": f"https://api.github.com/repos/{REPO}/issues/{pr}"}


REC = f"VERDICT: pass reviewer=pr-reviewer sha={H1}"


def rec_world(comments=(), **extra):
    return world(**{f"repos/{REPO}/issues/comments": list(comments), **extra})


def test_records_snapshot_tracks_only_trusted_record_like_pr_comments():
    issue_c = {**cm(4, REC), "html_url": f"https://github.com/{REPO}/issues/9#c", "issue_url": "x/issues/9"}
    snap, cur = auditor(rec_world([cm(1, REC), cm(2, "LGTM"), cm(3, REC, user="mallory"), issue_c])).records(None, None)
    assert list(snap) == ["ic:1"] and cur["ic"] == "2026-11-27T10:00:00Z"


def test_record_comment_query_is_since_sorted_ascending():
    a = auditor(rec_world())
    a.records(None, None)
    q = [c for c in a.gh.calls if c.startswith(f"repos/{REPO}/issues/comments?")][0]
    assert "since=2026-10-28T12%3A00%3A00Z" in q and "sort=updated" in q and "direction=asc" in q


def test_record_deleted_is_found_by_rotation():
    snap, cur = auditor(rec_world([cm(1, REC)])).records(None, None)
    snap["ic:1"]["v"] = "2026-11-27T11:00:00Z"
    a = auditor(rec_world())     # the since-listing no longer shows it; the GET 404s
    new, _ = a.records(snap, cur)
    assert [f["key"] for f in a.findings] == ["R7:deleted:ic:1"] and new == {}


def test_record_edited_away_is_flagged_and_still_tracked():
    snap, cur = auditor(rec_world([cm(1, REC)])).records(None, None)
    a = auditor(rec_world([cm(1, "never mind", edited=True)]), seq=4)
    new, _ = a.records(snap, cur)
    assert rules_of(a) == ["R7:edited"] and "ic:1" in new and a.findings[0]["key"].endswith(":4")


def test_record_edited_before_first_snapshot_is_flagged():
    a = auditor(rec_world([cm(1, REC, edited=True)]))
    a.records(None, None)
    assert rules_of(a) == ["R7:edited-before-snapshot"]


def test_reviews_of_updated_prs_are_tracked_and_edits_seen_in_rotation():
    rv = {"id": 8, "body": REC, "user": {"login": "acardote"}, "state": "COMMENTED", "submitted_at": "2026-11-27T10:00:00Z"}
    r = rec_world(**{f"repos/{REPO}/pulls": [{"number": 5, "updated_at": "2026-11-27T11:00:00Z"}],
                     f"repos/{REPO}/pulls/5/reviews": [rv]})
    snap, cur = auditor(r).records(None, None)
    assert "rv:5:8" in snap
    snap["rv:5:8"]["v"] = "2026-11-27T11:00:00Z"
    r2 = rec_world(**{f"repos/{REPO}/pulls/5/reviews/8": {**rv, "body": "changed"}})
    a = auditor(r2)
    a.records(snap, cur)
    assert rules_of(a) == ["R7:edited"]


def test_records_older_than_the_scope_age_out():
    snap = {"ic:1": {"pr": 3, "h": "x", "author": "acardote", "at": "2026-09-01T00:00:00Z", "v": "x"}}
    a = auditor(rec_world())
    assert a.records(snap, {})[0] == {} and a.findings == []


# ---------------------------------------------------------------- R4

def checks_world(cr, job, run=None):
    r = world(**{
        f"repos/{REPO}/pulls": [{"number": 5, "head": {"sha": H1}}],
        f"repos/{REPO}/commits/{H1}/check-runs": {"check_runs": [cr]},
    })
    if job is not None:
        r[f"repos/{REPO}/actions/jobs/{cr['id']}"] = job
    r[f"repos/{REPO}/actions/runs/55"] = run or {"id": 55, "path": ".github/workflows/verdict.yml",
                                                 "event": "pull_request_target", "repository": {"full_name": REPO},
                                                 "pull_requests": [{"number": 5, "base": {"ref": "main"}}]}
    return r


GOOD_CR = {"id": 77, "status": "completed", "app": {"id": 15368}}
GOOD_JOB = {"runner_name": "GitHub Actions 2", "steps": [{"name": "x"}], "run_id": 55}


@pytest.mark.parametrize("cr,job,run,flagged", [
    (GOOD_CR, GOOD_JOB, None, False),
    (GOOD_CR, {**GOOD_JOB, "runner_name": None, "steps": []}, None, True),           # #540 f-i
    (GOOD_CR, {**GOOD_JOB, "steps": []}, None, True),
    (GOOD_CR, None, None, True),
    ({**GOOD_CR, "app": {"id": 1}}, None, None, True),
    ({**GOOD_CR, "status": "in_progress"}, None, None, False),
    # wario I5: a real job named review-verdict in a branch push workflow
    (GOOD_CR, GOOD_JOB, {"id": 55, "path": ".github/workflows/ci.yml", "event": "push",
                         "repository": {"full_name": REPO}}, True),
    (GOOD_CR, GOOD_JOB, {"id": 55, "path": ".github/workflows/verdict.yml", "event": "push",
                         "repository": {"full_name": REPO}}, True),
    (GOOD_CR, GOOD_JOB, {"id": 55, "path": ".github/workflows/verdict.yml", "event": "pull_request_target",
                         "repository": {"full_name": REPO}, "pull_requests": [{"base": {"ref": "ws/x"}}]}, True),
])
def test_forged_checks(cr, job, run, flagged):
    a = auditor(checks_world(cr, job, run))
    ok, bad, _ = a.forged_checks([], {})
    assert bool(a.conditions) is flagged
    assert (77 in ok) is (not flagged and cr["status"] == "completed")


def test_forged_check_stays_open_without_refetching():
    a = auditor(checks_world(GOOD_CR, None))
    ok, bad, _ = a.forged_checks([], {})
    b = auditor(checks_world(GOOD_CR, None))
    b.forged_checks(ok, bad, {})
    assert "R4:77" in b.conditions and f"repos/{REPO}/actions/jobs/77" not in b.gh.calls


# ---------------------------------------------------------------- R5

def run_rec(rid, path=".github/workflows/ci.yml", branch="ws/a/x", event="push", sha=D1):
    return {"id": rid, "path": path, "head_branch": branch, "event": event, "head_sha": sha, "actor": {"login": "acardote"}}


@pytest.mark.parametrize("run,branch_blobs,flagged", [
    (run_rec(1), {".github/workflows/ci.yml": "8" * 40}, True),                 # modified ci.yml ran on a branch
    (run_rec(1, path=".github/workflows/evil.yml"), {".github/workflows/evil.yml": "8" * 40}, True),
    (run_rec(1, branch="v1", event="push"), {".github/workflows/ci.yml": "8" * 40}, True),   # tag push
    (run_rec(1), dict(WF_BLOBS), False),                                        # same definition as main
    (run_rec(1, branch="main", event="push"), {}, False),                       # main's own commit
    (run_rec(1, branch="main", event="push", sha=OTHER), {}, True),             # a tag named main
    (run_rec(1, event="pull_request_target"), {}, False),
    (run_rec(1, path="dynamic/pages/pages-build-deployment"), {}, False),
])
def test_workflow_runs_from_outside_the_default_branch(run, branch_blobs, flagged):
    r = world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": [run]},
                 f"repos/{REPO}/git/trees/{D1}": tree({**WF_BLOBS, **branch_blobs})})
    r[f"repos/{REPO}/compare/{D1}...main"] = {"status": "ahead"}          # D1 is on main
    r[f"repos/{REPO}/compare/{OTHER}...main"] = {"status": "diverged"}    # OTHER is not
    a = auditor(r)
    cur = a.foreign_runs({"id": 0, "at": "2026-11-27T11:40:00Z"})
    assert bool(a.findings) is flagged and cur["id"] == 1


def test_run_scan_overflow_is_flagged_and_moves_on():
    r = world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": Incomplete([run_rec(9, branch="main")])},
                 f"repos/{REPO}/compare/{D1}...main": {"status": "identical"}})
    a = auditor(r)
    assert a.foreign_runs(None)["id"] == 9 and rules_of(a) == ["R5:runs-overflow"]


def test_already_seen_runs_are_skipped():
    r = world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": [run_rec(5)]}})
    a = auditor(r)
    a.foreign_runs({"id": 5, "at": "x"})
    assert a.findings == []


def test_branch_workflow_files_flagged_once_per_tip():
    r = world(**{
        f"repos/{REPO}/branches": [{"name": "main", "commit": {"sha": M1}}, {"name": "ws/a/x", "commit": {"sha": D1}},
                                   {"name": "ws/b/y", "commit": {"sha": OTHER}}],
        f"repos/{REPO}/compare/main...{D1}": {"files": [{"filename": ".github/workflows/merge.yml"}]},
        f"repos/{REPO}/compare/main...{OTHER}": {"files": [{"filename": "src/x.py"}]},
    })
    a = auditor(r)
    snap = a.branch_workflows(None)
    assert [f["key"] for f in a.findings] == [f"R5:ws/a/x:{D1}"]
    b = auditor(r)
    b.branch_workflows(snap)
    assert b.findings == [] and not any("compare" in c for c in b.gh.calls)


def test_too_many_branches_is_a_condition_not_a_failure():
    r = world(**{f"repos/{REPO}/branches": Incomplete([{"name": "main", "commit": {"sha": M1}}])})
    a = auditor(r)
    a.branch_workflows(None)
    assert "R5:branches-truncated" in a.conditions


# ---------------------------------------------------------------- state chain (wario C1-C3, challenger I3/I5)

def audit_run(rid, number, branch="main", event="schedule", path=".github/workflows/audit.yml", head=WSHA,
              conclusion="success", status="completed", created="2026-11-27T11:45:00Z"):
    return {"id": rid, "run_number": number, "event": event, "head_branch": branch, "path": path, "head_sha": head,
            "conclusion": conclusion, "status": status, "created_at": created,
            "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO}}


def state_zip(state):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("state.json", json.dumps(state))
    return buf.getvalue()


def first_state():
    """A genuine state, from a genesis run_audit (run 200, #1) on world()."""
    gh = FakeGH(world())
    state, plan, a, issue = au.run_audit(gh, REPO, CFG, env(200, 1), {"AUTO_MERGE_ENABLED": "true"},
                                         now=NOW, sleep=lambda s: None)
    au.publish(gh, REPO, CFG, env(200, 1), state, plan, a, issue, dry_run=False)
    return state, gh


SUCCESS_Q = f"repos/{REPO}/actions/workflows/audit.yml/runs?branch=main&status=success"


def second_world(state, runs=None, anchor_entries=None, **over):
    runs = runs if runs is not None else [audit_run(200, 1)]
    body = au.render_anchor(REPO, anchor_entries if anchor_entries is not None else state["chain"])
    r = world(**{
        f"repos/{REPO}/actions/workflows/audit.yml/runs": {"workflow_runs": runs},
        f"repos/{REPO}/actions/runs/200/artifacts": {"artifacts": [{"id": 5, "name": "fleet-audit-state", "expired": False}]},
        f"repos/{REPO}/actions/artifacts/5/zip": state_zip(state),
        f"repos/{REPO}/issues": [{"number": 3, "title": CFG["findings_issue_title"], "body": "decoy by a person",
                                  "user": {"login": "acardote"}},
                                 {"number": 7, "title": CFG["findings_issue_title"], "body": body,
                                  "user": {"login": "github-actions[bot]"}}],
        f"repos/{REPO}/branches/main": {"commit": {"sha": M1}, "protected": True, "protection": {"enabled": True}},
    })
    r.update(over)
    return r


def load(r, e=None):
    a = auditor(r)
    anchor = au.parse_anchor(au.find_issue(a.gh, REPO, CFG)[1])
    return au.load_state(a.gh, REPO, CFG, e or env(), anchor, a), a


def test_first_ever_run_starts_the_chain():
    state, gh = first_state()
    e = state["chain"][-1]
    assert e["seq"] == 1 and e["prev"] == au.GENESIS and e["digest"] == au.entry_digest(e)
    assert e["state"] == au.state_digest(state) and state["issue"] == 7
    body = gh.posts[0][1]["body"]           # the findings issue is created with the chain
    assert au.parse_anchor(body)["entries"][-1]["seq"] == 1
    assert au.parse_anchor(gh.patches[-1][1]["body"])["entries"][-1]["digest"] == e["digest"]


def test_predecessor_state_loads_and_the_chain_continues():
    state, _ = first_state()
    gh = FakeGH(second_world(state))
    s2, plan, a, issue = au.run_audit(gh, REPO, CFG, env(), {"AUTO_MERGE_ENABLED": "true"}, now=NOW, sleep=lambda s: None)
    e2 = s2["chain"][-1]
    assert e2["seq"] == 2 and e2["prev"] == state["chain"][-1]["digest"] and plan["events"] == []
    q = [c for c in gh.calls if "audit.yml/runs?" in c]
    assert "branch=main&status=success" in q[0] and "created=%3E%3D" in q[1]


def test_open_conditions_resurface_every_run_but_are_posted_once():
    """wario C1: a condition is re-derived, never deduplicated away; Tier 0 reads it from each entry."""
    r = world(**{f"repos/{REPO}/labels/do-not-auto-merge": au.NotFound("x")})
    gh = FakeGH(r)
    s1, p1, a1, i1 = au.run_audit(gh, REPO, CFG, env(200, 1), {}, now=NOW, sleep=lambda s: None)
    assert [c["key"] for c in p1["new_conditions"]] == ["R3:label-missing:do-not-auto-merge"]
    r2 = second_world(s1, **{f"repos/{REPO}/labels/do-not-auto-merge": au.NotFound("x")})
    s2, p2, a2, i2 = au.run_audit(FakeGH(r2), REPO, CFG, env(), {}, now=NOW, sleep=lambda s: None)
    assert p2["new_conditions"] == [] and [o["key"] for o in s2["chain"][-1]["open"]] == ["R3:label-missing:do-not-auto-merge"]


def test_deleted_predecessor_artifact_fails_closed():
    state, _ = first_state()
    r = second_world(state, **{f"repos/{REPO}/actions/runs/200/artifacts": {"artifacts": []}})
    with pytest.raises(au.StateBroken, match="state artifact is gone"):
        load(r)


def test_untrusted_artifact_uploader_is_never_the_predecessor():
    state, _ = first_state()
    r = second_world(state, runs=[audit_run(250, 2, branch="ws/a/x", event="push"), audit_run(200, 1)])
    loaded, a = load(r, env(300, 3))
    assert loaded["run_id"] == 200


def test_deleted_audit_runs_leave_a_run_number_gap_and_fail_closed():
    """wario C3: deleting newer runs+artifacts rolls the state back; the run_number gap shows it.
    challenger2 I3: one listing can lag, so the first sighting is a FLAG and the gap fails closed
    only when it persists on a later run (>= 5 min)."""
    state, _ = first_state()
    loaded, a = load(second_world(state), env(300, 4))
    assert rules_of(a) == ["R6:runs-gap-suspect"] and a.gap_suspects["numbers"] == [2, 3]
    s2, *_ = au.run_audit(FakeGH(second_world(state)), REPO, CFG, env(300, 4), {}, now=NOW, sleep=lambda s: None)
    assert s2["gap_suspects"]["numbers"] == [2, 3]
    # next run, 15 min later: 2 and 3 still not listed -> fail closed
    r = second_world(s2, runs=[audit_run(300, 4)],
                     **{f"repos/{REPO}/actions/runs/300/artifacts": {"artifacts": [{"id": 9, "name": "fleet-audit-state"}]},
                        f"repos/{REPO}/actions/artifacts/9/zip": state_zip(s2)})
    later = au.Auditor(FakeGH(r), REPO, CFG, now=datetime(2026, 11, 27, 12, 15, tzinfo=timezone.utc))
    with pytest.raises(au.StateBroken, match=r"\[2, 3\] are still missing"):
        au.load_state(later.gh, REPO, CFG, env(310, 5), au.parse_anchor(au.find_issue(later.gh, REPO, CFG)[1]), later)


def test_a_suspected_gap_that_appears_later_was_listing_lag():
    state, _ = first_state()
    s2, *_ = au.run_audit(FakeGH(second_world(state)), REPO, CFG, env(300, 4), {}, now=NOW, sleep=lambda s: None)
    r = second_world(s2, runs=[audit_run(300, 4), audit_run(250, 3, conclusion="cancelled"), audit_run(240, 2)],
                     **{f"repos/{REPO}/actions/runs/300/artifacts": {"artifacts": [{"id": 9, "name": "fleet-audit-state"}]},
                        f"repos/{REPO}/actions/artifacts/9/zip": state_zip(s2)})
    r[SUCCESS_Q] = {"workflow_runs": [audit_run(300, 4)]}
    later = au.Auditor(FakeGH(r), REPO, CFG, now=datetime(2026, 11, 27, 12, 15, tzinfo=timezone.utc))
    loaded = au.load_state(later.gh, REPO, CFG, env(310, 5), au.parse_anchor(au.find_issue(later.gh, REPO, CFG)[1]), later)
    assert loaded["run_id"] == 300 and later.gap_suspects is None and "listing lag" in later.notes[0]


@pytest.mark.parametrize("extra", [
    [dict(audit_run(210, 2), status="completed", conclusion="cancelled"),
     dict(audit_run(220, 3), status="completed", conclusion="skipped")],
    [dict(audit_run(210, 2), status="queued", conclusion=None),
     dict(audit_run(220, 3), status="in_progress", conclusion=None)],
    [dict(audit_run(210, 2), conclusion="failure"), dict(audit_run(220, 3, branch="ws/x", event="push"), conclusion="startup_failure")],
])
def test_cancelled_skipped_queued_and_running_runs_leave_no_gap(extra):
    """challenger2 I3, realistic shapes: concurrency cancels pending runs; they are listed, so no gap."""
    state, _ = first_state()
    r = second_world(state)
    r[f"repos/{REPO}/actions/workflows/audit.yml/runs"] = {"workflow_runs": [audit_run(200, 1)] + extra}
    r[SUCCESS_Q] = {"workflow_runs": [audit_run(200, 1)]}
    loaded, a = load(r, env(300, 4))
    assert loaded["run_id"] == 200 and a.findings == [] and a.gap_suspects is None


def test_a_number_missing_only_from_the_created_filter_is_listing_lag():
    state, _ = first_state()
    r = second_world(state)
    created_q = "repos/{}/actions/workflows/audit.yml/runs?created=%3E%3D2026-11-27T11%3A45%3A00Z".format(REPO)
    r[created_q] = {"workflow_runs": [audit_run(200, 1)]}               # the search view lags
    r[f"repos/{REPO}/actions/workflows/audit.yml/runs"] = {"workflow_runs": [audit_run(200, 1), audit_run(210, 2)]}
    r[SUCCESS_Q] = {"workflow_runs": [audit_run(200, 1)]}
    loaded, a = load(r, env(300, 3))
    assert a.findings == [] and a.gap_suspects is None


def test_anchor_ahead_from_a_successful_run_is_a_rollback():
    """wario C3 with the runs' artifacts deleted but the run kept: the anchor shows the newer seq."""
    state, _ = first_state()
    later = dict(state["chain"][-1], seq=2, run_id=260, prev=state["chain"][-1]["digest"])
    later["digest"] = au.entry_digest(later)
    r = second_world(state, anchor_entries=state["chain"] + [later],
                     **{f"repos/{REPO}/actions/runs/260": audit_run(260, 2)})
    r[SUCCESS_Q] = {"workflow_runs": [audit_run(200, 1)]}
    r[f"repos/{REPO}/actions/workflows/audit.yml/runs"] = {"workflow_runs": [audit_run(200, 1), audit_run(260, 2)]}
    with pytest.raises(au.StateBroken, match="rollback"):
        load(r, env(300, 3))


def test_anchor_ahead_naming_a_deleted_run_is_a_rollback():
    state, _ = first_state()
    later = dict(state["chain"][-1], seq=2, run_id=260)
    later["digest"] = au.entry_digest(later)
    r = second_world(state, anchor_entries=state["chain"] + [later])
    with pytest.raises(au.StateBroken, match="no longer exists"):
        load(r)


def test_anchor_entry_of_a_failed_run_was_never_committed():
    state, _ = first_state()
    later = dict(state["chain"][-1], seq=2, run_id=260)
    later["digest"] = au.entry_digest(later)
    failed = audit_run(260, 2, conclusion="failure")
    r = second_world(state, anchor_entries=state["chain"] + [later], **{f"repos/{REPO}/actions/runs/260": failed})
    r[SUCCESS_Q] = {"workflow_runs": [audit_run(200, 1)]}
    r[f"repos/{REPO}/actions/workflows/audit.yml/runs"] = {"workflow_runs": [audit_run(200, 1), failed]}
    loaded, a = load(r, env(300, 3))
    assert loaded["run_id"] == 200 and "never committed" in a.notes[0]


def test_forged_anchor_entry_is_flagged_and_overwritten():
    state, _ = first_state()
    forged = dict(state["chain"][-1], seq=2, run_id=261)
    forged["digest"] = au.entry_digest(forged)
    r = second_world(state, anchor_entries=state["chain"] + [forged],
                     **{f"repos/{REPO}/actions/runs/261": audit_run(261, 9, branch="ws/x", event="push")})
    loaded, a = load(r)
    assert loaded and rules_of(a) == ["R6:anchor-forged"]


def test_edited_anchor_entry_is_flagged():
    state, _ = first_state()
    edited = dict(state["chain"][-1], flags=[])
    edited["digest"] = au.entry_digest(edited) + "0"
    r = second_world(state, anchor_entries=[edited])
    loaded, a = load(r)
    assert rules_of(a) == ["R6:anchor-mismatch"]


def test_no_successful_run_but_a_chain_in_the_anchor_fails_closed():
    state, _ = first_state()
    r = second_world(state, runs=[])
    with pytest.raises(au.StateBroken, match="audit runs were deleted"):
        load(r)


def test_state_from_other_audit_code_fails_closed():
    """wario C2: an altered audit merged and reverted forged state; its run ran other code."""
    state, _ = first_state()
    alt = "6" * 40
    r = second_world(state, runs=[audit_run(200, 1, head=alt)],
                     **{f"repos/{REPO}/git/trees/{alt}": tree({**CODE, ".github/audit/audit.py": "0" * 40})})
    with pytest.raises(au.StateBroken, match="other audit code"):
        load(r)


def test_previous_code_listed_in_config_is_accepted():
    state, _ = first_state()
    alt = "6" * 40
    old = {**CODE, ".github/audit/audit.py": "0" * 40}
    r = second_world(state, runs=[audit_run(200, 1, head=alt)], **{f"repos/{REPO}/git/trees/{alt}": tree(old)})
    a = auditor(r)
    cfg = {**CFG, "accepted_previous_code": [au.code_digest_of(old)]}
    anchor = au.parse_anchor(au.find_issue(a.gh, REPO, cfg)[1])
    assert au.load_state(a.gh, REPO, cfg, env(), anchor, a)["run_id"] == 200


def test_tampered_state_content_fails_closed():
    state, _ = first_state()
    bad = copy.deepcopy(state)
    bad["head"] = OTHER
    r = second_world(state, **{f"repos/{REPO}/actions/artifacts/5/zip": state_zip(bad)})
    with pytest.raises(au.StateBroken, match="does not match its chain entry"):
        load(r)


def test_a_gap_since_the_previous_run_is_flagged():
    """wario I3: a disable-act-re-enable window shows as a gap."""
    state, _ = first_state()
    a = au.Auditor(FakeGH(second_world(state)), REPO, CFG, now=datetime(2026, 11, 27, 13, 30, tzinfo=timezone.utc))
    anchor = au.parse_anchor(au.find_issue(a.gh, REPO, CFG)[1])
    au.load_state(a.gh, REPO, CFG, env(), anchor, a)
    assert rules_of(a) == ["R6:gap"]


def test_rebaseline_is_explicit_flagged_and_continues_the_sequence():
    state, _ = first_state()
    r = second_world(state, **{f"repos/{REPO}/actions/runs/200/artifacts": {"artifacts": []}})
    with pytest.raises(au.StateBroken):
        au.run_audit(FakeGH(r), REPO, CFG, env(), {}, now=NOW, sleep=lambda s: None)
    e = env(event="workflow_dispatch", rebaseline="fresh", reason="artifact expired")
    s2, plan, a, issue = au.run_audit(FakeGH(r), REPO, CFG, e, {}, now=NOW, sleep=lambda s: None)
    entry = s2["chain"][-1]
    assert entry["seq"] == 2 and entry["prev"] == state["chain"][-1]["digest"]
    assert entry["rebaseline"]["mode"] == "fresh" and entry["rebaseline"]["actor"] == "acardote"
    assert "R6:rebaseline" in rules_of(a)


def test_rebaseline_input_is_ignored_outside_workflow_dispatch():
    assert au.RunEnv(1, 1, WSHA, "a", "schedule", rebaseline="fresh").rebaseline == ""


def test_broken_state_is_reported_in_the_anchor_without_touching_the_chain():
    state, _ = first_state()
    gh = FakeGH({})
    au.mark_broken(gh, REPO, 7, {"entries": state["chain"]}, "state artifact is gone")
    doc = au.parse_anchor(gh.patches[0][1]["body"])
    assert doc["status"] == "broken" and doc["entries"] == state["chain"]


def test_every_flag_is_posted_in_chunks_never_truncated():
    """wario I11: 60 000 chars cut FLAGs off; now the comment is split."""
    many = [au.finding("R2", f"R2:direct:{i}", "x" * 180) for i in range(800)]
    text = au.render(many, [], [], [], [], "u", 3)
    parts = au.chunks(text)
    assert len(parts) > 1 and all(len(p) <= au.COMMENT_CHUNK for p in parts)
    assert sum(p.count("`FLAG`") for p in parts) == 800


def test_anchor_keeps_the_newest_entries_within_the_budget():
    entries = [{"seq": i, "pad": "x" * 2000} for i in range(100)]
    doc = au.parse_anchor(au.render_anchor(REPO, entries))
    assert doc["entries"][-1]["seq"] == 99 and len(au.canon(doc["entries"])) <= au.ANCHOR_BUDGET + 2100


def test_render_neutralises_mentions():
    out = au.render([au.finding("R2", "k", "by @acardote")], [], [], [], [], "u", 1)
    assert "@acardote" not in out and "`FLAG` R2" in out


def test_summaries_cannot_inject_lines():
    """wario N6: names with newlines cannot start a log line or a markdown block."""
    f = au.finding("R5", "k", "branch 'x\n::add-mask::y\r'")
    assert "\n" not in f["summary"] and "\r" not in f["summary"]


CODE_DIGEST_VECTOR = "fdf55c5f654c86eca4ee387f9e474eb5cd97600eecb2f6c1a7c492346e01554f"
ENTRY_DIGEST_VECTOR = "4c3e4feb5ab43a4d95dcd2d77da18f0bea6665a60a3657d071b8dabefd364c7a"


def test_code_digest_vector_matches_the_front_door():
    """PAU tests/test_fleet_audit_check.py pins the same vector (audit_code_digest)."""
    blobs = {".github/workflows/audit.yml": "a" * 40, ".github/audit/audit.py": "b" * 40, ".github/audit/config.json": "c" * 40}
    assert au.code_digest_of(blobs) == CODE_DIGEST_VECTOR


def test_entry_digest_vector_matches_the_front_door():
    """PAU verifies chain entries with the same canonical JSON + SHA-256."""
    e = {"seq": 1, "prev": "genesis", "run_id": 10, "flags": [], "digest": "ignored"}
    assert au.entry_digest(e) == ENTRY_DIGEST_VECTOR


# ---------------------------------------------------------------- client

class FakeResp(io.BytesIO):
    def __init__(self, data: bytes, headers=None):
        super().__init__(data)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_collect_follows_links_and_never_raises_for_size():
    """challenger C1 / wario I1: paging is bounded and reports truncation instead of failing."""
    def opener(req, timeout=0):
        page = int(re.search(r"[?&]page=(\d+)", req.full_url).group(1)) if re.search(r"[?&]page=", req.full_url) else 1
        link = f'<https://api.github.com/repos/r/pulls?per_page=100&page={page + 1}>; rel="next"'
        return FakeResp(json.dumps([{"n": page}]).encode(), {"Link": link})

    gh = au.GitHub("t", opener=opener, sleep=lambda s: None)
    items, complete = gh.collect("repos/r/pulls", max_pages=3)
    assert items == [{"n": 1}, {"n": 2}, {"n": 3}] and complete is False
    items, complete = gh.collect("repos/r/pulls", max_pages=9, stop=lambda it: it["n"] == 2)
    assert items == [{"n": 1}] and complete is True


def test_rate_limit_waits_then_retries_or_fails_closed():
    """challenger I4: primary rate limits are 403s; they wait for the reset instead of failing at once."""
    calls = []

    def opener(req, timeout=0):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError(req.full_url, 403, "rate", {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "130"}, None)
        return FakeResp(b"{}")

    slept = []
    gh = au.GitHub("t", opener=opener, sleep=slept.append, clock=lambda: 100.0)
    assert gh.get("repos/r") == {} and slept == [31.0]
    gh2 = au.GitHub("t", sleep=lambda s: None, clock=lambda: 0.0, opener=lambda req, timeout=0: (_ for _ in ()).throw(
        urllib.error.HTTPError(req.full_url, 403, "rate", {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "99999"}, None)))
    with pytest.raises(au.AuditError, match="rate limited"):
        gh2.get("repos/r")


def test_plain_403_fails_closed_without_retry():
    gh = au.GitHub("t", sleep=lambda s: None, opener=lambda req, timeout=0: (_ for _ in ()).throw(
        urllib.error.HTTPError(req.full_url, 403, "no", {}, None)))
    with pytest.raises(au.AuditError, match="HTTP 403"):
        gh.get("repos/r")


def test_redirect_is_followed_without_the_token():
    seen = []

    def opener(req, timeout=0):
        seen.append((req.full_url, req.get_header("Authorization")))
        if req.full_url.startswith("https://api.github.com/"):
            raise urllib.error.HTTPError(req.full_url, 302, "Found", {"Location": "https://blob.example/x.zip"}, None)
        return FakeResp(b"ZIP")

    gh = au.GitHub("secret-token", opener=opener, sleep=lambda s: None)
    assert gh.download("repos/r/actions/runs/1/logs", 100) == b"ZIP"
    assert seen == [("https://api.github.com/repos/r/actions/runs/1/logs", "Bearer secret-token"),
                    ("https://blob.example/x.zip", None)]


def test_token_never_sent_off_the_api_host():
    gh = au.GitHub("t", opener=lambda *a, **k: FakeResp(b"{}"))
    with pytest.raises(au.AuditError):
        gh._call("https://evil.example/x")


def test_download_size_cap():
    gh = au.GitHub("t", opener=lambda *a, **k: FakeResp(b"x" * 50))
    with pytest.raises(au.AuditError):
        gh.download("repos/r/x", 10)


def test_not_found_and_retry():
    calls = []

    def opener(req, timeout=0):
        calls.append(1)
        code = 502 if len(calls) == 1 else 404
        raise urllib.error.HTTPError(req.full_url, code, "x", {}, None)

    gh = au.GitHub("t", opener=opener, sleep=lambda s: None)
    with pytest.raises(au.NotFound):
        gh.get("repos/r")
    assert len(calls) == 2


def test_wrong_default_branch_fails_closed():
    with pytest.raises(au.AuditError):
        au.run_audit(FakeGH(world(**{f"repos/{REPO}": {"default_branch": "master"}})), REPO, CFG, env(), {})


# ---------------------------------------------------------------- config and workflow file

def test_trusted_authors_match_verdict_config():
    verdict_cfg = json.loads((HERE.parent / "verdict" / "config.json").read_text())
    assert CFG["trusted_record_authors"] == verdict_cfg["trusted_record_authors"]


def test_record_regexes_match_verdict():
    src = (HERE.parent / "verdict" / "verdict.py").read_text()
    for name in ("RECORD_LIKE_RE", "CRITICAL_LIKE_RE"):
        m = re.search(rf"^{name} = re\.compile\((r\".*?\")\)$", src, re.M)
        assert m and eval(m.group(1)) == getattr(au, name).pattern  # noqa: S307 - literal from our own file


def test_config_has_no_dead_keys():
    assert "initial_commit_limit" not in CFG and CFG["max_gap_minutes"] < 60


def wf_text():
    return WORKFLOW.read_text()


def test_workflow_triggers_are_default_branch_only():
    t = wf_text()
    on = t.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert re.findall(r"^  ([a-z_]+):", on, re.M) == ["push", "schedule", "workflow_dispatch"]
    assert "branches: [main]" in on
    for bad in ("pull_request", "workflow_run", "issue_comment"):
        assert bad not in on


def test_workflow_permissions():
    t = wf_text()
    assert "\npermissions: {}\n" in t
    perms = t.split("    permissions:\n", 1)[1].split("    steps:", 1)[0]
    got = dict(re.findall(r"^      ([a-z-]+): (\w+)$", perms, re.M))
    assert got == {"contents": "read", "pull-requests": "read", "checks": "read", "actions": "read", "issues": "write"}


def test_workflow_guard_checkout_and_pins():
    t = wf_text()
    assert t.index("Refuse a definition not on the default branch") < t.index("actions/checkout")
    assert '.github/workflows/audit.yml@refs/heads/main"' in t
    assert "ref: ${{ github.workflow_sha }}" in t and "persist-credentials: false" in t
    for uses in re.findall(r"uses: (\S+)", t):
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", uses), uses
    assert "github.event.pull_request" not in t and "head_ref" not in t
    run_lines = "\n".join(re.findall(r"run: (.*)", t))
    run_blocks = "\n".join(re.findall(r"run: \|\n((?:          .*\n)+)", t))
    assert "${{" not in run_lines and "${{" not in run_blocks
    assert "REBASELINE: ${{ inputs.rebaseline }}" in t       # dispatch inputs only through env
    assert "if: steps.audit.outputs.noop != 'true'" in t.split("Save state for the next run", 1)[1].split("uses:", 1)[0]
    assert "id: audit" in t
    assert "name: fleet-audit-state" in t and CFG["state_artifact"] == "fleet-audit-state"


def test_script_stops_workflow_commands_before_printing_repo_text():
    src = (HERE / "audit.py").read_text()
    main_src = src.split("def main(", 1)[1]
    assert main_src.index("::stop-commands::") < main_src.index("run_audit(")


# ---------------------------------------------------------------- round 2 (verify pass)

def rerun_env(attempt=2):
    return au.RunEnv(300, 2, WSHA, "a", "schedule", run_attempt=attempt)


def test_a_rerun_of_a_run_that_already_succeeded_writes_nothing():
    """verify V-I4: "Re-run all jobs" must not rewrite the seq the first attempt wrote."""
    state, _ = first_state()
    r = second_world(state, **{f"repos/{REPO}/actions/runs/300/attempts/1": {"conclusion": "success"},
                               f"repos/{REPO}/actions/runs/300/artifacts": {"artifacts": [{"name": "fleet-audit-state"}]}})
    with pytest.raises(au.NoOp, match="attempt 1 already succeeded"):
        au.run_audit(FakeGH(r), REPO, CFG, rerun_env(), {})


def test_a_rerun_of_a_failed_run_audits_normally():
    """verify2 V2-I1: "Re-run failed jobs" after a transient failure must not become a success without state."""
    state, _ = first_state()
    r = second_world(state, **{f"repos/{REPO}/actions/runs/300/attempts/1": {"conclusion": "failure"}})
    s2, plan, a, issue = au.run_audit(FakeGH(r), REPO, CFG, rerun_env(), {}, now=NOW, sleep=lambda s: None)
    assert s2["chain"][-1]["seq"] == 2 and s2["run_id"] == 300


def test_a_rerun_whose_earlier_success_lost_its_artifact_fails_instead_of_wedging():
    """verify2 V2-I1: if the earlier attempt's artifact is not listed after a re-run, fail this attempt
    (a failed run is never a predecessor) rather than leave a successful run without state."""
    state, _ = first_state()
    r = second_world(state, **{f"repos/{REPO}/actions/runs/300/attempts/1": {"conclusion": "success"},
                               f"repos/{REPO}/actions/runs/300/artifacts": {"artifacts": []}})
    with pytest.raises(au.AuditError, match="not listed"):
        au.run_audit(FakeGH(r), REPO, CFG, rerun_env(), {})


def test_unreadable_attempts_fall_back_to_auditing_normally():
    state, _ = first_state()
    s2, *_ = au.run_audit(FakeGH(second_world(state)), REPO, CFG, rerun_env(3), {}, now=NOW, sleep=lambda s: None)
    assert s2["chain"][-1]["seq"] == 2


def test_a_rerun_of_an_old_failed_run_is_refused_not_a_success():
    """verify V-I4: it would otherwise append an entry and wedge the next run as a rollback."""
    state, _ = first_state()
    r = second_world(state, runs=[audit_run(200, 5)])
    with pytest.raises(au.AuditError, match="older than"):
        load(r, env(150, 3))


def test_rebaseline_continue_never_adopts_state_from_other_code():
    """verify V-I2: the forged state of an altered (then reverted) audit run is skipped."""
    real, _ = first_state()
    alt = "6" * 40
    forged = copy.deepcopy(real)
    forged["run_id"] = 260
    forged["head"] = OTHER
    e = dict(forged["chain"][-1], run_id=260, state=au.state_digest(forged))
    e["digest"] = au.entry_digest(e)
    forged["chain"][-1] = e
    r = second_world(real, runs=[audit_run(260, 2, head=alt), audit_run(200, 1)],
                     **{f"repos/{REPO}/git/trees/{alt}": tree({**CODE, ".github/audit/audit.py": "0" * 40}),
                        f"repos/{REPO}/actions/runs/260/artifacts": {"artifacts": [{"id": 6, "name": "fleet-audit-state"}]},
                        f"repos/{REPO}/actions/artifacts/6/zip": state_zip(forged)})
    st, run, skipped = au.newest_readable_state(FakeGH(r), REPO, CFG, env(300, 3))
    assert run["id"] == 200 and st["head"] == real["head"] and "ran audit code" in skipped[0]
    s2, plan, a, issue = au.run_audit(FakeGH(r), REPO, CFG, env(300, 3, event="workflow_dispatch", rebaseline="continue"),
                                      {}, now=NOW, sleep=lambda s: None)
    assert s2["chain"][-1]["rebaseline"]["adopted_run"] == 200 and "ran audit code" in s2["chain"][-1]["rebaseline"]["skipped"][0]


WITNESS_VECTOR = "fleet-audit-chain seq=7 digest=" + "ab" * 32 + " run_id=99 flags_total=2 r6=anchor-mismatch,rebaseline"


def test_witness_line_vector_matches_the_front_door():
    """PAU tests/test_fleet_audit_check.py parses the same line."""
    e = {"seq": 7, "digest": "ab" * 32, "run_id": 99, "flags_total": 2, "rebaseline": {"mode": "fresh"},
         "flags": [{"rule": "R6", "key": "R6:anchor-mismatch:3:9"}, {"rule": "R6", "key": "R6:gap:9"}]}
    assert au.witness_line(e) == WITNESS_VECTOR
    assert au.witness_line({"seq": 1, "digest": "c" * 64, "run_id": 2, "flags": []}).endswith("flags_total=0 r6=-")


def test_main_emits_exactly_one_witness_after_resuming_commands(monkeypatch, tmp_path, capsys):
    state, _ = first_state()
    fake = FakeGH(second_world(state))
    monkeypatch.setattr(au, "GitHub", lambda *a, **k: fake)
    for k, v in dict(GH_TOKEN="t", GITHUB_RUN_ID="300", GITHUB_RUN_NUMBER="2", GITHUB_WORKFLOW_SHA=WSHA,
                     GITHUB_EVENT_NAME="schedule", GITHUB_ACTOR="acardote", VARS_JSON="{}", GITHUB_RUN_ATTEMPT="1").items():
        monkeypatch.setenv(k, v)
    assert au.main(["--repo", REPO, "--config", str(HERE / "config.json"), "--state-out", str(tmp_path / "s.json")]) == 0
    out = capsys.readouterr().out.splitlines()
    notes = [x for x in out if x.startswith("::notice title=fleet-audit-chain::")]
    saved = json.loads((tmp_path / "s.json").read_text())
    assert notes == ["::notice title=fleet-audit-chain::" + au.witness_line(saved["chain"][-1])]
    resume = next(i for i, x in enumerate(out) if re.fullmatch(r"::[0-9a-f]{32}::", x))
    assert out.index(notes[0]) > resume


def test_main_noop_rerun_exits_zero_and_tells_the_upload_step(monkeypatch, tmp_path):
    state, _ = first_state()
    r = second_world(state, **{f"repos/{REPO}/actions/runs/300/attempts/1": {"conclusion": "success"},
                               f"repos/{REPO}/actions/runs/300/artifacts": {"artifacts": [{"name": "fleet-audit-state"}]}})
    monkeypatch.setattr(au, "GitHub", lambda *a, **k: FakeGH(r))
    out = tmp_path / "out"
    for k, v in dict(GH_TOKEN="t", GITHUB_RUN_ID="300", GITHUB_RUN_NUMBER="2", GITHUB_RUN_ATTEMPT="2",
                     GITHUB_OUTPUT=str(out)).items():
        monkeypatch.setenv(k, v)
    assert au.main(["--repo", REPO, "--config", str(HERE / "config.json"), "--state-out", str(tmp_path / "s.json")]) == 0
    assert not (tmp_path / "s.json").exists() and out.read_text() == "noop=true\n"


def test_capped_flags_can_be_rebuilt_from_the_posted_comments():
    """verify2 V2-M2: entries cap FLAGs at 25; flags_digest lets the front door verify the full posted list."""
    many = [au.finding("R2", f"R2:direct:{i}", "x " * 600 + "@someone") for i in range(120)]
    body = au.render_body(many, [], [], [], [])
    parts = au.chunks(body, au.COMMENT_CHUNK - 300)
    assert len(parts) > 1
    lines = [ln for p in parts for ln in p.splitlines() if ln.startswith("- `FLAG` ")]
    assert hashlib.sha256("\n".join(lines).encode()).hexdigest() == au.flags_digest(many)
    e = au.make_entry(2, "p", env(), M1, "c", "s", many, [], "t", None)
    assert len(e["flags"]) == 25 and e["flags_total"] == 120 and e["flags_digest"] == au.flags_digest(many)


def test_published_comment_parts_carry_run_and_seq():
    state, _ = first_state()
    r = second_world(state, **{f"repos/{REPO}/labels/do-not-auto-merge": au.NotFound("x")})
    gh = FakeGH(r)
    s2, plan, a, issue = au.run_audit(gh, REPO, CFG, env(), {}, now=NOW, sleep=lambda s: None)
    au.publish(gh, REPO, CFG, env(), s2, plan, a, issue, dry_run=False)
    posted = [b["body"] for p, b in gh.posts if p.endswith("/comments")]
    assert posted and posted[0].startswith(f"## merge-audit run https://github.com/{REPO}/actions/runs/300 (chain seq 2, part 1/1)")


def test_a_rebaseline_chains_from_the_adopted_state_not_the_anchor():
    """verify2 V2-M1: after a strip, the anchor's head is forged; a rebaseline that loaded the real
    state chains from it, and records the previous seq and FLAG count."""
    state, _ = first_state()
    forged = dict(state["chain"][-1], flags=[], flags_total=0, head=OTHER)
    forged["digest"] = au.entry_digest(forged)
    r = second_world(state, anchor_entries=[forged])
    e = env(event="workflow_dispatch", rebaseline="continue", reason="after strip")
    s2, *_ = au.run_audit(FakeGH(r), REPO, CFG, e, {}, now=NOW, sleep=lambda s: None)
    rb = s2["chain"][-1]
    assert rb["prev"] == state["chain"][-1]["digest"] != forged["digest"]
    assert rb["rebaseline"]["prev_seq"] == 1 and rb["rebaseline"]["prev_flags_total"] == state["chain"][-1]["flags_total"]


def test_issue_recreated_late_is_found_newest_first():
    fake = FakeGH(world(**{f"repos/{REPO}/issues?state=all&sort=created&direction=asc": [{"number": 1, "title": "x"}],
                           f"repos/{REPO}/issues?state=all&sort=created&direction=desc": [
                               {"number": 900, "title": CFG["findings_issue_title"], "user": {"login": "github-actions[bot]"},
                                "body": "b"}]}))
    assert au.find_issue(fake, REPO, CFG) == (900, "b")


def test_a_schedule_merge_run_whose_commit_is_not_on_main_proves_nothing():
    """addendum V-I3: a trusted run of the workflow at main, not a ref that only shares the name."""
    run = merge_run(head=OTHER)
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]},
                         f"repos/{REPO}/compare/{OTHER}...main": {"status": "diverged"}}))
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:provenance"] and "not on main" in a.findings[0]["summary"]


def test_integrity_flags_are_first_in_the_capped_entry():
    flags = [au.finding("R2", f"R2:direct:{i}", "x") for i in range(40)] + [au.finding("R6", "R6:anchor-mismatch:1:2", "y")]
    ordered = sorted(flags, key=lambda f: f["rule"] != "R6")
    e = au.make_entry(2, "p", env(), M1, "c", "s", ordered, [], "t", None)
    assert e["flags"][0]["rule"] == "R6" and "r6=anchor-mismatch" in au.witness_line(e)


def test_flag_line_vector_matches_the_front_door():
    """PAU tests/test_fleet_audit_check.py pins the same line."""
    assert au.flag_line({"rule": "R2", "key": "R2:direct:x", "summary": "by @a"}) == "- `FLAG` R2 `R2:direct:x`: by @​a"


# ---------------------------------------------------------------- challenger2 (round 5): I1, I2

BASE_SHA = "7" * 40


@pytest.mark.parametrize("branch_blob,base_blob,flagged", [
    ("8" * 40, "8" * 40, False),     # stale branch: unchanged since the branch point, main changed ci.yml later
    ("8" * 40, "5" * 40, True),      # the branch changed ci.yml
    ("8" * 40, None, True),          # the branch added a workflow main never had at the branch point
])
def test_r5_compares_with_main_at_the_branch_point(branch_blob, base_blob, flagged):
    """challenger2 I1: no FLAG flood for branches cut before a workflow change on main."""
    path = ".github/workflows/ci.yml"
    base_tree = {**WF_BLOBS}
    if base_blob is None:
        base_tree.pop(path)
    else:
        base_tree[path] = base_blob
    r = world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": [run_rec(1), run_rec(2, event="pull_request")]},
                 f"repos/{REPO}/git/trees/{D1}": tree({**WF_BLOBS, path: branch_blob}),
                 f"repos/{REPO}/compare/main...{D1}": {"merge_base_commit": {"sha": BASE_SHA}},
                 f"repos/{REPO}/git/trees/{BASE_SHA}": tree(base_tree)})
    a = auditor(r)
    a.foreign_runs({"id": 0, "at": "2026-11-27T11:40:00Z"})
    assert len(a.findings) == (2 if flagged else 0)


def test_run_scan_honours_the_api_budget_and_carries_the_rest():
    """challenger2 I2: a push flood never fails the run; the cursor stops at the last run checked."""
    runs = [dict(run_rec(i, sha=D1), created_at=f"2026-11-27T11:{i:02d}:00Z") for i in range(1, 6)]
    r = world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": runs},
                 f"repos/{REPO}/git/trees/{D1}": tree(WF_BLOBS)})
    a = auditor(r)
    a.call_limit = a.gh.count + 3            # listing + default tree + one more, then stop
    cur = a.foreign_runs({"id": 0, "at": "2026-11-27T11:00:00Z"})
    assert "R5:runs-backlog" in a.conditions and a.findings == []
    assert 0 < cur["id"] < 5 and cur["at"] < "2026-11-27T11:05:00Z"
    b = auditor(r)                            # next run, no budget pressure: finishes the rest
    cur2 = b.foreign_runs(cur)
    assert cur2["id"] == 5 and "R5:runs-backlog" not in b.conditions


def test_forged_checks_read_a_bounded_number_of_prs_and_keep_known_conditions():
    """challenger2 I2: one check-runs read per open PR every run does not scale; rotate, new heads first."""
    prs = [{"number": n, "head": {"sha": f"{n:040x}"}} for n in range(1, 6)]
    r = world(**{f"repos/{REPO}/pulls": prs})
    for p in prs:
        r[f"repos/{REPO}/commits/{p['head']['sha']}/check-runs"] = {"check_runs": []}
    cfg = {**CFG, "checks_prs_per_run": 2}
    bad = {"77": {"why": "is not an Actions job (forged)", "pr": "5", "head": f"{5:040x}"}}
    seen = {str(n): {"head": f"{n:040x}", "at": f"2026-11-27T10:0{n}:00Z"} for n in range(1, 6)}
    seen["3"]["head"] = "old"                 # PR 3's head moved: read first
    a = au.Auditor(FakeGH(r), REPO, cfg, now=NOW, sleep=lambda s: None)
    ok, bad2, seen2 = a.forged_checks([], bad, seen)
    reads = [c for c in a.gh.calls if "/check-runs" in c]
    assert len(reads) == 2 and f"{1:040x}" in reads[0] and f"{2:040x}" in reads[1]   # least recently read first
    assert "R4:77" in a.conditions and "R4:checks-backlog" in a.conditions and bad2["77"]["pr"] == "5"
    assert seen2["1"]["at"] == "2026-11-27T12:00:00Z"


def test_the_whole_run_stays_within_the_api_budget_under_a_flood():
    """challenger2 I2 end to end: 300 branch runs and 200 open PRs finish as a successful run."""
    runs = [dict(run_rec(i, sha=f"{i:040x}"), created_at="2026-11-27T11:50:00Z") for i in range(1, 301)]
    prs = [{"number": n, "head": {"sha": f"{n + 1000:040x}"}, "updated_at": "2026-01-01T00:00:00Z"} for n in range(1, 201)]
    r = world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": runs}, f"repos/{REPO}/pulls": prs})
    for i in range(1, 301):
        r[f"repos/{REPO}/git/trees/{i:040x}"] = tree(WF_BLOBS)
    for p in prs:
        r[f"repos/{REPO}/commits/{p['head']['sha']}/check-runs"] = {"check_runs": []}
    gh = FakeGH(r)
    state, plan, a, issue = au.run_audit(gh, REPO, CFG, env(200, 1), {}, now=NOW, sleep=lambda s: None)
    assert gh.count <= CFG["api_budget_per_run"] + 40      # the budget plus the fixed calls after the last check
    assert {"R5:runs-backlog", "R4:checks-backlog"} & {c["key"] for c in plan["conditions"]}


# ---------------------------------------------------------------- verify5 (round 6): V5-I1, V5-M1, V5-M2

def test_a_review_flood_cannot_starve_r5():
    """V5-I1: records may not spend the shares reserved for checks and runs."""
    prs = [{"number": n, "updated_at": f"2026-11-27T11:{n % 60:02d}:00Z", "head": {"sha": f"{n:040x}"}} for n in range(1, 400)]
    runs = [dict(run_rec(9000 + i, sha=D1), created_at="2026-11-27T11:50:00Z") for i in range(5)]
    r = world(**{f"repos/{REPO}/pulls": prs, f"repos/{REPO}/actions/runs": {"workflow_runs": runs},
                 f"repos/{REPO}/git/trees/{D1}": tree({**WF_BLOBS, ".github/workflows/ci.yml": "8" * 40}),
                 f"repos/{REPO}/compare/main...{D1}": {"merge_base_commit": {"sha": BASE_SHA}},
                 f"repos/{REPO}/git/trees/{BASE_SHA}": tree(WF_BLOBS)})
    for p in prs:
        r[f"repos/{REPO}/pulls/{p['number']}/reviews"] = []
        r[f"repos/{REPO}/commits/{p['head']['sha']}/check-runs"] = {"check_runs": []}
    gh = FakeGH(r)
    state, plan, a, issue = au.run_audit(gh, REPO, CFG, env(200, 1), {}, now=NOW, sleep=lambda s: None)
    assert [f["key"] for f in plan["events"] if f["key"].startswith("R5:run:")] == [f"R5:run:{9000 + i}" for i in range(5)]
    assert "R7:records-backlog" in {c["key"] for c in plan["conditions"]}


def test_a_backlog_that_persists_becomes_a_flag_naming_the_oldest_run():
    runs = [dict(run_rec(i, sha=D1), created_at=f"2026-11-27T11:{i:02d}:00Z") for i in range(1, 6)]
    r = world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": runs}, f"repos/{REPO}/git/trees/{D1}": tree(WF_BLOBS)})
    bl = {"runs": 0}
    keys = []
    for k in range(CFG["backlog_flag_after"]):
        a = auditor(r, seq=k + 1)
        a.call_limit = a.gh.count + 3
        a.foreign_runs({"id": 0, "at": "2026-11-27T11:00:00Z"}, bl)
        bl = a.backlogs["runs"]
        keys += [f["key"] for f in a.findings]
    assert keys == [f"R5:runs-backlog:{CFG['backlog_flag_after']}"]
    assert "Oldest waiting: run 2" in a.findings[0]["summary"] and "actor 'acardote'" in a.findings[0]["summary"]


def test_a_section_starved_to_zero_is_a_flag_at_once():
    runs = [dict(run_rec(1, sha=D1), created_at="2026-11-27T11:01:00Z")]
    a = auditor(world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": runs}}))
    a.call_limit = a.gh.count            # nothing left
    a.foreign_runs({"id": 0, "at": "2026-11-27T11:00:00Z"})
    assert [f["key"] for f in a.findings] == ["R5:runs-backlog:0"] and "starved" in a.findings[0]["summary"]


def test_a_run_deleted_while_waiting_in_the_backlog_is_flagged():
    pending = [{"id": 7, "path": ".github/workflows/ci.yml", "branch": "ws/x", "actor": "acardote"}]
    a = auditor(world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": []}}))
    a.foreign_runs({"id": 6, "at": "2026-11-27T11:00:00Z", "pending": pending})
    assert [f["key"] for f in a.findings] == ["R5:run-vanished:7"] and "'acardote'" in a.findings[0]["summary"]


@pytest.mark.parametrize("main_has_file,retired,flagged", [
    (True, False, False),     # stale branch, file still on main: accepted
    (False, False, True),     # main deleted the workflow since: its old version is not accepted
    (True, True, True),       # the old version is retired (config, 7a): not accepted
])
def test_an_old_main_version_is_accepted_only_while_main_keeps_the_file_and_it_is_not_retired(main_has_file, retired, flagged):
    """V5-M1."""
    path = ".github/workflows/ci.yml"
    old = "8" * 40
    main_tree = dict(WF_BLOBS) if main_has_file else {k: v for k, v in WF_BLOBS.items() if k != path}
    r = world(**{f"repos/{REPO}/actions/runs": {"workflow_runs": [run_rec(1)]},
                 f"repos/{REPO}/git/trees/main": tree(main_tree),
                 f"repos/{REPO}/git/trees/{D1}": tree({**WF_BLOBS, path: old}),
                 f"repos/{REPO}/compare/main...{D1}": {"merge_base_commit": {"sha": BASE_SHA}},
                 f"repos/{REPO}/git/trees/{BASE_SHA}": tree({**WF_BLOBS, path: old})})
    cfg = {**CFG, "retired_workflow_blobs": [old] if retired else []}
    a = au.Auditor(FakeGH(r), REPO, cfg, now=NOW, sleep=lambda s: None)
    a.foreign_runs({"id": 0, "at": "2026-11-27T11:40:00Z"})
    assert bool(a.findings) is flagged


def test_a_gap_recheck_that_cannot_complete_fails_closed():
    """V5-M2: flooding >1000 runs to make the re-check incomplete no longer disables the fail-closed."""
    state, _ = first_state()
    s2, *_ = au.run_audit(FakeGH(second_world(state)), REPO, CFG, env(300, 4), {}, now=NOW, sleep=lambda s: None)
    r = second_world(s2, runs=[audit_run(300, 4)] + [audit_run(400 + i, 10 + i) for i in range(3)],
                     **{f"repos/{REPO}/actions/runs/300/artifacts": {"artifacts": [{"id": 9, "name": "fleet-audit-state"}]},
                        f"repos/{REPO}/actions/artifacts/9/zip": state_zip(s2)})
    r[SUCCESS_Q] = {"workflow_runs": [audit_run(300, 4)]}
    r[f"repos/{REPO}/actions/workflows/audit.yml/runs?created=%3E%3D2026-11-27T11%3A45%3A00Z"] = \
        {"workflow_runs": Incomplete([audit_run(300, 4), audit_run(250, 3), audit_run(240, 2)])}
    later = au.Auditor(FakeGH(r), REPO, CFG, now=datetime(2026, 11, 27, 12, 15, tzinfo=timezone.utc))
    with pytest.raises(au.StateBroken, match="still missing"):
        au.load_state(later.gh, REPO, CFG, env(310, 5), au.parse_anchor(au.find_issue(later.gh, REPO, CFG)[1]), later)


def test_the_gap_suspect_kind_travels_in_the_witness():
    e = {"seq": 3, "digest": "c" * 64, "run_id": 5, "flags_total": 1,
         "flags": [{"rule": "R6", "key": "R6:runs-gap-suspect:5"}]}
    assert au.witness_line(e).endswith("r6=runs-gap-suspect")
