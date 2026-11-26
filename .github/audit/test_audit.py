"""Tests for merge-audit (acardote/personal-assistant-ultra#581).

Run: python3 -m pytest -q .github/audit

Covers #581's acceptance and falsifiers against a stubbed GitHub API:
- a planted direct push is flagged (R2), and so is a merge not made by
  merge.yml, including the #540 route: a merge.yml run from a non-default ref
  whose log says MERGED (R1);
- a clean default-branch merge.yml merge that logged its recomputation passes;
- control changes, forged checks, branch workflow files, and review records
  edited or deleted between runs are flagged;
and the workflow file's hard rules.
"""
from __future__ import annotations

import copy
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
REF = f"{REPO}/.github/workflows/merge.yml@refs/heads/main"
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
MERGED_AT = "2026-11-27T11:30:00Z"


class FakeGH(au.GitHub):
    def __init__(self, routes: dict):
        super().__init__("t")
        self.routes = routes
        self.posts: list = []
        self.calls: list = []

    def _lookup(self, path: str):
        self.calls.append(path)
        for key in (path, path.split("?")[0]):
            if key in self.routes:
                v = self.routes[key]
                if isinstance(v, Exception):
                    raise v
                return copy.deepcopy(v)
        raise au.NotFound(f"no route {path}")

    def get(self, path):
        return self._lookup(path)

    def paged(self, path, key=None, limit=20):
        d = self._lookup(path)
        return d.get(key) if key and isinstance(d, dict) else d

    def download(self, path, max_bytes):
        return self._lookup(path)

    def post(self, path, body):
        self.posts.append((path, body))
        return {"number": 7}


def logzip(*lines: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("merge/1_merge.txt", "\n".join(f"2026-11-27T11:29:59.1234567Z {x}" for x in lines))
    return buf.getvalue()


def good_log(run_id=100, pr=5, head=H1, ref=REF):
    return logzip(f"workflow_ref={ref} run_id={run_id} event=schedule",
                  f"VERDICT-RECOMPUTED pr={pr} head={head} result=pass",
                  f"MERGED pr={pr} head={head} run_id={run_id} workflow_ref={ref}")


def merge_run(rid=100, event="schedule", branch="main", prs=None, status="completed",
              created="2026-11-27T11:29:00Z", path=".github/workflows/merge.yml"):
    return {"id": rid, "event": event, "head_branch": branch, "path": path, "status": status,
            "created_at": created, "repository": {"full_name": REPO},
            "head_repository": {"full_name": REPO}, "pull_requests": prs or []}


def world(**over) -> dict:
    """A repo where main moved from BASE to M1, a bot squash merge of PR #5."""
    r = {
        f"repos/{REPO}": {"default_branch": "main", "id": 1},
        f"repos/{REPO}/actions/artifacts": {"artifacts": []},
        f"repos/{REPO}/actions/workflows/audit.yml/runs": {"workflow_runs": []},
        f"repos/{REPO}/branches/main": {"commit": {"sha": M1}, "protected": True, "protection": {"enabled": True}},
        f"repos/{REPO}/compare/{BASE}...{M1}": {"status": "ahead", "total_commits": 1, "commits": [{"sha": M1}]},
        f"repos/{REPO}/commits/{M1}/pulls": [{"number": 5, "merged_at": MERGED_AT, "merge_commit_sha": M1}],
        f"repos/{REPO}/pulls/5": {"number": 5, "merged_at": MERGED_AT, "merged_by": {"login": "github-actions[bot]"},
                                  "head": {"sha": H1}, "state": "closed", "closed_at": MERGED_AT},
        f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [merge_run()]},
        f"repos/{REPO}/actions/runs/100/logs": good_log(),
        f"repos/{REPO}/events": [],
        f"repos/{REPO}/rulesets": [{"id": 9, "name": "e5-main", "enforcement": "active",
                                    "updated_at": "2026-11-27T10:00:00Z", "target": "branch", "source_type": "Repository"}],
        f"repos/{REPO}/rules/branches/main": [{"type": "deletion"}],
        f"repos/{REPO}/actions/workflows": {"workflows": [{"path": p, "state": "active"} for p in CFG["watched_workflows"]]},
        f"repos/{REPO}/labels/do-not-auto-merge": {"id": 3, "name": "do-not-auto-merge", "color": "ff0000"},
        f"repos/{REPO}/issues/events": [],
        f"repos/{REPO}/pulls": [],
        f"repos/{REPO}/branches": [{"name": "main", "commit": {"sha": M1}}],
        f"repos/{REPO}/issues": [],
    }
    r.update(over)
    return r


def auditor(routes) -> au.Auditor:
    return au.Auditor(FakeGH(routes), REPO, CFG, now=NOW, sleep=lambda s: None)


def rules_of(a):
    return [f["rule"] + ":" + f["key"].split(":")[1] for f in a.findings]


# ---------------------------------------------------------------- R1 / R2

def test_clean_merge_yml_merge_passes():
    a = auditor(world())
    assert a.audit_commits(None, M1) == M1
    assert a.findings == []
    assert a.ledger == [f"{M1[:12]} PR #5 merged by github-actions[bot]: verified by run 100"]


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
    (b"not a zip", "unreadable"),
])
def test_trusted_run_without_proof_is_flagged(log, why):
    a = auditor(world(**{f"repos/{REPO}/actions/runs/100/logs": log}))
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:provenance"]
    assert why in a.findings[0]["summary"]


def test_run_created_after_merge_does_not_count():
    run = merge_run(created="2026-11-27T11:31:00Z")
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]}}))
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:provenance"]


def test_pending_merge_run_defers_the_commit():
    run = merge_run(status="in_progress")
    a = auditor(world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": [run]}}))
    assert a.audit_commits(None, M1) == BASE
    assert a.findings == [] and "still in progress" in a.notes[0]


def test_planted_direct_push_is_flagged():
    r = world(**{
        f"repos/{REPO}/branches/main": {"commit": {"sha": D1}},
        f"repos/{REPO}/compare/{M1}...{D1}": {"status": "ahead", "total_commits": 1,
                                              "commits": [{"sha": D1, "author": {"login": "acardote"}}]},
        f"repos/{REPO}/commits/{D1}/pulls": [],
    })
    a = auditor(r)
    assert a.audit_commits(M1, D1) == D1
    assert rules_of(a) == ["R2:direct"]
    assert "'acardote'" in a.findings[0]["summary"]


def test_operator_merge_is_flagged_for_confirmation():
    r = world()
    r[f"repos/{REPO}/pulls/5"]["merged_by"] = {"login": "acardote"}
    a = auditor(r)
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:operator"]


def test_other_merger_is_flagged():
    r = world()
    r[f"repos/{REPO}/pulls/5"]["merged_by"] = {"login": "acardote-fleet[bot]"}
    a = auditor(r)
    a.audit_commits(None, M1)
    assert rules_of(a) == ["R1:merger"]


def test_commit_of_a_pr_merged_in_range_is_not_a_direct_push():
    c = "c" * 40
    r = world(**{
        f"repos/{REPO}/compare/{BASE}...{M1}": {"status": "ahead", "total_commits": 2, "commits": [{"sha": c}, {"sha": M1}]},
        f"repos/{REPO}/commits/{c}/pulls": [{"number": 5, "merged_at": MERGED_AT, "merge_commit_sha": M1}],
    })
    a = auditor(r)
    a.audit_commits(None, M1)
    assert a.findings == []


@pytest.mark.parametrize("status", ["diverged", "behind"])
def test_force_push_is_flagged(status):
    r = world(**{f"repos/{REPO}/compare/{OTHER}...{M1}": {"status": status, "total_commits": 0, "commits": []}})
    a = auditor(r)
    a.audit_commits(OTHER, M1)
    assert "R2:rewrite" in rules_of(a)


def test_vanished_base_is_flagged_and_falls_back_to_listing():
    r = world(**{f"repos/{REPO}/commits": [{"sha": M1}]})
    a = auditor(r)
    a.audit_commits(OTHER, M1)
    assert rules_of(a)[0] == "R2:base-gone"


def test_too_many_commits_fails_closed():
    r = world(**{f"repos/{REPO}/compare/{BASE}...{M1}": {"status": "ahead", "total_commits": 5000, "commits": []}})
    with pytest.raises(au.AuditError):
        auditor(r).audit_commits(None, M1)


def test_push_events_flag_non_merge_pushes_with_actor():
    r = world(**{
        f"repos/{REPO}/events": [
            {"id": "11", "type": "PushEvent", "actor": {"login": "acardote"}, "created_at": "t",
             "payload": {"ref": "refs/heads/main", "head": D1, "before": M1}},
            {"id": "12", "type": "PushEvent", "actor": {"login": "github-actions[bot]"}, "created_at": "t",
             "payload": {"ref": "refs/heads/main", "head": M1, "before": BASE}},
            {"id": "13", "type": "PushEvent", "actor": {"login": "x"}, "payload": {"ref": "refs/heads/ws/a", "head": D1}},
            {"id": "9", "type": "PushEvent", "actor": {"login": "old"}, "payload": {"ref": "refs/heads/main", "head": D1}},
        ],
        f"repos/{REPO}/commits/{D1}/pulls": [],
    })
    a = auditor(r)
    assert a.push_events(10, set()) == 13
    assert [f["key"] for f in a.findings] == ["R2:push:11"]
    assert "'acardote'" in a.findings[0]["summary"]


def test_push_events_first_run_sets_cursor_only():
    r = world(**{f"repos/{REPO}/events": [{"id": "11", "type": "PushEvent", "payload": {"ref": "refs/heads/main", "head": D1}}]})
    a = auditor(r)
    assert a.push_events(None, set()) == 11 and a.findings == []


# ---------------------------------------------------------------- R3

def controls_snapshot(r):
    return auditor(r).controls(None, {"AUTO_MERGE_ENABLED": "true"})


def test_controls_unchanged_no_flags():
    r = world()
    snap = controls_snapshot(r)
    a = auditor(r)
    a.controls(snap, {"AUTO_MERGE_ENABLED": "true"})
    assert a.findings == []


@pytest.mark.parametrize("mutate,var,want", [
    (lambda r: r[f"repos/{REPO}/rulesets"][0].update(updated_at="2026-11-27T11:00:00Z"), "true", "R3:rulesets"),
    (lambda r: r[f"repos/{REPO}/rulesets"][0].update(enforcement="disabled"), "true", "R3:ruleset-missing"),
    (lambda r: r.update({f"repos/{REPO}/rules/branches/main": []}), "true", "R3:rules"),
    (lambda r: None, "false", "R3:vars"),
    (lambda r: r.update({f"repos/{REPO}/labels/do-not-auto-merge": au.NotFound("x")}), "true", "R3:label-missing"),
    (lambda r: r[f"repos/{REPO}/actions/workflows"]["workflows"][2].update(state="disabled_manually"), "true", "R3:workflow-state"),
])
def test_control_changes_are_flagged(mutate, var, want):
    r = world()
    snap = controls_snapshot(r)
    mutate(r)
    a = auditor(r)
    a.controls(snap, {"AUTO_MERGE_ENABLED": var})
    assert want in rules_of(a)


def test_kill_switch_label_events_are_flagged():
    r = world(**{f"repos/{REPO}/issues/events": [
        {"id": 51, "event": "unlabeled", "label": {"name": "do-not-auto-merge"}, "actor": {"login": "acardote"},
         "issue": {"number": 4}, "created_at": "t"},
        {"id": 52, "event": "labeled", "label": {"name": "auto-merge"}, "actor": {"login": "x"}, "issue": {"number": 4}},
        {"id": 40, "event": "labeled", "label": {"name": "do-not-auto-merge"}, "actor": {"login": "x"}, "issue": {"number": 1}},
    ]})
    a = auditor(r)
    assert a.label_events(50) == 52
    assert [f["key"] for f in a.findings] == ["R3:label-event:51"]


# ---------------------------------------------------------------- R7

def records_world(comments, reviews=(), rcs=()):
    return world(**{
        f"repos/{REPO}/pulls": [{"number": 5, "state": "open", "updated_at": "2026-11-27T11:00:00Z"}],
        f"repos/{REPO}/issues/5/comments": list(comments),
        f"repos/{REPO}/pulls/5/reviews": list(reviews),
        f"repos/{REPO}/pulls/5/comments": list(rcs),
    })


def cm(cid, body, user="acardote-fleet[bot]", edited=False):
    return {"id": cid, "body": body, "user": {"login": user}, "created_at": "2026-11-27T10:00:00Z",
            "updated_at": "2026-11-27T10:05:00Z" if edited else "2026-11-27T10:00:00Z"}


REC = f"VERDICT: pass reviewer=pr-reviewer sha={H1}"


def test_records_snapshot_tracks_only_trusted_record_like_items():
    snap = auditor(records_world([cm(1, REC), cm(2, "LGTM"), cm(3, REC, user="mallory")])).records(None)
    assert list(snap) == ["ic:1"]


def test_record_deleted_between_runs_is_flagged():
    snap = auditor(records_world([cm(1, REC)])).records(None)
    a = auditor(records_world([]))
    a.records(snap)
    assert [f["key"] for f in a.findings] == ["R7:deleted:ic:1"]


def test_record_edited_away_is_flagged_and_still_tracked():
    snap = auditor(records_world([cm(1, REC)])).records(None)
    a = auditor(records_world([cm(1, "never mind", edited=True)]))
    new = a.records(snap)
    assert rules_of(a) == ["R7:edited"] and "ic:1" in new


def test_record_edited_before_first_snapshot_is_flagged():
    a = auditor(records_world([cm(1, REC, edited=True)]))
    a.records(None)
    assert rules_of(a) == ["R7:edited-before-snapshot"]


def test_review_and_review_comment_records_tracked():
    rv = {"id": 8, "body": REC, "user": {"login": "acardote"}, "state": "COMMENTED", "submitted_at": "t"}
    rc = cm(9, f"CRITICAL: id=c1 reviewer=wario sha={H1}")
    snap = auditor(records_world([], [rv], [rc])).records(None)
    assert set(snap) == {"rv:8", "rc:9"}
    a = auditor(records_world([], [{**rv, "body": "changed"}], []))
    a.records(snap)
    assert sorted(f["key"].split(":")[1] for f in a.findings) == ["deleted", "edited"]


def test_records_of_old_closed_prs_age_out():
    snap = {"ic:1": {"pr": 3, "h": "x", "author": "acardote"}}
    r = records_world([])
    r[f"repos/{REPO}/pulls/3"] = {"number": 3, "state": "closed", "closed_at": "2026-09-01T00:00:00Z"}
    a = auditor(r)
    assert a.records(snap) == {} and a.findings == []


# ---------------------------------------------------------------- R4 / R5

def checks_world(cr, job):
    r = world(**{
        f"repos/{REPO}/pulls": [{"number": 5, "head": {"sha": H1}}],
        f"repos/{REPO}/commits/{H1}/check-runs": {"check_runs": [cr]},
    })
    if job is not None:
        r[f"repos/{REPO}/actions/jobs/{cr['id']}"] = job
    return r


GOOD_CR = {"id": 77, "status": "completed", "app": {"id": 15368}}


@pytest.mark.parametrize("cr,job,flagged", [
    (GOOD_CR, {"runner_name": "GitHub Actions 2", "steps": [{"name": "x"}]}, False),
    (GOOD_CR, {"runner_name": None, "steps": []}, True),           # #540 f-i
    (GOOD_CR, {"runner_name": "r", "steps": []}, True),
    (GOOD_CR, None, True),
    ({**GOOD_CR, "app": {"id": 1}}, None, True),
    ({**GOOD_CR, "status": "in_progress"}, None, False),
])
def test_forged_checks(cr, job, flagged):
    a = auditor(checks_world(cr, job))
    ok = a.forged_checks([])
    assert bool(a.findings) is flagged
    assert (77 in ok) is (not flagged and cr["status"] == "completed")


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


# ---------------------------------------------------------------- state

def audit_run(rid, branch="main", event="schedule", path=".github/workflows/audit.yml"):
    return {"id": rid, "event": event, "head_branch": branch, "path": path,
            "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO}}


def state_zip(state):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("state.json", json.dumps(state))
    return buf.getvalue()


def test_state_from_untrusted_run_is_ignored_and_flagged():
    good = {"version": 1, "head": M1}
    r = world(**{
        f"repos/{REPO}/actions/artifacts": {"artifacts": [
            {"id": 2, "name": "fleet-audit-state", "created_at": "2026-11-27T11:50:00Z", "workflow_run": {"id": 201}},
            {"id": 1, "name": "fleet-audit-state", "created_at": "2026-11-27T11:45:00Z", "workflow_run": {"id": 200}},
        ]},
        f"repos/{REPO}/actions/runs/201": audit_run(201, branch="ws/a/x", event="push"),
        f"repos/{REPO}/actions/runs/200": audit_run(200),
        f"repos/{REPO}/actions/artifacts/1/zip": state_zip(good),
    })
    findings = []
    assert au.load_state(FakeGH(r), REPO, CFG, 300, findings) == good
    assert [f["key"] for f in findings] == ["R6:state-untrusted:2"]


def test_missing_state_after_earlier_success_is_flagged():
    r = world(**{f"repos/{REPO}/actions/workflows/audit.yml/runs": {"workflow_runs": [audit_run(250)]}})
    findings = []
    assert au.load_state(FakeGH(r), REPO, CFG, 300, findings) is None
    assert [f["key"] for f in findings] == ["R6:state-missing:250"]


def test_first_ever_run_has_no_state_finding():
    findings = []
    assert au.load_state(FakeGH(world()), REPO, CFG, 300, findings) is None and findings == []


def test_run_audit_end_to_end_and_dedupes_across_runs():
    r = world(**{f"repos/{REPO}/actions/workflows/merge.yml/runs": {"workflow_runs": []}})
    state, new, a = au.run_audit(FakeGH(r), REPO, CFG, 300, {"AUTO_MERGE_ENABLED": "true"}, now=NOW, sleep=lambda s: None)
    assert [f["key"] for f in new] == [f"R1:provenance:{M1}"]
    assert state["head"] == M1 and state["flagged"] == [f"R1:provenance:{M1}"]
    # Second run: the earlier state comes back from a trusted artifact; nothing new, no repeat.
    r2 = world(**{
        f"repos/{REPO}/actions/artifacts": {"artifacts": [
            {"id": 5, "name": "fleet-audit-state", "created_at": "x", "workflow_run": {"id": 300}}]},
        f"repos/{REPO}/actions/runs/300": audit_run(300),
        f"repos/{REPO}/actions/artifacts/5/zip": state_zip(state),
    })
    state2, new2, _ = au.run_audit(FakeGH(r2), REPO, CFG, 301, {"AUTO_MERGE_ENABLED": "true"}, now=NOW, sleep=lambda s: None)
    assert new2 == [] and state2["head"] == M1


def test_wrong_default_branch_fails_closed():
    with pytest.raises(au.AuditError):
        au.run_audit(FakeGH(world(**{f"repos/{REPO}": {"default_branch": "master"}})), REPO, CFG, 1, {})


def test_render_neutralises_mentions():
    out = au.render([au.finding("R2", "k", "by @acardote")], [], [], "u")
    assert "@acardote" not in out and "`FLAG` R2" in out


# ---------------------------------------------------------------- client

class FakeResp(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


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


# ---------------------------------------------------------------- config and workflow file

def test_trusted_authors_match_verdict_config():
    verdict_cfg = json.loads((HERE.parent / "verdict" / "config.json").read_text())
    assert CFG["trusted_record_authors"] == verdict_cfg["trusted_record_authors"]


def test_record_regexes_match_verdict():
    src = (HERE.parent / "verdict" / "verdict.py").read_text()
    for name in ("RECORD_LIKE_RE", "CRITICAL_LIKE_RE"):
        m = re.search(rf"^{name} = re\.compile\((r\".*?\")\)$", src, re.M)
        assert m and eval(m.group(1)) == getattr(au, name).pattern  # noqa: S307 - literal from our own file


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
    assert "${{" not in run_lines
    assert "name: fleet-audit-state" in t and CFG["state_artifact"] == "fleet-audit-state"
