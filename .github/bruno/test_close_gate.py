"""Tests for the Bruno close gate's fleet-pilot local change 2
(acardote/personal-assistant-ultra#583; operator decision 2026-11-27 on #530).

Run: python3 -m pytest -q .github/bruno

The gate is the inline `actions/github-script` body of
.github/workflows/bruno-close-gate.yml. Each test extracts that body and runs
it under node with a mocked `github` / `context` / `core`, then reads whether
the gate let the close stand or reopened the issue.

Covers:
- a reconciliation by exactly `acardote-fleet[bot]` with an `[agent-posted]`
  heading passes, for a parent and for a child whose falsifiers comment is
  also App-posted and prefixed;
- any other bot (another App, `github-actions[bot]`, a user account named
  `acardote-fleet[bot]` with type User) still does not count;
- the strict checks still fire for the App: no provenance, no
  `state:reconciled`, no falsifiers, no parent link;
- an App-posted `## Owner disposition` record does not count;
- a human reconciliation still passes, and the prefix is accepted from a human;
- the tag is also stripped from the issue body (Parent: and Falsifiers checks)
  and from the bodies scanned for open children of a disposition-closed parent;
- repeated and differently cased tags are stripped;
- the latest reconciliation wins between a human and the App.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "bruno-close-gate.yml"

yaml = pytest.importorskip("yaml")
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is required to run the gate script")

APP = {"login": "acardote-fleet[bot]", "type": "Bot"}
HUMAN = {"login": "acardote", "type": "User"}

HARNESS = r"""
const fs = require('fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const script = input.script;
const calls = [];
let failed = null;
const core = {
  info: () => {}, warning: () => {},
  setFailed: (m) => { failed = m; },
};
const err404 = () => { const e = new Error('Not Found'); e.status = 404; return e; };
const github = {
  paginate: async (fn, params) => fn === github.rest.issues.listComments
    ? input.comments
    : fn === github.rest.issues.listForRepo ? (input.open_issues || []) : [],
  rest: {
    issues: {
      listComments: async () => ({ data: input.comments }),
      listEvents: async () => ({ data: [] }),
      listForRepo: async () => ({ data: [] }),
      get: async ({ issue_number }) => {
        const i = (input.issues || {})[String(issue_number)];
        if (!i) throw err404();
        return { data: i };
      },
      createComment: async (a) => { calls.push(['comment', a.body]); },
      update: async (a) => { calls.push(['update', a.state]); },
      removeLabel: async (a) => { calls.push(['removeLabel', a.name]); },
      addLabels: async (a) => { calls.push(['addLabels', a.labels]); },
    },
    pulls: { get: async () => { throw err404(); } },
    repos: {
      getCollaboratorPermissionLevel: async ({ username }) => {
        const p = (input.permissions || {})[username];
        if (!p) throw err404();
        return { data: { permission: p } };
      },
    },
  },
};
const context = {
  repo: { owner: 'acardote', repo: 'fleet-pilot' },
  payload: { issue: input.issue },
};
const fastTimeout = (fn) => fn();
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const run = new AsyncFunction('github', 'context', 'core', 'setTimeout', script);
run(github, context, core, fastTimeout).then(() => {
  process.stdout.write(JSON.stringify({ failed, calls }));
}).catch((e) => {
  process.stdout.write(JSON.stringify({ crashed: String(e && e.stack || e), failed, calls }));
});
"""


def gate_script() -> str:
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"]["enforce-reconciliation"]["steps"]
    return next(s for s in steps if "actions/github-script" in s.get("uses", ""))["with"]["script"]


def run_gate(issue: dict, comments: list, issues: dict | None = None,
             permissions: dict | None = None, open_issues: list | None = None) -> dict:
    payload = {
        "open_issues": open_issues or [],
        "script": gate_script(),
        "issue": issue,
        "comments": comments,
        "issues": issues or {},
        "permissions": permissions or {},
    }
    out = subprocess.run([NODE, "-e", HARNESS], input=json.dumps(payload),
                         capture_output=True, text=True, timeout=60, check=True)
    result = json.loads(out.stdout)
    assert "crashed" not in result, result["crashed"]
    return result


def stood(result: dict) -> bool:
    return result["failed"] is None and not any(c[0] == "update" for c in result["calls"])


def reopened(result: dict) -> bool:
    return result["failed"] is not None and ["update", "open"] in result["calls"]


def gate_comment(result: dict) -> str:
    return next(c[1] for c in result["calls"] if c[0] == "comment")


def issue(labels, body="", creator=HUMAN, assignees=()):
    return {"number": 18, "labels": [{"name": n} for n in labels], "body": body,
            "user": creator, "assignees": [{"login": a} for a in assignees]}


def comment(user, body, created="2026-11-27T10:00:00Z", cid=1):
    return {"id": cid, "user": user, "body": body, "created_at": created}


RECON = ("[agent-posted] ## Reconciliation (move:5)\n\n"
         "All criteria met against landed state.\n"
         "Provenance: acardote/fleet-pilot#19, `227fbb5d24a0`\n")
FALSIFIERS = "[agent-posted] ## Falsifiers (move:4)\n\n- F1: the gate reopens.\n"
PARENT_ISSUES = {"7": {"number": 7, "labels": [{"name": "parent"}]}}
CHILD_BODY = "Parent: #7\n\nGoal: pilot stream.\n"


def test_app_reconciliation_with_agent_posted_heading_passes_parent():
    r = run_gate(issue(["parent", "state:reconciled"]), [comment(APP, RECON)])
    assert stood(r), r


def test_app_reconciliation_and_falsifiers_pass_child():
    r = run_gate(issue(["child", "state:reconciled"], CHILD_BODY),
                 [comment(APP, FALSIFIERS, cid=1), comment(APP, RECON, cid=2)],
                 issues=PARENT_ISSUES)
    assert stood(r), r


def test_app_reconciliation_without_prefix_passes():
    body = RECON.replace("[agent-posted] ", "")
    r = run_gate(issue(["parent", "state:reconciled"]), [comment(APP, body)])
    assert stood(r), r


def test_human_reconciliation_with_prefix_passes():
    r = run_gate(issue(["parent", "state:reconciled"]), [comment(HUMAN, RECON)])
    assert stood(r), r


def test_human_reconciliation_still_passes():
    body = RECON.replace("[agent-posted] ", "")
    r = run_gate(issue(["parent", "state:reconciled"]), [comment(HUMAN, body)])
    assert stood(r), r


@pytest.mark.parametrize("user", [
    {"login": "some-other-app[bot]", "type": "Bot"},
    {"login": "github-actions[bot]", "type": "Bot"},
    {"login": "dependabot[bot]", "type": "Bot"},
    # A user account cannot pass on the login string alone.
    {"login": "acardote-fleet[bot]", "type": "User"},
])
def test_other_bots_and_impostors_do_not_count(user):
    r = run_gate(issue(["parent", "state:reconciled"]), [comment(user, RECON)],
                 permissions={"acardote-fleet[bot]": "read"})
    assert reopened(r), r
    assert "Reconciliation" in gate_comment(r)


def test_app_reconciliation_without_provenance_reopens():
    body = "[agent-posted] ## Reconciliation (move:5)\n\nAll criteria met.\n"
    r = run_gate(issue(["parent", "state:reconciled"]), [comment(APP, body)])
    assert reopened(r), r
    assert "Provenance" in gate_comment(r)


def test_app_reconciliation_without_reconciled_label_reopens():
    r = run_gate(issue(["parent"]), [comment(APP, RECON)])
    assert reopened(r), r
    assert "state:reconciled" in gate_comment(r)


def test_app_child_without_falsifiers_reopens():
    r = run_gate(issue(["child", "state:reconciled"], CHILD_BODY),
                 [comment(APP, RECON)], issues=PARENT_ISSUES)
    assert reopened(r), r
    assert "Falsifiers" in gate_comment(r)


def test_app_child_without_parent_link_reopens():
    r = run_gate(issue(["child", "state:reconciled"], "Goal: pilot stream.\n"),
                 [comment(APP, FALSIFIERS, cid=1), comment(APP, RECON, cid=2)],
                 issues=PARENT_ISSUES)
    assert reopened(r), r
    assert "Parent" in gate_comment(r)


def test_app_child_with_unlabelled_parent_reopens():
    r = run_gate(issue(["child", "state:reconciled"], CHILD_BODY),
                 [comment(APP, FALSIFIERS, cid=1), comment(APP, RECON, cid=2)],
                 issues={"7": {"number": 7, "labels": []}})
    assert reopened(r), r
    assert "lacks the `parent` label" in gate_comment(r)


def test_prefix_mid_body_is_not_a_heading():
    body = ("Some text first.\n[agent-posted] ## Reconciliation (move:5)\n"
            "Provenance: acardote/fleet-pilot#19\n")
    r = run_gate(issue(["parent", "state:reconciled"]), [comment(APP, body)])
    assert reopened(r), r


def test_app_owner_disposition_does_not_count():
    body = ("[agent-posted] ## Owner disposition\n\n"
            "- **Owner's words:** \"drop it\"\n- **Recorded:** 2026-11-27, comment\n")
    r = run_gate(issue(["parent", "state:declined"]), [comment(APP, body)])
    assert reopened(r), r
    assert "record comment (non-bot)" in gate_comment(r)


# ---- fix-up round: issue bodies, tag variants, ordering ----

def test_tagged_child_body_parent_line_passes():
    r = run_gate(issue(["child", "state:reconciled"], "[agent-posted] " + CHILD_BODY),
                 [comment(APP, FALSIFIERS, cid=1), comment(APP, RECON, cid=2)],
                 issues=PARENT_ISSUES)
    assert stood(r), r


def test_tagged_child_body_falsifiers_heading_passes():
    body = "[agent-posted] ## Falsifiers\n\n- F1: the gate reopens.\n\nParent: #7\n"
    r = run_gate(issue(["child", "state:reconciled"], body),
                 [comment(APP, RECON)], issues=PARENT_ISSUES)
    assert stood(r), r


def test_tagged_child_body_without_parent_still_reopens():
    r = run_gate(issue(["child", "state:reconciled"], "[agent-posted] Goal: x\n"),
                 [comment(APP, FALSIFIERS, cid=1), comment(APP, RECON, cid=2)],
                 issues=PARENT_ISSUES)
    assert reopened(r), r
    assert "Parent" in gate_comment(r)


@pytest.mark.parametrize("tagged", [True, False])
def test_disposition_parent_close_sees_open_tagged_child(tagged):
    record = ("## Owner disposition\n\n- **Disposition:** declined\n"
              "- **Owner's words:** \"drop it\"\n")
    child = {"number": 30, "body": ("[agent-posted] " if tagged else "") + "Parent: #18\n\nGoal: x\n"}
    r = run_gate(issue(["parent", "state:declined"]), [comment(HUMAN, record)],
                 open_issues=[child])
    assert reopened(r), r
    assert "no open children (open: #30)" in gate_comment(r)


@pytest.mark.parametrize("prefix", [
    "[agent-posted] [agent-posted] ",
    "[Agent-Posted] ",
    "[AGENT-POSTED]",
])
def test_tag_variants_are_stripped(prefix):
    body = RECON.replace("[agent-posted] ", prefix)
    r = run_gate(issue(["parent", "state:reconciled"]), [comment(APP, body)])
    assert stood(r), r


def test_latest_reconciliation_wins_app_after_human_without_provenance():
    human = comment(HUMAN, "## Reconciliation\n\nnothing\n", created="2026-11-27T09:00:00Z", cid=1)
    app = comment(APP, RECON, created="2026-11-27T10:00:00Z", cid=2)
    r = run_gate(issue(["parent", "state:reconciled"]), [human, app])
    assert stood(r), r


def test_latest_reconciliation_wins_human_after_app_without_provenance():
    app = comment(APP, RECON, created="2026-11-27T09:00:00Z", cid=1)
    human = comment(HUMAN, "## Reconciliation\n\nnothing\n", created="2026-11-27T10:00:00Z", cid=2)
    r = run_gate(issue(["parent", "state:reconciled"]), [app, human])
    assert reopened(r), r
    assert "Provenance" in gate_comment(r)
