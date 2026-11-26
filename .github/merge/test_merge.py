"""Tests for auto-merge (acardote/personal-assistant-ultra#580).

Run: python3 -m pytest -q .github/merge

Covers #580's acceptance and falsifiers:
- a clean labelled PR is merged via `gh pr merge --squash --match-head-commit H`
  only after a logged inline recomputation of the verdict at H  [falsifier 1];
- a PR touching a 7a path (floor or derived, renamed or deleted, symlink or
  submodule) is skipped  [falsifier 2];
- AUTO_MERGE_ENABLED other than exactly "true", or the do-not-auto-merge label
  (also when added just before the merge call), means no merge  [falsifier 3];
and the hard rules on the workflow file (default-branch-only triggers,
permissions, no PR-head checkout) and on the e5-main ruleset definition.
The 7a and end-to-end tests use real git repositories in tmp_path.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import merge as m  # noqa: E402

V = m.load_verdict("e5_verdict_test")
WORKFLOW = HERE.parent / "workflows" / "merge.yml"
RULESET = HERE.parent / "rulesets" / "e5-main.json"
CONFIG = json.loads((HERE / "config.json").read_text())
VCONFIG = json.loads((HERE.parent / "verdict" / "config.json").read_text())
REPO = "acardote/fleet-pilot"
REF = f"{REPO}/.github/workflows/merge.yml@refs/heads/main"
BOT = "acardote-fleet[bot]"

# The #581 audit's parser (fleet-pilot#4, .github/audit/audit.py MERGED_RE and
# VERDICT_LOG_RE). Kept in sync by test_audit_regexes_match_the_audit_file once
# that file is on the branch.
AUDIT_MERGED_RE = re.compile(r"^MERGED pr=([1-9][0-9]*) head=([0-9a-f]{40}) run_id=([1-9][0-9]*) workflow_ref=(\S+)$")
AUDIT_VERDICT_RE = re.compile(r"^VERDICT-RECOMPUTED pr=([1-9][0-9]*) head=([0-9a-f]{40}) result=(pass|fail)$")


# --------------------------------------------------------------------------
# Workflow file structure
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def wf():
    import yaml  # required, never skipped: ci.yml installs PyYAML (challenger I4)
    doc = yaml.safe_load(WORKFLOW.read_text())
    if True in doc and "on" not in doc:  # PyYAML reads bare `on` as True
        doc["on"] = doc.pop(True)
    return doc


def steps(wf):
    return wf["jobs"]["auto-merge"]["steps"]


def test_triggers_are_default_branch_only(wf):
    assert set(wf["on"].keys()) == {"pull_request_target", "schedule"}
    assert wf["on"]["pull_request_target"]["branches"] == ["main"]
    assert set(wf["on"]["pull_request_target"]["types"]) == {"labeled", "synchronize"}
    assert wf["on"]["schedule"] == [{"cron": "*/5 * * * *"}]


@pytest.mark.parametrize("bad", ["push", "pull_request", "workflow_dispatch", "workflow_run",
                                 "workflow_call", "issue_comment", "repository_dispatch"])
def test_no_trigger_that_runs_branch_definitions(wf, bad):
    assert bad not in wf["on"]


def test_permissions_minimal(wf):
    assert wf["permissions"] == {}
    assert list(wf["jobs"].keys()) == ["auto-merge"]
    assert wf["jobs"]["auto-merge"]["permissions"] == {
        "contents": "write", "pull-requests": "write", "issues": "read", "actions": "read"}


def test_runs_serialised_never_cancelled(wf):
    assert wf["concurrency"] == {"group": "auto-merge", "cancel-in-progress": False}


def test_checkout_is_default_branch_workflow_commit_only(wf):
    cos = [s for s in steps(wf) if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert len(cos) == 1
    w = cos[0]["with"]
    assert w["ref"] == "${{ github.workflow_sha }}"
    assert w["persist-credentials"] is False
    assert "repository" not in w
    assert set(w["sparse-checkout"].split()) == {".github/verdict", ".github/merge"}


def test_no_pr_head_or_payload_reference_in_workflow():
    text = WORKFLOW.read_text()
    for needle in ("pull_request.head", "github.head_ref", "refs/pull/", "merge_commit_sha",
                   "github.event.pull_request", "github.event.number"):
        assert needle not in text, needle


def test_actions_pinned_and_no_interpolation_in_run(wf):
    for s in steps(wf):
        if "uses" in s:
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", s["uses"]), s["uses"]
        if "run" in s:
            assert "${{" not in s["run"], s.get("name")


def test_guard_runs_first_and_refuses_other_refs_and_events(wf):
    names = [s.get("name", "") for s in steps(wf)]
    gi = names.index("Refuse a definition not on the default branch")
    guard = steps(wf)[gi]["run"]
    assert 'expected="${GITHUB_REPOSITORY}/.github/workflows/merge.yml@refs/heads/main"' in guard
    assert "pull_request_target|schedule) ;;" in guard and guard.count("exit 1") == 2
    assert gi < next(i for i, s in enumerate(steps(wf)) if "uses" in s)


def test_merge_step_runs_default_branch_code_with_kill_switch_variable(wf):
    last = steps(wf)[-1]
    assert last["run"] == ('python3 .github/merge/merge.py --repo "${GITHUB_REPOSITORY}" '
                           '--config .github/merge/config.json')
    assert last["env"] == {"GH_TOKEN": "${{ github.token }}",
                           "AUTO_MERGE_ENABLED": "${{ vars.AUTO_MERGE_ENABLED }}"}


def test_merge_code_is_stdlib_only_and_reads_no_checks():
    src = (HERE / "merge.py").read_text()
    imports = set(re.findall(r"^(?:from|import) ([\w.]+)", src, re.MULTILINE))
    allowed = {"__future__", "argparse", "ast", "base64", "importlib.util", "json", "os", "posixpath",
               "re", "subprocess", "sys", "tempfile", "dataclasses", "pathlib", "typing"}
    assert imports <= allowed, imports - allowed
    for needle in ("check-runs", "check_runs", "check-suites", "/statuses", "/status", "event_path",
                   "GITHUB_EVENT_PATH", "--admin", "--auto"):
        assert needle not in src, needle


def test_verdict_is_imported_from_the_verdict_file():
    assert V.__file__ == str(HERE.parent / "verdict" / "verdict.py")
    assert callable(V.fetch_and_compute) and callable(V.compute_verdict)


# --------------------------------------------------------------------------
# Ruleset definition
# --------------------------------------------------------------------------

def test_ruleset_definition():
    r = json.loads(RULESET.read_text())
    assert r["name"] == "e5-main" and r["target"] == "branch" and r["enforcement"] == "active"
    assert r["bypass_actors"] == []
    assert r["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    rules = {x["type"]: x.get("parameters") for x in r["rules"]}
    assert set(rules) == {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}
    assert rules["pull_request"]["required_approving_review_count"] == 0
    assert rules["required_status_checks"]["required_status_checks"] == [
        {"context": "review-verdict", "integration_id": 15368}]


def test_operator_doc_applies_the_ruleset_file_and_variable():
    doc = (ROOT / "docs" / "operator" / "apply-e5-main.md").read_text()
    assert "--input .github/rulesets/e5-main.json" in doc
    assert "gh variable set AUTO_MERGE_ENABLED --repo acardote/fleet-pilot --body true" in doc


def test_operator_doc_has_break_glass_and_safe_order():
    """challenger C2/I6: a rollback path by ruleset id, and the ruleset only after CI is green
    and the verdict passed on a test PR; blobs pinned before the variable enables merging."""
    doc = (ROOT / "docs" / "operator" / "apply-e5-main.md").read_text()
    assert "gh api -X PUT repos/acardote/fleet-pilot/rulesets/$ID -f enforcement=disabled" in doc
    assert "gh api -X DELETE repos/acardote/fleet-pilot/rulesets/$ID" in doc
    green = doc.index("--workflow ci --branch main --event push")
    preflight = doc.index("## 3. Pre-flight")
    apply = doc.index("gh api -X POST repos/acardote/fleet-pilot/rulesets --input .github/rulesets/e5-main.json")
    pin = doc.index("## 6. Pin the workflow blobs")
    enable = doc.index("gh variable set AUTO_MERGE_ENABLED --repo acardote/fleet-pilot --body true")
    assert green < preflight < apply < pin < enable


# --------------------------------------------------------------------------
# Kill switch (variable) and 7a matching
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value,ok", [("true", True), (None, False), ("", False), ("True", False),
                                      ("TRUE", False), ("false", False), (" true", False), ("1", False),
                                      ("yes", False)])
def test_kill_switch_exactly_true(value, ok):
    assert m.kill_switch_allows(value) is ok


FLOOR_SAMPLES = [".github/workflows/x.yml", ".github/merge/config.json", ".claude/settings.json",
                 ".husky/pre-commit", "templates/git-hooks/pre-push", "agents/yoshi.md", "CLAUDE.md",
                 ".bruno/config.toml", "release-policy.yaml", "RELEASE.md", "tools/lint-provenance.py",
                 "tools/_config.py", "tests/conftest.py", "tests/fixtures/a.json",
                 "docs/policy/autonomy-v2.md", "package.json", "web/package-lock.json", "pyproject.toml",
                 "uv.lock", "requirements-dev.txt", "Pipfile.lock", "go.sum", "Cargo.toml", "Gemfile",
                 "x/flock.c", "templates/routines/harvest.md", "scripts/pa-session",
                 "tools/live-commit-push.sh", "tools/session-spend.py", "tools/install-agents.py",
                 "tests/test_policy_v2_sync.py", ".vscode/tasks.json", ".devcontainer/devcontainer.json",
                 ".envrc", ".pre-commit-config.yaml", ".GitHub/workflows/x.yml", ".gitattributes"]


@pytest.mark.parametrize("path", FLOOR_SAMPLES)
def test_floor_covers_merge_model_section_5(path):
    assert V.matches_any(path, CONFIG["floor_7a"]), path


@pytest.mark.parametrize("path", ["src/app.py", "docs/guide.md", "README.md", "tests/test_app.py"])
def test_ordinary_paths_not_on_floor(path):
    assert not V.matches_any(path, CONFIG["floor_7a"])


def ch(path, old="100644", new="100644", status="M"):
    return m.Change(old, new, status, path)


def test_check_7a():
    pats = CONFIG["floor_7a"] + ["lib/run.sh"]
    assert m.check_7a([ch("src/app.py")], pats, V.matches_any) == []
    assert m.check_7a([ch("lib/run.sh")], pats, V.matches_any) == ['7a path: "lib/run.sh"']
    assert m.check_7a([ch(".github/workflows/x.yml", new="000000", status="D")], pats, V.matches_any)
    assert m.check_7a([ch("docs/link", new="120000", status="A")], pats, V.matches_any)
    assert m.check_7a([ch("vendor/sub", old="160000", new="160000")], pats, V.matches_any)
    assert m.check_7a([], pats, V.matches_any)  # empty diff fails closed


def test_parse_raw_diff_rejects_renames_and_garbage():
    ok = b":100644 100644 " + b"a" * 40 + b" " + b"b" * 40 + b" M\0src/a.py\0"
    assert m.parse_raw_diff(ok)[0].path == "src/a.py"
    with pytest.raises(m.GitError):
        m.parse_raw_diff(ok.replace(b" M\0", b" R100\0"))
    with pytest.raises(m.GitError):
        m.parse_raw_diff(b"garbage\0")


# --------------------------------------------------------------------------
# 7a derivation (transitive, fail closed)
# --------------------------------------------------------------------------

def derive(files: dict[str, str], modes: dict[str, str] | None = None):
    tree = {p: (modes or {}).get(p, "100644") for p in files}
    return m.derive_7a(tree, lambda p: files[p].encode(), V.matches_any, CONFIG)


def test_derives_workflow_run_script_and_transitive_python_imports():
    pats, unresolved = derive({
        ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: python3 tools/check.py --x\n",
        "tools/check.py": "from tools import helper\nimport lib.util\n",
        "tools/helper.py": "X = 'data/rules.json'\nY = 'docs'\n",
        "lib/__init__.py": "",
        "lib/util.py": "import json\n",
        "data/rules.json": "{}",
        "src/app.py": "print(1)\n",
    })
    assert unresolved == []
    for p in ("tools/check.py", "tools/helper.py", "lib/util.py", "lib/__init__.py"):
        assert p in pats, p
    # A data path and a bare word are mentions, not execution edges.
    for p in ("src/app.py", "data/rules.json", "docs/x.md"):
        assert not V.matches_any(p, pats), p


def test_derives_settings_hook_and_shell_source_relative_to_script():
    pats, unresolved = derive({
        ".claude/settings.json": json.dumps({"hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/tools/drift-hook.sh"}]}]}}),
        "tools/drift-hook.sh": '#!/bin/bash\nsource "$(dirname "$0")/lib.sh"\n',
        "tools/lib.sh": "echo hi\n",
    })
    assert unresolved == []
    assert "tools/drift-hook.sh" in pats and "tools/lib.sh" in pats


def test_derives_local_action_directory_as_glob_but_not_test_runner_arguments():
    pats, unresolved = derive({
        ".github/workflows/ci.yml": "jobs:\n  t:\n    name: tests\n    steps:\n      - uses: ./tools/act\n"
                                    "      - run: pytest tests/unit\n      - run: echo docs kb memory\n",
        "tools/act/action.yml": "runs:\n  using: composite\n  steps:\n    - run: bash ${{ github.action_path }}/go.sh\n"
                                "      shell: bash\n",
        "tools/act/go.sh": "echo\n",
        "tests/unit/test_a.py": "def test_a():\n    pass\n",
        "docs/a.md": "x\n", "kb/a.md": "x\n", "tests/x.md": "x\n"})
    assert unresolved == [] and "tools/act/**" in pats and "tools/act/go.sh" in pats
    for p in ("tests/unit/test_a.py", "docs/a.md", "kb/a.md", "tests/x.md"):
        assert not V.matches_any(p, pats), p


def test_missing_literal_script_and_exec_glob_are_7a():
    """wario I-1: a PR that CREATES a file a root already runs is 7a."""
    pats, unresolved = derive({
        ".github/workflows/ci.yml": "run: |\n  [ -f scripts/extra.sh ] && bash scripts/extra.sh\n"
                                    "  for f in hooks/*.sh; do bash hooks/*.sh; done\n  ./tools/later\n"})
    assert unresolved == []
    for p in ("scripts/extra.sh", "hooks/a.sh", "tools/later"):
        assert V.matches_any(p, pats), p
    assert not V.matches_any("scripts/other.sh", pats)


def test_shell_variables_and_self_dir_are_substituted():
    pats, unresolved = derive({
        ".claude/settings.json": json.dumps({"hooks": {"S": [{"hooks": [
            {"type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/tools/push.sh"},
            {"type": "command", "command": "bash tools/drift.sh"}]}]}}),
        "tools/push.sh": ('#!/bin/bash\n# comment: bash not/a/ref.sh\nSCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)\n'
                          'LINT="$SCRIPT_DIR/lint.py"\npython3 "$LINT" --x\nexec "$@"\n'),
        "tools/drift.sh": 'case "$0" in\n  */*) dir="${0%/*}" ;;\n  *) dir="." ;;\nesac\n'
                          'script="$dir/install.py"\npython3 "$script"\n',
        "tools/lint.py": "import json\n", "tools/install.py": "import os\n"})
    assert unresolved == [], unresolved
    for p in ("tools/push.sh", "tools/lint.py", "tools/drift.sh", "tools/install.py"):
        assert p in pats, p
    assert not V.matches_any("not/a/ref.sh", pats)


def test_python_loader_with_path_join_resolves():
    pats, unresolved = derive({
        ".github/workflows/ci.yml": "run: python3 tests/test_x.py\n",
        "tests/test_x.py": ("import importlib.util\nfrom pathlib import Path\nROOT = Path(__file__).parent.parent\n"
                            "SCRIPT = ROOT / 'tools' / 'lint-x.py'\n"
                            "spec = importlib.util.spec_from_file_location('m', SCRIPT)\n"),
        "tools/lint-x.py": "print(1)\n"})
    assert unresolved == [] and "tools/lint-x.py" in pats


def test_follows_symlink_to_its_target():
    pats, unresolved = derive({".github/workflows/ci.yml": "run: bash scripts/go\n",
                               "scripts/go": "../lib/go.sh", "lib/go.sh": "echo\n"},
                              modes={"scripts/go": "120000"})
    assert unresolved == [] and "lib/go.sh" in pats


@pytest.mark.parametrize("files,frag", [
    ({".github/workflows/ci.yml": "run: python3 tools/x.py\n",
      "tools/x.py": "import importlib\nimportlib.import_module(name)\n"}, "dynamic import_module()"),
    ({".github/workflows/ci.yml": "run: python3 tools/x.py\n", "tools/x.py": "def (:\n"},
     "cannot parse as Python"),
    ({".github/workflows/ci.yml": "run: bash tools/x.sh\n", "tools/x.sh": 'source "$LIBDIR/a.sh"\n'},
     "dynamic shell reference"),
    ({".github/workflows/ci.yml": "run: python3 ${{ inputs.script }}\n"}, "dynamic shell reference"),
    ({".github/workflows/ci.yml": "run: bash scripts/go\n", "scripts/go": "../../etc/passwd"},
     "symlink target outside"),
])
def test_unresolvable_reference_fails_closed(files, frag):
    modes = {"scripts/go": "120000"} if "scripts/go" in files else None
    _, unresolved = derive(files, modes)
    assert any(frag in u for u in unresolved), unresolved


def test_derivation_on_this_repository_resolves():
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-s"], capture_output=True, text=True, check=True)
    tree = {}
    for line in out.stdout.splitlines():
        meta, path = line.split("\t", 1)
        tree[path] = meta.split()[0]
    pats, unresolved = m.derive_7a(tree, lambda p: (ROOT / p).read_bytes(), V.matches_any, CONFIG)
    assert unresolved == []
    assert ".github/verdict/verdict.py" in pats and ".github/merge/merge.py" in pats


# --------------------------------------------------------------------------
# End to end with real git: fake GitHub API, fake `gh pr merge`
# --------------------------------------------------------------------------

def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture()
def origin(tmp_path):
    """Origin repo: main with a workflow running tools/check.sh; PR 1 changes src/app.py;
    PR 2 changes tools/check.sh (derived 7a); PR 3 renames .github/x.yml out of .github."""
    w = tmp_path / "work"
    w.mkdir()
    git(w, "init", "-q", "-b", "main")
    git(w, "config", "user.email", "t@example.com")
    git(w, "config", "user.name", "t")
    (w / ".github" / "workflows").mkdir(parents=True)
    (w / ".github" / "workflows" / "ci.yml").write_text("on: push\njobs:\n  t:\n    steps:\n      - run: bash tools/check.sh\n")
    (w / ".github" / "x.yml").write_text("a: 1\n")
    (w / "tools").mkdir()
    (w / "tools" / "check.sh").write_text("echo ok\n")
    (w / "src").mkdir()
    (w / "src" / "app.py").write_text("print(1)\n")
    git(w, "add", "-A")
    git(w, "commit", "-q", "-m", "base")
    heads = {}
    for n, change in ((1, lambda: (w / "src" / "app.py").write_text("print(2)\n")),
                      (2, lambda: (w / "tools" / "check.sh").write_text("echo pwned\n")),
                      (3, lambda: git(w, "mv", ".github/x.yml", "docs-x.yml"))):
        git(w, "checkout", "-q", "-b", f"ws/{n}", "main")
        change()
        git(w, "add", "-A")
        git(w, "commit", "-q", "-m", f"pr {n}")
        heads[n] = git(w, "rev-parse", "HEAD")
        git(w, "update-ref", f"refs/pull/{n}/head", heads[n])
        git(w, "checkout", "-q", "main")
    return SimpleNamespace(url=str(w), heads=heads, work=w)


def pr_obj(n, head, labels=("auto-merge", "weight:standard"), repo=REPO, state="open"):
    return {"number": n, "state": state, "draft": False, "labels": [{"name": x} for x in labels],
            "head": {"sha": head, "ref": f"ws/{n}", "repo": {"full_name": repo}},
            "base": {"ref": "main", "repo": {"full_name": REPO, "default_branch": "main"}}}


class FakeGH:
    def __init__(self, prs, labels_before_merge=None, pr_rereads=None):
        self.prs = {p["number"]: p for p in prs}
        self.labels_before_merge = labels_before_merge or {}
        self.pr_rereads = pr_rereads or {}
        self.calls = []
        self.reads = {}

    def get(self, path):
        self.calls.append(path)
        if path == f"repos/{REPO}":
            return {"default_branch": "main"}
        mm = re.fullmatch(rf"repos/{REPO}/pulls/(\d+)", path)
        if mm:
            n = int(mm.group(1))
            self.reads[n] = self.reads.get(n, 0) + 1
            seq = self.pr_rereads.get(n)
            if seq and self.reads[n] > 1:
                return seq
            return self.prs[n]
        raise AssertionError(path)

    def paged(self, path, key=None, limit=100):
        self.calls.append(path)
        if path.startswith(f"repos/{REPO}/pulls?state=open&base=main"):
            return list(self.prs.values())
        mm = re.fullmatch(rf"repos/{REPO}/issues/(\d+)/labels", path)
        if mm:
            n = int(mm.group(1))
            names = self.labels_before_merge.get(n, [x["name"] for x in self.prs[n]["labels"]])
            return [{"name": x} for x in names]
        raise AssertionError(path)


def fake_verdict(passed=True, head_override=None, raises=False, reasons=None):
    calls = []

    def fetch_and_compute(gh, repo, n, cfg):
        calls.append(n)
        assert cfg is VCONFIG
        if raises:
            raise V.VerdictError(raises if isinstance(raises, str) else "boom")
        head = head_override or gh.prs[n]["head"]["sha"]
        return V.Result(passed=passed, head_sha=head, weight="standard",
                        reasons=reasons if reasons is not None else ([] if passed else ["incomplete review set"]))
    return SimpleNamespace(fetch_and_compute=fetch_and_compute, Result=V.Result, matches_any=V.matches_any,
                           VerdictError=V.VerdictError, calls=calls)


def make_runner(origin, prs, verdict=None, event="schedule", ref=REF, merged_ok=True, workflow_sha=None,
                merge_msg="Required status check \"review-verdict\" is expected", **ghkw):
    merges = []

    def merger(repo, n, head, method):
        merges.append((repo, n, head, method))
        return (True, "") if merged_ok else (False, merge_msg)
    ctx = m.Ctx(REPO, "4242", ref, workflow_sha or git(origin.work, "rev-parse", "main"), event)
    gh = FakeGH(prs, **ghkw)
    r = m.Runner(ctx, gh, m.Git(origin.url), verdict or fake_verdict(), VCONFIG, CONFIG, merger)
    return r, merges


def test_clean_labelled_pr_is_merged_after_logged_inline_verdict(origin, capsys):
    h = origin.heads[1]
    r, merges = make_runner(origin, [pr_obj(1, h)])
    assert r.run("true") == 0
    assert merges == [(REPO, 1, h, "squash")]
    out = capsys.readouterr().out
    assert f"PROVENANCE workflow_ref={REF}" in out
    lines = out.splitlines()
    v_line = lines.index(f"VERDICT-RECOMPUTED pr=1 head={h} result=pass")
    clear = next(i for i, x in enumerate(lines) if x.startswith(f"7A-CLEAR pr=1 head={h}"))
    merged = lines.index(f"MERGED pr=1 head={h} run_id=4242 workflow_ref={REF}")
    assert v_line < clear < merged
    assert AUDIT_VERDICT_RE.fullmatch(lines[v_line]) and AUDIT_MERGED_RE.fullmatch(lines[merged])


def test_gh_merge_command_pins_head():
    seen = []

    def run(args, **kw):
        seen.append(args)
        return subprocess.CompletedProcess(args, 0, b"", b"")
    assert m.gh_merge(REPO, 7, "a" * 40, "squash", run=run) == (True, "")
    assert seen == [["gh", "pr", "merge", "7", "--repo", REPO, "--squash", "--match-head-commit", "a" * 40]]


@pytest.mark.parametrize("value", [None, "", "false", "True"])
def test_kill_switch_variable_blocks_everything(origin, capsys, value):
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])])
    assert r.run(value) == 0
    assert merges == []
    out = capsys.readouterr().out
    assert "KILL SWITCH" in out and "VERDICT-RECOMPUTED" not in out
    assert r.gh.calls == []  # not even the candidate list is read


def test_kill_label_blocks(origin, capsys):
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1], labels=("auto-merge", "do-not-auto-merge"))])
    r.run("true")
    assert merges == []
    assert '"do-not-auto-merge" label present' in capsys.readouterr().out


def test_kill_label_added_just_before_merge_blocks(origin, capsys):
    h = origin.heads[1]
    r, merges = make_runner(origin, [pr_obj(1, h)],
                            labels_before_merge={1: ["auto-merge", "do-not-auto-merge"]})
    r.run("true")
    assert merges == []
    assert "label present (re-read before merge)" in capsys.readouterr().out


@pytest.mark.parametrize("n", [2, 3])
def test_7a_pr_is_skipped(origin, capsys, n):
    """PR 2 edits a script the default-branch workflow runs (derived); PR 3 renames
    a .github file out of .github (old side counts)."""
    h = origin.heads[n]
    r, merges = make_runner(origin, [pr_obj(n, h)])
    r.run("true")
    assert merges == []
    out = capsys.readouterr().out
    assert f"SKIP pr={n} head={h} outcome=skipped reason=touches a 7a path; skip (operator merges)" in out
    assert (f'7A-HIT pr={n} 7a path: "tools/check.sh"' if n == 2 else f'7A-HIT pr={n} 7a path: ".github/x.yml"') in out


def test_only_auto_merge_labelled_same_repo_prs_are_candidates(origin, capsys):
    h = origin.heads[1]
    prs = [pr_obj(1, h, labels=("weight:standard",)), pr_obj(4, h, repo="evil/fork")]
    r, merges = make_runner(origin, prs)
    r.run("true")
    assert merges == [] and "CANDIDATES []" in capsys.readouterr().out


def test_operator_merge_label_is_skipped(origin):
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1], labels=("auto-merge", "operator-merge"))])
    r.run("true")
    assert merges == []


@pytest.mark.parametrize("kw", [{"passed": False}, {"raises": True}, {"head_override": "e" * 40}])
def test_failing_or_stale_verdict_never_merges(origin, capsys, kw):
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])], verdict=fake_verdict(**kw))
    assert r.run("true") == 0  # a failing verdict is the normal case: the run stays green
    assert merges == []
    assert f"VERDICT-RECOMPUTED pr=1 head={origin.heads[1]} result=fail" in capsys.readouterr().out.splitlines()


def test_head_moved_before_merge_skips(origin):
    h = origin.heads[1]
    r, merges = make_runner(origin, [pr_obj(1, h)], pr_rereads={1: pr_obj(1, origin.heads[2])})
    r.run("true")
    assert merges == []


def test_fetched_head_not_h_skips(origin, capsys):
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[2])])  # API says H=heads[2], pull/1 is heads[1]
    r.run("true")
    assert merges == [] and "is not H (head moved)" in capsys.readouterr().out


@pytest.mark.parametrize("event,ref", [("workflow_dispatch", REF), ("push", REF),
                                       ("schedule", f"{REPO}/.github/workflows/merge.yml@refs/heads/ws/x"),
                                       ("pull_request_target", f"{REPO}/.github/workflows/other.yml@refs/heads/main")])
def test_refuses_non_default_definition(origin, capsys, event, ref):
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])], event=event, ref=ref)
    assert r.run("true") == 1
    assert merges == [] and "REFUSED" in capsys.readouterr().out


def test_unresolvable_7a_derivation_merges_nothing(origin, capsys):
    w = origin.work
    (w / "tools" / "check.sh").write_text('source "$SOMEWHERE/x.sh"\n')
    git(w, "commit", "-q", "-am", "dynamic")
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])])
    assert r.run("true") == 1
    out = capsys.readouterr().out
    assert merges == [] and "7A-DERIVE unresolved" in out and "no merges this run" in out


def test_unfetchable_pr_fails_closed(origin, capsys):
    git(origin.work, "update-ref", "-d", "refs/pull/1/head")
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])])
    assert r.run("true") == 1  # systemic: the run goes red
    out = capsys.readouterr().out
    assert merges == [] and "outcome=error reason=7a check could not complete (fail closed)" in out


def test_refused_merge_is_logged(origin, capsys):
    h = origin.heads[1]
    r, merges = make_runner(origin, [pr_obj(1, h)], merged_ok=False)
    assert r.run("true") == 1  # a refused merge makes the run red (challenger I2)
    out = capsys.readouterr().out
    assert len(merges) == 1 and f"MERGE-REFUSED pr=1 head={h} kind=check-stale" in out
    assert not any(x.startswith("MERGED") for x in out.splitlines())
    assert "::error title=auto-merge::" in out


# --------------------------------------------------------------------------
# End to end with the REAL verdict function, inline
# --------------------------------------------------------------------------

class VerdictGH(FakeGH):
    """Serves the endpoints verdict.fetch_and_compute reads, for PR 1 at head h."""

    def __init__(self, h, comments, prs):
        super().__init__(prs)
        self.h = h
        self.comments = comments

    def full_pr(self):
        p = dict(self.prs[1])
        p.update({"additions": 1, "deletions": 1, "changed_files": 1, "commits": 1,
                  "body": "Change.\n\nAuthor-Agent: yoshi\n"})
        return p

    def get(self, path):
        if path == f"repos/{REPO}/pulls/1":
            self.calls.append(path)
            return self.full_pr()
        if "/git/trees/" in path:
            return {"sha": "d" * 40, "truncated": False, "tree": [
                {"path": ".github/workflows/ci.yml", "mode": "100644", "type": "blob", "sha": "c" * 40},
                {"path": "src/app.py", "mode": "100644", "type": "blob", "sha": "b" * 40}]}
        if "/contents/" in path:
            return {"type": "file", "sha": "c" * 40}
        return super().get(path)

    def paged(self, path, key=None, limit=100):
        if path.endswith("/pulls/1/files"):
            return [{"filename": "src/app.py", "status": "modified", "additions": 1, "deletions": 1,
                     "patch": "@@ -1 +1 @@"}]
        if path.endswith("/pulls/1/commits"):
            return [{"sha": self.h, "parents": [{"sha": "0" * 40}]}]
        if path.endswith("/issues/1/comments"):
            return self.comments
        if path.endswith("/pulls/1/reviews") or path.endswith("/pulls/1/comments"):
            return []
        if "/actions/runs" in path:
            assert "event=push" in path and f"head_sha={self.h}" in path
            return [{"id": 1, "path": ".github/workflows/ci.yml", "head_sha": self.h, "event": "push",
                     "head_branch": "ws/1", "status": "completed", "conclusion": "success",
                     "created_at": "2026-11-26T09:00:00Z", "run_attempt": 1,
                     "head_repository": {"full_name": REPO}, "repository": {"full_name": REPO}}]
        return super().paged(path, key, limit)


@pytest.mark.parametrize("reviewed_sha_is_head,expect_merge", [(True, True), (False, False)])
def test_real_inline_verdict_gates_the_merge(origin, capsys, reviewed_sha_is_head, expect_merge):
    h = origin.heads[1]
    sha = h if reviewed_sha_is_head else "9" * 40
    comments = [{"body": f"VERDICT: pass reviewer=pr-challenger sha={sha}", "user": {"login": BOT},
                 "created_at": "2026-11-26T10:00:00Z"}]
    prs = [pr_obj(1, h, labels=("auto-merge", "weight:trivial"))]
    gh = VerdictGH(h, comments, prs)
    merges = []
    ctx = m.Ctx(REPO, "7", REF, git(origin.work, "rev-parse", "main"), "pull_request_target")
    r = m.Runner(ctx, gh, m.Git(origin.url), V, VCONFIG, CONFIG,
                 lambda repo, n, head, meth: (merges.append(head) or True, ""))
    r.run("true")
    out = capsys.readouterr().out
    assert (merges == [h]) is expect_merge, out
    assert f"VERDICT-RECOMPUTED pr=1 head={h} result={'pass' if expect_merge else 'fail'}" in out.splitlines()
    assert f"VERDICT-CONTEXT pr=1 head={h} verdict_head=" in out
    if not expect_merge:
        assert "VERDICT-DETAIL pr=1 FAIL: " in out  # the verdict's reasons are logged


# --------------------------------------------------------------------------
# Log contract with the #581 audit, and log-line forgery (wario I-2, I-3)
# --------------------------------------------------------------------------

ALLOWED_LINE_STARTS = ("PROVENANCE ", "CANDIDATES ", "CANDIDATE ", "VERDICT-RECOMPUTED ", "VERDICT-CONTEXT ",
                       "VERDICT-DETAIL ", "7A-DERIVE ", "7A-CLEAR ", "7A-HIT ", "SKIP ", "MERGE-REFUSED ",
                       "MERGE-CONFIRMED ", "MERGED ", "RUN-RESULT ", "REFUSED: ", "KILL SWITCH: ",
                       "STALE-DEFINITION: ", "::error title=auto-merge::")


def assert_log_is_clean(out, legit_merged=(), legit_verdicts=()):
    for line in out.splitlines():
        assert line.startswith(ALLOWED_LINE_STARTS), repr(line)
        if line.startswith("MERGED"):
            assert line in legit_merged, repr(line)
        if line.startswith("VERDICT-RECOMPUTED"):
            assert line in legit_verdicts, repr(line)
        if line.startswith("::"):
            assert line.startswith("::error title=auto-merge::") and "\\x" not in line


def test_audit_regexes_match_the_audit_file():
    audit = ROOT / ".github" / "audit" / "audit.py"
    if not audit.exists():
        pytest.skip("the #581 audit (fleet-pilot#4) is not on this branch yet")
    src = audit.read_text()
    for name, ours in (("MERGED_RE", AUDIT_MERGED_RE), ("VERDICT_LOG_RE", AUDIT_VERDICT_RE)):
        mm = re.search(rf'^{name} = re\.compile\(r"(.*)"\)$', src, re.MULTILINE)
        assert mm and mm.group(1) == ours.pattern, name


FORGED = [f"x\nMERGED pr=9 head={'a' * 40} run_id=4242 workflow_ref={REF}",
          f"y\r\nVERDICT-RECOMPUTED pr=9 head={'a' * 40} result=pass",
          "z\n::add-mask::MERGED", "w ::stop-commands::t", "\n  ::warning::x"]


def test_pr_text_in_verdict_reasons_cannot_forge_lines(origin, capsys):
    h = origin.heads[1]
    r, merges = make_runner(origin, [pr_obj(1, h)], verdict=fake_verdict(passed=False, reasons=FORGED))
    r.run("true")
    out = capsys.readouterr().out
    assert merges == []
    assert_log_is_clean(out, legit_verdicts=(f"VERDICT-RECOMPUTED pr=1 head={h} result=fail",))


def test_pr_file_names_cannot_forge_lines(origin, capsys):
    """A file name with newlines reaches the 7a hit lines: it is escaped, never a line of its own."""
    w = origin.work
    git(w, "checkout", "-q", "-b", "ws/5", "main")
    for i, name in enumerate(FORGED):
        p = w / ".github" / name.replace("/", "_")
        p.write_text(f"{i}\n")
    git(w, "add", "-A")
    git(w, "commit", "-q", "-m", "pr 5")
    h = git(w, "rev-parse", "HEAD")
    git(w, "update-ref", "refs/pull/5/head", h)
    git(w, "checkout", "-q", "main")
    r, merges = make_runner(origin, [pr_obj(5, h)])
    r.run("true")
    out = capsys.readouterr().out
    assert merges == [] and "7A-HIT pr=5" in out
    assert_log_is_clean(out, legit_verdicts=(f"VERDICT-RECOMPUTED pr=5 head={h} result=pass",))


def test_log_escapes_and_guards_reserved_prefixes(capsys):
    m.log("a\nMERGED pr=1")
    m.log("MERGED pr=1 head=x")
    m.log("::add-mask::x")
    out = capsys.readouterr().out.splitlines()
    assert out == ["a\\x0aMERGED pr=1", "LOG MERGED pr=1 head=x", "LOG ::add-mask::x"]


# --------------------------------------------------------------------------
# Systemic failures, confirmed merges, re-derivation (challenger I2, I5)
# --------------------------------------------------------------------------

def merged_pr(n, head, by):
    p = pr_obj(n, head)
    p.update({"state": "closed", "merged": True, "merged_by": {"login": by}})
    return p


def test_timed_out_merge_that_landed_is_logged_as_merged(origin, capsys):
    h = origin.heads[1]
    r, merges = make_runner(origin, [pr_obj(1, h)], merged_ok=False, merge_msg="TimeoutExpired: 120s",
                            pr_rereads={1: pr_obj(1, h)})
    # first re-read (before the merge) sees the open PR; the one after the failed call sees it merged
    seq = iter([pr_obj(1, h), pr_obj(1, h), merged_pr(1, h, "github-actions[bot]")])
    r.gh.get = lambda path, _g=r.gh.get: next(seq) if path == f"repos/{REPO}/pulls/1" else _g(path)
    assert r.run("true") == 0
    lines = capsys.readouterr().out.splitlines()
    assert f"MERGED pr=1 head={h} run_id=4242 workflow_ref={REF}" in lines
    assert any(x.startswith("MERGE-CONFIRMED pr=1") for x in lines)


def test_failed_merge_merged_by_someone_else_is_not_claimed(origin, capsys):
    h = origin.heads[1]
    r, merges = make_runner(origin, [pr_obj(1, h)], merged_ok=False, merge_msg="Pull request is not mergeable")
    seq = iter([pr_obj(1, h), pr_obj(1, h), merged_pr(1, h, "acardote")])
    r.gh.get = lambda path, _g=r.gh.get: next(seq) if path == f"repos/{REPO}/pulls/1" else _g(path)
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert not any(x.startswith("MERGED") for x in out.splitlines()) and "merged by another actor" in out


def test_api_failure_in_verdict_makes_the_run_red(origin, capsys):
    v = fake_verdict(raises="GET repos/acardote/fleet-pilot/pulls/1/reviews failed: HTTP 403")
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])], verdict=v)
    assert r.run("true") == 1
    out = capsys.readouterr().out
    assert merges == [] and "outcome=error" in out and "RUN-RESULT merged=0 skipped=0 error=1 refused=0" in out


def test_ordinary_verdict_error_is_a_plain_skip(origin, capsys):
    v = fake_verdict(raises="weight: no weight label")
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])], verdict=v)
    assert r.run("true") == 0 and merges == []


def test_rederives_after_each_merge(origin, capsys):
    w = origin.work
    git(w, "checkout", "-q", "-b", "ws/6", "main")
    (w / "src" / "other.py").write_text("x = 1\n")
    git(w, "add", "-A")
    git(w, "commit", "-q", "-m", "pr 6")
    h6 = git(w, "rev-parse", "HEAD")
    git(w, "update-ref", "refs/pull/6/head", h6)
    git(w, "checkout", "-q", "main")
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1]), pr_obj(6, h6)])
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert [x[1] for x in merges] == [1, 6]
    assert out.count("7A-DERIVE base=") == 2


def test_stale_definition_stops_the_run(origin, capsys):
    w = origin.work
    wsha = git(w, "rev-parse", "main")
    (w / "tools" / "check.sh").write_text("echo tightened\n")  # a 7a change lands after this run was queued
    git(w, "commit", "-q", "-am", "7a change")
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])], workflow_sha=wsha)
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert merges == [] and "STALE-DEFINITION" in out


def test_non_7a_change_after_definition_does_not_stop_the_run(origin, capsys):
    w = origin.work
    wsha = git(w, "rev-parse", "main")
    (w / "src" / "lib.py").write_text("y = 2\n")
    git(w, "add", "-A")
    git(w, "commit", "-q", "-m", "ordinary change")
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])], workflow_sha=wsha)
    assert r.run("true") == 0 and [x[1] for x in merges] == [1]


def test_missing_run_id_refuses_before_any_merge(origin, capsys):
    r, merges = make_runner(origin, [pr_obj(1, origin.heads[1])])
    r.ctx.run_id = ""
    assert r.run("true") == 1 and merges == []
