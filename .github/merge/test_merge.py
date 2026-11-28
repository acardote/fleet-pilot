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

import base64
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
    assert wf["on"]["schedule"] == [{"cron": "17 * * * *"}]


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
               "re", "subprocess", "sys", "tempfile", "time", "dataclasses", "pathlib", "typing"}
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


# --- Command positions (fp#3 verify N1/N2): wrappers, -m, make, npm --------

def wf_run(body: str) -> str:
    return "jobs:\n  a:\n    steps:\n      - run: |\n" + "".join(f"          {ln}\n" for ln in body.split("\n"))


WRAPPED = [
    "timeout 30 tools/run", "timeout 30s tools/run --x", "timeout -k 5 30 tools/run",
    "timeout --signal=KILL 30 tools/run", "timeout -s KILL 1m tools/run", "timeout --foreground 5 tools/run",
    "ls | xargs tools/run", "ls | xargs -n1 tools/run",
    "ls | xargs -n 1 -P 4 tools/run", "ls | xargs -I{} tools/run {}", "ls | xargs -0 -r tools/run",
    "env A=b tools/run", "env -i A=b C=d tools/run", "env -u HOME tools/run", "env -S 'tools/run --x'",
    "nice tools/run", "nice -n 10 tools/run", "nice -10 tools/run", "nohup tools/run &", "nohup tools/run > log 2>&1 &",
    "sudo tools/run", "sudo -u bob -E tools/run", "sudo -E A=1 tools/run", "exec tools/run", "exec -a name tools/run",
    "command tools/run", "time tools/run", "time -p tools/run", "stdbuf -oL tools/run", "stdbuf -o L tools/run",
    "setsid -f tools/run", "ionice -c 3 tools/run", "flock -w 5 /tmp/lock tools/run", "flock /tmp/lock -c 'tools/run'",
    "watch -n 5 tools/run", "eval 'tools/run --x'", "FOO=1 tools/run", "FOO=1 BAR=2 tools/run", "! tools/run",
    "if tools/run; then echo ok; fi", "while tools/run; do :; done", "x=$(tools/run)", "x=`tools/run`",
    'echo "$(tools/run)"', "diff <(tools/run) b", "find . -name '*.md' -exec tools/run {} \\;",
    "find . -execdir tools/run {} +", "cd tools && ./run", "cd tools\n./run", "{ tools/run; }",
    "f() { tools/run; }", "[ -x tools/run ] && tools/run", "true || tools/run", "tools/run | tee out",
    "timeout 5 env A=1 nice tools/run", "sudo -u x timeout 5 tools/run", "uv run --with pyyaml tools/run",
    "uv run --quiet --with a --with b tools/run", "poetry run tools/run", "bash -c 'tools/run'",
    "timeout 9 bash -c 'tools/run'", "sh -ec 'cd tools && ./run'", "nohup sh -c \"tools/run\" &",
    "timeout --frobnicate 5 tools/run", "xargs --frob tools/run", "xargs -Z 7 tools/run",
    "tools/run \\\n  --flag", "# a comment\ntools/run", "pushd tools && ./run", "bash <<'EOF'\ntools/run\nEOF",
]


@pytest.mark.parametrize("body", WRAPPED)
def test_wrapped_and_nested_commands_are_followed(body):
    """N1: an extensionless script reached through a wrapper or a shell construct is 7a."""
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run(body), "tools/run": "echo hi\n",
                               "docs/a.md": "x\n"})
    assert unresolved == [], unresolved
    assert "tools/run" in pats, (body, [p for p in pats if p not in CONFIG["floor_7a"]])
    assert not V.matches_any("docs/a.md", pats)


@pytest.mark.parametrize("body", [
    "echo tools/run", "cat tools/run", "git add tools/", "ls docs/ memory/", "# run `tools/run` by hand",
    "echo 'see `tools/run`'  # backticks in a comment: `memory/`",
])
def test_mentions_are_still_not_execution_edges(body):
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run(body), "tools/run": "echo\n",
                               "memory/a.md": "x\n", "docs/a.md": "x\n"})
    assert unresolved == []
    for p in ("memory/a.md", "docs/a.md"):
        assert not V.matches_any(p, pats), (body, p)
    if "echo 'see" not in body:  # `...` inside single quotes is read as a command: over-inclusion is allowed
        assert not V.matches_any("tools/run", pats), body


def test_executable_bit_file_named_anywhere_is_an_edge():
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run('out="$(echo tools/run-me)"\nlog tools/plain'),
                               "tools/run-me": "echo\n", "tools/plain": "echo\n"},
                              modes={"tools/run-me": "100755"})
    assert unresolved == [] and "tools/run-me" in pats


@pytest.mark.parametrize("body", [
    "python -m tools.gen", "python3 -m tools.gen --x", "python3 -I -m tools.gen", "python3 -Im tools.gen",
    "python -mtools.gen", "python3 -W ignore -m tools.gen", "python3 -X dev -u -m tools.gen",
    "python3.12 -m tools.gen", "timeout 60 python3 -I -m tools.gen", "uv run python -m tools.gen",
    "python3 -c 'import tools.gen'", "python3 -c 'from tools import gen'",
    "python3 - <<'EOF'\nimport tools.gen\nEOF", "cat <<EOF | python3\nfrom tools.gen import main\nEOF",
])
def test_python_module_invocation_resolves_to_the_module_file(body):
    """N2: `python -m a.b` runs a/b.py (or a/b/__main__.py); the old derivation recorded a bogus 'a.b'."""
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run(body), "tools/__init__.py": "",
                               "tools/gen.py": "from tools import helper\n", "tools/helper.py": "X = 1\n"})
    assert unresolved == [], unresolved
    for p in ("tools/gen.py", "tools/helper.py", "tools/__init__.py"):
        assert p in pats, (body, p)
    assert "tools.gen" not in pats


def test_python_module_package_main_and_shadowing_candidates_are_7a():
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("python -m tools.gen\npython -m tools.later"),
                               "tools/gen/__init__.py": "", "tools/gen/__main__.py": "import os\n",
                               "tests/t.py": "x\n"})
    assert unresolved == []
    for p in ("tools/gen/__init__.py", "tools/gen/__main__.py",
              # not in the tree yet: a PR that creates one is 7a
              "tools/gen.py", "tools/later.py", "tools/later/__main__.py", "tools/later/__init__.py",
              "tools/__init__.py"):
        assert V.matches_any(p, pats), p


def test_python_m_pytest_does_not_make_the_test_tree_7a():
    """By design: test files are what pytest is given, not an execution edge (the CI token is read-only)."""
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 -m pytest -q tests"),
                               "tests/test_a.py": "def test_a():\n    pass\n"})
    assert unresolved == []
    assert not V.matches_any("tests/test_a.py", pats)
    assert V.matches_any("pytest/__main__.py", pats) and V.matches_any("pytest.py", pats)


@pytest.mark.parametrize("body,frag", [
    ('python3 -m "$MOD"', "python -m module"),
    ("python3 -Z tools/x.py", "python option"),
    ('make -C "$DIR" all', "make directory"),
    ('make -f "$MK"', "make file"),
    ('"$TOOLS/run" --x', "dynamic command"),
    ("timeout 5 \"${BIN}/run\"", "dynamic command"),
    ("node -e 'require(\"./tools/x\")'", "inline node code"),
    ('npm --prefix "$P" ci', "package directory"),
])
def test_unresolvable_command_positions_fail_closed(body, frag):
    _, unresolved = derive({".github/workflows/ci.yml": wf_run(body)})
    assert any(frag in u for u in unresolved), unresolved


def test_github_script_javascript_is_not_read_as_shell_syntax():
    wf = ("jobs:\n  a:\n    steps:\n      - uses: actions/github-script@v7\n        with:\n"
          "          script: |\n            const u = `${owner}/${repo}`;\n            run(`${ref.o}/${ref.r}`);\n"
          "      - run: '\"${BIN}/run\"'\n")
    _, unresolved = derive({".github/workflows/ci.yml": wf})
    assert len(unresolved) == 1 and "${BIN}/run" in unresolved[0], unresolved


def test_make_invocation_derives_the_makefile_and_its_recipes():
    pats, unresolved = derive({
        ".github/workflows/ci.yml": wf_run("make test\nmake -C sub build\nmake -f build/extra.mk x"),
        "Makefile": "PY := python3\ninclude common.mk\ntest:\n\t@scripts/check --all\n\t$(PY) -m tools.gen\n",
        "common.mk": "lint:\n\ttools/lint-me\n",
        "sub/Makefile": "build:\n\t./build.sh\n", "sub/build.sh": "echo\n",
        "build/extra.mk": "x:\n\ttimeout 5 tools/x\n",
        "scripts/check": "echo\n", "tools/gen.py": "x = 1\n", "tools/lint-me": "echo\n", "tools/x": "echo\n"})
    assert unresolved == [], unresolved
    for p in ("Makefile", "common.mk", "scripts/check", "tools/gen.py", "tools/lint-me", "sub/Makefile",
              "sub/build.sh", "build/extra.mk", "tools/x"):
        assert V.matches_any(p, pats), p


@pytest.mark.parametrize("path", ["Makefile", "sub/makefile", "GNUmakefile", "x/rules.mk", "justfile",
                                  "Taskfile.yml", "Dockerfile", "docker/Dockerfile.ci", "docker-compose.yml"])
def test_build_tool_entry_files_are_on_the_floor(path):
    assert V.matches_any(path, CONFIG["floor_7a"]), path


@pytest.mark.parametrize("body", ["npm run build", "npm ci", "npm test", "yarn build", "pnpm install",
                                  "timeout 600 npm run build", "cd web && npm run build", "npm --prefix web ci",
                                  "pnpm -C web run build", "pnpm -r run build"])
def test_npm_family_invocation_derives_package_json_scripts(body):
    pkg = json.dumps({"scripts": {"build": "node tools/b.js", "postinstall": "tools/setup", "test": "tools/t"}})
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run(body), "package.json": pkg,
                               "web/package.json": pkg, "tools/b.js": "1\n", "tools/setup": "echo\n",
                               "tools/t": "echo\n"})
    assert unresolved == [], unresolved
    for p in ("tools/b.js", "tools/setup", "tools/t"):
        assert V.matches_any(p, pats), (body, p)


@pytest.mark.parametrize("code", [
    "import subprocess\nsubprocess.run(['tools/run', '--x'])\n",
    "import subprocess\nsubprocess.check_call(['timeout', '5', 'tools/run'])\n",
    "import subprocess\nsubprocess.run('tools/run --x', shell=True)\n",
    "import os\nos.system('nohup tools/run &')\n",
    "import os\nos.execv('tools/run', ['run'])\n",
    "import subprocess\nsubprocess.Popen(['python3', '-m', 'tools.runmod'])\n",
])
def test_python_subprocess_literals_are_followed(code):
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/x.py"), "tools/x.py": code,
                               "tools/run": "echo\n", "tools/runmod.py": "x = 1\n"})
    assert unresolved == [], unresolved
    assert "tools/run" in pats or "tools/runmod.py" in pats, code


_PYH = "import subprocess, sys, os, functools\nfrom pathlib import Path\n"
_HERE_RUN = "Path(__file__).parent / 'run'"


@pytest.mark.parametrize("code,target", [
    ("subprocess.run([str(Path(__file__).parents[1] / 'scripts' / 'y')])", "scripts/y"),
    ("subprocess.run([str(Path(__file__).resolve().parents[1] / 'scripts' / 'y')])", "scripts/y"),
    ("ROOT = Path(__file__).resolve().parents[1]\nsubprocess.run([str(ROOT / 'scripts' / 'y')])", "scripts/y"),
    ("subprocess.run([str(Path(__file__).parents[0] / 'run')])", "tools/run"),
    ("subprocess.run([str(Path(__file__).parents[1] / 'deploy-it')])", "deploy-it"),
])
def test_python_parents_index_is_evaluated(code, target):
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/x.py"), "tools/x.py": _PYH + code,
                               "tools/run": "echo\n", "scripts/y": "echo\n", "deploy-it": "echo\n"})
    assert unresolved == [], unresolved
    assert V.matches_any(target, pats), code


@pytest.mark.parametrize("code", [
    f"getattr(subprocess, 'run')([str({_HERE_RUN})])",
    f"getattr(os, 'system')(str({_HERE_RUN}))",
    f"r = subprocess.run\nr([str({_HERE_RUN})])",
    f"from subprocess import run as r\nr([str({_HERE_RUN})])",
    f"import subprocess as sp\nsp.run([str({_HERE_RUN})])",
    f"sp = subprocess\nr = sp.check_call\nr([str({_HERE_RUN})])",
    f"r = getattr(subprocess, 'Popen')\nr([str({_HERE_RUN})])",
    f"functools.partial(subprocess.run, [str({_HERE_RUN})])()",
    f"from functools import partial\npartial(subprocess.run, [str({_HERE_RUN})], check=True)()",
    f"import pty\npty.spawn([str({_HERE_RUN})])",
    f"os.posix_spawn(str({_HERE_RUN}), ['run'], os.environ)",
    f"os.posix_spawnp(str({_HERE_RUN}), ['run'], os.environ)",
    f"class C:\n    r = subprocess.run\n    def go(self):\n        self.r([str({_HERE_RUN})])\n",
    "getattr(subprocess, 'run')(['tools/' + 'ru' + 'n'])",
])
def test_python_exec_aliases_and_forms_are_followed(code):
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/x.py"), "tools/x.py": _PYH + code,
                               "tools/run": "echo\n"})
    assert unresolved == [], unresolved
    assert V.matches_any("tools/run", pats), code


@pytest.mark.parametrize("code", [
    "getattr(subprocess, sys.argv[1])(['x'])",
    "import subprocess as sp\nfn = sys.argv[1]\ngetattr(sp, fn)(['x'])",
    "functools.partial(subprocess.run)(sys.argv[1:])",
    "def go(f):\n    f(sys.argv[1:])\ngo(subprocess.run)",
    "TABLE = {'r': subprocess.run}\nTABLE['r'](sys.argv[1:])",
    "from subprocess import run as r\nhooks = [r]\nhooks[0](sys.argv[1:])",
])
def test_python_unresolvable_exec_shapes_use_the_fallback(code):
    # Names nothing: fails closed.
    _, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/x.py"), "tools/x.py": _PYH + code})
    assert unresolved and "tools/x.py" in unresolved[0], (code, unresolved)
    # Names a tree file statically: that file becomes 7a.
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/x.py"),
                               "tools/x.py": _PYH + "TARGET = 'tools/run'\n" + code, "tools/run": "echo\n"})
    assert unresolved == [], (code, unresolved)
    assert V.matches_any("tools/run", pats), code


def test_python_exec_shapes_do_not_flag_unrelated_getattr_or_names():
    code = _PYH + "x = getattr(os, 'environ')\nrun = 3\ncall = run + 1\nprint(subprocess.DEVNULL)\n"
    _, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/x.py"), "tools/x.py": code})
    assert unresolved == [], unresolved


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


VERDICT_RUNS_RE = re.compile(rf"repos/{REPO}/actions/workflows/verdict\.yml/runs\?head_sha=([0-9a-f]{{40}})"
                             r"&event=pull_request_target&per_page=100")


def vrun(head, rid=900, status="completed", conclusion="success", path=".github/workflows/verdict.yml",
         event="pull_request_target"):
    return {"id": rid, "status": status, "conclusion": conclusion if status == "completed" else None,
            "path": path, "event": event, "head_sha": head}


def default_verdict_runs(head, i):
    return [vrun(head)]


class FakeGH:
    def __init__(self, prs, labels_before_merge=None, pr_rereads=None, verdict_runs=default_verdict_runs):
        self.prs = {p["number"]: p for p in prs}
        self.verdict_runs = verdict_runs  # (head, call index) -> verdict.yml runs at head (#596)
        self.vreads = 0
        self.labels_before_merge = labels_before_merge or {}
        self.pr_rereads = pr_rereads or {}
        self.calls = []
        self.reads = {}

    def get(self, path):
        self.calls.append(path)
        mm = VERDICT_RUNS_RE.fullmatch(path)
        if mm:
            self.vreads += 1
            return {"total_count": 1, "workflow_runs": self.verdict_runs(mm.group(1), self.vreads - 1)}
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
    # a check-stale refusal is retried once in the run (#596), then logged
    assert len(merges) == 2 and f"MERGE-REFUSED pr=1 head={h} kind=check-stale" in out
    assert f"MERGE-RETRY pr=1 head={h} kind=check-stale" in out
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
        mm = VERDICT_RUNS_RE.fullmatch(path)
        if mm:
            return {"workflow_runs": [vrun(mm.group(1))]}
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


def test_step_working_directory_resolves_relative_commands():
    wf = ("jobs:\n  a:\n    steps:\n      - working-directory: tools\n        run: |\n          ./run\n"
          "          python3 -m gen\n")
    pats, unresolved = derive({".github/workflows/ci.yml": wf, "tools/run": "echo\n", "tools/gen.py": "x = 1\n"})
    assert unresolved == [] and "tools/run" in pats and "tools/gen.py" in pats
    _, unresolved = derive({".github/workflows/ci.yml": wf.replace("tools", "${{ matrix.dir }}")})
    assert any("working-directory" in u for u in unresolved), unresolved


def test_just_derives_the_justfile_and_task_fails_closed():
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("just check"),
                               "justfile": "check:\n    tools/run --all\n", "tools/run": "echo\n"})
    assert unresolved == [] and "justfile" in pats and "tools/run" in pats
    _, unresolved = derive({".github/workflows/ci.yml": wf_run("task check")})
    assert any("Taskfile" in u for u in unresolved), unresolved


def test_basic_auth_header_is_masked_on_actions(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    calls = []
    m.Git("https://github.com/o/r.git", token="tok", workdir=str(tmp_path / "g"),
          run=lambda *a, **k: calls.append(a) or subprocess.CompletedProcess(a, 0, b"", b""))
    basic = base64.b64encode(b"x-access-token:tok").decode()
    assert f"::add-mask::{basic}" in capsys.readouterr().out.splitlines()


# --- Python path arithmetic (fp#3 re-verify R1) ------------------------------

R1_CODE = [
    "import os, subprocess\nsubprocess.Popen([os.path.join(os.path.dirname(__file__), 'run')])\n",
    "import subprocess\nfrom pathlib import Path\nsubprocess.run([str(Path(__file__).parent / 'run')])\n",
    "import subprocess\nfrom pathlib import Path\n"
    "subprocess.run([str(Path(__file__).resolve().parent.joinpath('run'))])\n",
    "import os, subprocess\nHERE = os.path.dirname(os.path.abspath(__file__))\n"
    "subprocess.run([os.path.join(HERE, 'run'), '-x'])\n",
    "import os\nos.execv(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'run'), ['run'])\n",
    "import os\nfrom pathlib import Path\nos.spawnv(os.P_WAIT, str(Path(__file__).parent / 'run'), ['run'])\n",
    "import subprocess\nfrom pathlib import Path\nROOT = Path(__file__).parent.parent\n"
    "subprocess.run([ROOT / 'tools' / 'run'])\n",
    "import subprocess\nsubprocess.run(['./run'])\n",
    "import subprocess, os\nHERE = os.path.dirname(__file__)\nsubprocess.run(f'{HERE}/run --x', shell=True)\n",
    "import subprocess, os\nCMD = [os.path.join(os.path.dirname(__file__), 'run'), '--x']\n"
    "subprocess.check_call(CMD)\n",
    "import runpy\nfrom pathlib import Path\nrunpy.run_path(str(Path(__file__).parent / 'run'))\n",
]


@pytest.mark.parametrize("code", R1_CODE)
def test_python_file_relative_exec_targets_are_followed(code):
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/a.py"), "tools/a.py": code,
                               "tools/run": "echo\n", "run": "echo root\n"})
    assert unresolved == [], unresolved
    assert "tools/run" in pats, code


def test_python_interpreter_with_file_relative_script():
    code = ("import subprocess, sys\nfrom pathlib import Path\n"
            "subprocess.run([sys.executable, str(Path(__file__).parent / 'gen')])\n")
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/a.py"), "tools/a.py": code,
                               "tools/gen": "#!/usr/bin/env python3\nimport os\n"})
    assert unresolved == [] and "tools/gen" in pats


@pytest.mark.parametrize("code", [
    "import subprocess\nfrom pathlib import Path\nHERE = Path(__file__).parent\n"
    "def go(cmd):\n    return subprocess.run(cmd)\ngo([HERE / 'run'])\n",
    "import subprocess, sys\nfrom pathlib import Path\nTOOL = Path(__file__).parent / 'run'\n"
    "def go(script):\n    return subprocess.run([sys.executable, script])\ngo(TOOL)\n",
    "import subprocess, sys\n\ndef t(p):\n"
    "    subprocess.run([sys.executable, '-c', 'import runpy, sys; runpy.run_path(sys.argv[1])', p])\n"
    "t('tools/run')\n",
])
def test_non_literal_command_is_bounded_by_what_the_file_names(code):
    """A command that is not static: every tree file the module names statically is an edge."""
    pats, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/a.py"), "tools/a.py": code,
                               "tools/run": "echo\n", "docs/a.md": "x\n"})
    assert unresolved == [], unresolved
    assert "tools/run" in pats
    assert not V.matches_any("docs/a.md", pats)


@pytest.mark.parametrize("code", [
    "import subprocess, sys\nsubprocess.run(sys.argv[1:])\n",
    "import os, sys\nos.system(sys.argv[1])\n",
    "import os, sys\nos.execv(sys.argv[1], sys.argv[1:])\n",
])
def test_non_literal_command_in_a_file_naming_nothing_fails_closed(code):
    _, unresolved = derive({".github/workflows/ci.yml": wf_run("python3 tools/a.py"), "tools/a.py": code})
    assert any("non-literal command" in u for u in unresolved), unresolved


# --------------------------------------------------------------------------
# #596: the merge race with verdict.yml (wait for the required check, retry once)
# --------------------------------------------------------------------------

POLICY_MSG = "GraphQL: Repository rule violations found. The base branch policy prohibits the merge. (mergePullRequest)"


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s

    def __call__(self):
        return self.t


def race_runner(origin, prs, results, verdict_runs=default_verdict_runs, **kw):
    """A runner whose merge calls return `results` in order, with a fake clock."""
    r, merges = make_runner(origin, prs, verdict_runs=verdict_runs, **kw)
    seq = list(results)

    def merger(repo, n, head, method):
        merges.append((repo, n, head, method))
        return seq.pop(0)
    r.merger = merger
    clock = FakeClock()
    r.sleep, r.clock = clock.sleep, clock
    return r, merges, clock


def contract_lines(out, n, h):
    lines = out.splitlines()
    v = [x for x in lines if x.startswith(f"VERDICT-RECOMPUTED pr={n} ")]
    mg = [x for x in lines if x.startswith(f"MERGED pr={n} ")]
    return v, mg


def test_waits_for_a_pending_verdict_check_then_merges(origin, capsys):
    h = origin.heads[1]
    runs = lambda head, i: [vrun(head, 900, "completed", "cancelled"),  # noqa: E731
                            vrun(head, 901, "in_progress" if i < 3 else "completed")]
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [(True, "")], verdict_runs=runs)
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert merges == [(REPO, 1, h, "squash")]
    assert clock.sleeps == [10, 10, 10]
    assert f"CHECK-WAIT pr=1 head={h} state=success run=901" in out
    v, mg = contract_lines(out, 1, h)
    # it waited, so steps 4 and 5 ran again: a second, identical-format VERDICT-RECOMPUTED line
    assert v == [f"VERDICT-RECOMPUTED pr=1 head={h} result=pass"] * 2 and len(mg) == 1
    assert out.count("7A-DERIVE base=") == 2 and f"RE-VERIFY pr=1 head={h} attempt=1 waited=30s" in out
    assert AUDIT_MERGED_RE.fullmatch(mg[0])


def test_policy_refusal_while_check_is_recreated_is_retried_in_run(origin, capsys):
    """fleet-pilot#15 / run 45897564151: verdict.yml's concurrency group recreated the
    check between the wait and the merge call; the ruleset refused with "base branch policy"."""
    h = origin.heads[1]

    def runs(head, i):
        if i == 0:
            return [vrun(head, 900)]                       # step 7 sees the old success
        if i == 1:
            return [vrun(head, 900, "completed", "cancelled"), vrun(head, 901, "queued")]  # refusal: recreated
        return [vrun(head, 900, "completed", "cancelled"), vrun(head, 901)]
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [(False, POLICY_MSG), (True, "")], verdict_runs=runs)
    assert r.run("true") == 0  # no red run
    out = capsys.readouterr().out
    assert merges == [(REPO, 1, h, "squash")] * 2
    assert f"MERGE-RETRY pr=1 head={h} kind=check-stale" in out
    assert "MERGE-REFUSED" not in out
    v, mg = contract_lines(out, 1, h)
    assert v == [f"VERDICT-RECOMPUTED pr=1 head={h} result=pass"] * 2  # the retry re-verifies
    assert f"RE-VERIFY pr=1 head={h} attempt=2" in out
    assert mg == [f"MERGED pr=1 head={h} run_id=4242 workflow_ref={REF}"]
    assert "RUN-RESULT merged=1 skipped=0 error=0 refused=0" in out


def test_policy_refusal_with_settled_check_waits_retries_once_and_merges(origin, capsys):
    """ee-fleet-pilot#11 / run 46070064439: step 7 read the check as success (waited=0s), but
    GitHub's merge policy had not seen it yet. The refusal is check-stale, so the run pauses
    POLICY_SETTLE_S, re-reads the check, re-verifies, re-reads the labels and head, and merges."""
    h = origin.heads[1]
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [(False, POLICY_MSG), (True, "")])
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert merges == [(REPO, 1, h, "squash")] * 2  # both calls pinned to H (--match-head-commit)
    assert clock.sleeps == [m.POLICY_SETTLE_S] and m.POLICY_SETTLE_S == 15
    assert f"MERGE-RETRY pr=1 head={h} kind=check-stale wait=15s" in out
    assert "MERGE-REFUSED" not in out
    assert out.count(f"CHECK-WAIT pr=1 head={h} state=success") == 2  # step 7 re-read before the retry
    assert f"RE-VERIFY pr=1 head={h} attempt=2" in out
    v, mg = contract_lines(out, 1, h)
    assert v == [f"VERDICT-RECOMPUTED pr=1 head={h} result=pass"] * 2
    assert mg == [f"MERGED pr=1 head={h} run_id=4242 workflow_ref={REF}"]
    assert "RUN-RESULT merged=1 skipped=0 error=0 refused=0" in out


def test_policy_refusal_twice_is_refused_not_looped(origin, capsys):
    h = origin.heads[1]
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [(False, POLICY_MSG), (False, POLICY_MSG)])
    assert r.run("true") == 1
    out = capsys.readouterr().out
    assert len(merges) == 2 and out.count("MERGE-RETRY") == 1 and clock.sleeps == [15]
    assert f"MERGE-REFUSED pr=1 head={h} kind=check-stale" in out
    assert not any(x.startswith("MERGED") for x in out.splitlines())
    assert "RUN-RESULT merged=0 skipped=0 error=0 refused=1" in out


def test_other_refusal_is_not_retried(origin, capsys):
    h = origin.heads[1]
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [(False, "GraphQL: Pull Request is not mergeable")])
    assert r.run("true") == 1
    out = capsys.readouterr().out
    assert len(merges) == 1 and "MERGE-RETRY" not in out and clock.sleeps == []
    assert f"MERGE-REFUSED pr=1 head={h} kind=other" in out


def test_head_moved_during_the_policy_wait_blocks_the_retry(origin, capsys):
    h = origin.heads[1]
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [(False, POLICY_MSG)])
    reads = {"n": 0}
    orig = r.gh.get

    def get(path):
        res = orig(path)
        if path == f"repos/{REPO}/pulls/1":
            reads["n"] += 1
            if reads["n"] > 3:  # initial read, step 6 re-read, failed-merge re-read; then moved
                res = dict(res, head=dict(res["head"], sha="f" * 40))
        return res
    r.gh.get = get
    r.run("true")
    out = capsys.readouterr().out
    assert len(merges) == 1 and "MERGE-RETRY" in out
    assert not any(x.startswith("MERGED") for x in out.splitlines())


def test_run_deadline_during_the_policy_wait_blocks_the_retry(origin, capsys):
    """AUTO_MERGE_ENABLED cannot be re-read in-run (GITHUB_TOKEN has no Variables permission); the
    run-deadline check before every merge call bounds its latency, and it applies to the retry too."""
    h = origin.heads[1]
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [(False, POLICY_MSG)])

    def slow_sleep(s):  # the policy pause lands past the run deadline
        clock.sleeps.append(s)
        clock.t += m.RUN_DEADLINE_S + 1
    r.sleep = slow_sleep
    r.run("true")
    out = capsys.readouterr().out
    assert len(merges) == 1 and "MERGE-RETRY" in out
    assert not any(x.startswith("MERGED") for x in out.splitlines())
    assert f"SKIP pr=1 head={h}" in out and "run deadline 600s reached before the merge call" in out


def test_retry_refused_again_is_logged_check_stale_and_red(origin, capsys):
    h = origin.heads[1]
    runs = lambda head, i: [vrun(head, 900 + i)]  # noqa: E731 - a new run every read: always "new"
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [(False, POLICY_MSG), (False, POLICY_MSG)],
                               verdict_runs=runs)
    assert r.run("true") == 1
    out = capsys.readouterr().out
    assert len(merges) == 2 and out.count("MERGE-RETRY") == 1
    assert f"MERGE-REFUSED pr=1 head={h} kind=check-stale" in out
    assert not any(x.startswith("MERGED") for x in out.splitlines())


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", "neutral", "timed_out", "None"])
def test_never_merges_past_a_non_success_check(origin, capsys, conclusion):
    h = origin.heads[1]
    runs = lambda head, i: [vrun(head, 900), vrun(head, 901, "completed", conclusion)]  # noqa: E731
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [], verdict_runs=runs)
    assert r.run("true") == 0  # skipped, not red every cycle (fp17 challenger M2)
    out = capsys.readouterr().out
    assert merges == []
    assert f'outcome=skipped reason=review-verdict check at H concluded "{conclusion}"' in out
    v, mg = contract_lines(out, 1, h)
    assert v == [f"VERDICT-RECOMPUTED pr=1 head={h} result=pass"] and mg == []


def test_check_pending_past_the_bound_does_not_merge(origin, capsys):
    h = origin.heads[1]
    runs = lambda head, i: [vrun(head, 901, "in_progress")]  # noqa: E731
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [], verdict_runs=runs)
    assert r.run("true") == 1
    out = capsys.readouterr().out
    assert merges == [] and sum(clock.sleeps) == m.VERDICT_WAIT_S
    assert "gave_up=true" in out and "review-verdict check at H is pending after the bounded wait" in out


def test_no_verdict_run_at_head_waits_a_grace_then_does_not_merge(origin, capsys):
    h = origin.heads[1]
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [], verdict_runs=lambda head, i: [])
    assert r.run("true") == 1
    out = capsys.readouterr().out
    assert merges == [] and sum(clock.sleeps) == m.VERDICT_NONE_GRACE_S
    assert "review-verdict check at H is none after the bounded wait" in out


@pytest.mark.parametrize("bad", [{"path": ".github/workflows/ci.yml"}, {"event": "pull_request"},
                                 {"head_sha": "0" * 40}, {"id": "901"}])
def test_runs_of_other_workflows_events_or_heads_do_not_count(origin, capsys, bad):
    h = origin.heads[1]
    runs = lambda head, i: [{**vrun(head, 901), **bad}]  # noqa: E731
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [], verdict_runs=runs)
    assert r.run("true") == 1
    assert merges == [] and "is none after the bounded wait" in capsys.readouterr().out


def test_wait_budget_bounds_the_whole_run(origin, capsys):
    hs = origin.heads
    prs = [pr_obj(i, hs[i]) for i in range(1, min(len(hs), 7))]
    runs = lambda head, i: [vrun(head, 901, "queued")]  # noqa: E731
    r, merges, clock = race_runner(origin, prs, [], verdict_runs=runs)
    assert r.run("true") == 1
    assert merges == [] and sum(clock.sleeps) <= m.RUN_DEADLINE_S
    capsys.readouterr()


def test_kill_label_added_before_the_retry_blocks_it(origin, capsys):
    h = origin.heads[1]
    runs = lambda head, i: [vrun(head, 900 + i)]  # noqa: E731
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [(False, POLICY_MSG)], verdict_runs=runs)
    reads = {"n": 0}
    orig = r.gh.paged

    def paged(path, key=None, limit=100):
        if path == f"repos/{REPO}/issues/1/labels":
            reads["n"] += 1
            if reads["n"] > 1:
                return [{"name": "auto-merge"}, {"name": "do-not-auto-merge"}]
        return orig(path, key=key, limit=limit)
    r.gh.paged = paged
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert len(merges) == 1 and "MERGE-RETRY" in out
    assert '"do-not-auto-merge" label present (re-read before merge)' in out


def test_unreadable_check_state_fails_closed(origin, capsys):
    h = origin.heads[1]

    def runs(head, i):
        raise V.VerdictError("GET repos/x/actions/workflows/verdict.yml/runs failed: HTTP 403")
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [], verdict_runs=runs)
    assert r.run("true") == 1
    out = capsys.readouterr().out
    assert merges == [] and "outcome=error reason=cannot read the review-verdict check (fail closed)" in out


def test_merge_workflow_can_read_actions_runs(wf):
    # step 7 reads verdict.yml runs through the Actions API: needs actions: read, nothing more
    assert wf["jobs"]["auto-merge"]["permissions"]["actions"] == "read"


def test_no_wait_means_no_reverification(origin, capsys):
    h = origin.heads[1]
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [(True, "")])
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert clock.sleeps == [] and "RE-VERIFY" not in out and out.count("VERDICT-RECOMPUTED") == 1


def test_critical_posted_during_the_wait_stops_the_merge(origin, capsys):
    """fp17 challenger I1(a): the verdict is recomputed after the wait, not reused."""
    h = origin.heads[1]
    results = iter([True, False])  # pass before the wait; a CRITICAL record lands during it

    def fetch_and_compute(gh, repo, n, cfg):
        ok = next(results)
        return V.Result(passed=ok, head_sha=h, weight="standard", reasons=[] if ok else ["critical finding open"])
    v = SimpleNamespace(fetch_and_compute=fetch_and_compute, Result=V.Result, matches_any=V.matches_any,
                        VerdictError=V.VerdictError)
    runs = lambda head, i: [vrun(head, 901, "in_progress" if i < 2 else "completed")]  # noqa: E731
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [], verdict_runs=runs, verdict=v)
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert merges == []
    v_lines, mg = contract_lines(out, 1, h)
    assert v_lines == [f"VERDICT-RECOMPUTED pr=1 head={h} result=pass", f"VERDICT-RECOMPUTED pr=1 head={h} result=fail"]
    assert mg == [] and "VERDICT-DETAIL pr=1 FAIL: critical finding open" in out


def test_7a_change_landing_on_main_during_the_wait_stops_the_run(origin, capsys):
    """fp17 challenger I1(c): the base tip is re-fetched and the definition re-checked after the wait."""
    h = origin.heads[1]
    w = origin.work

    def runs(head, i):
        if i == 0:  # during the wait, main gains a 7a change the run's definition lacks
            (w / "tools" / "check.sh").write_text("echo tightened\n")
            git(w, "commit", "-q", "-am", "7a change during the wait")
            return [vrun(head, 901, "in_progress")]
        return [vrun(head, 901)]
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [], verdict_runs=runs)
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert merges == [] and "STALE-DEFINITION" in out and out.count("7A-DERIVE base=") == 2  # re-derived


def test_no_merge_call_after_the_run_deadline(origin, capsys):
    """AUTO_MERGE_ENABLED cannot be re-read in-run, so the deadline bounds the kill-switch latency."""
    h = origin.heads[1]
    r, merges, clock = race_runner(origin, [pr_obj(1, h)], [(True, "")])
    orig = r.verify

    def slow_verify(n, head, branch):
        clock.t += m.RUN_DEADLINE_S + 1  # the run spent its deadline on earlier work
        return orig(n, head, branch)
    r.verify = slow_verify
    assert r.run("true") == 0
    out = capsys.readouterr().out
    assert merges == [] and f"run deadline {m.RUN_DEADLINE_S}s reached before the merge call" in out


def test_verdict_runs_read_is_one_page_newest_first(origin, capsys):
    """fp17 challenger M3: hundreds of runs at one head never error; one page is read."""
    h = origin.heads[1]
    runs = lambda head, i: [vrun(head, 2000 - k, "completed", "cancelled" if k else "success")  # noqa: E731
                            for k in range(100)]
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [(True, "")], verdict_runs=runs)
    assert r.run("true") == 0 and len(merges) == 1
    assert "CHECK-WAIT pr=1 head=" + h + " state=success run=2000" in capsys.readouterr().out
    assert sum(1 for c in r.gh.calls if VERDICT_RUNS_RE.fullmatch(c)) == 1


def test_malformed_verdict_runs_response_fails_closed(origin, capsys):
    h = origin.heads[1]
    r, merges, _ = race_runner(origin, [pr_obj(1, h)], [])
    orig = r.gh.get
    r.gh.get = lambda path: {"message": "nope"} if VERDICT_RUNS_RE.fullmatch(path) else orig(path)
    assert r.run("true") == 1
    assert merges == [] and "cannot read the review-verdict check (fail closed)" in capsys.readouterr().out
