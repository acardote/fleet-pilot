#!/usr/bin/env python3
"""auto-merge: the E5 merge workflow's logic (acardote/personal-assistant-ultra#580).

Design: acardote/personal-assistant-ultra docs/design/merge-model.md, section 3
(merge workflow) and section 5 (7a path set). Policy row 7 in
docs/policy/autonomy-v2.md (E5 recompute-inline rule).

Per run (.github/workflows/merge.yml calls this from the default branch only):
  1. Log the provenance line.
  2. Kill switch (variable), fail closed: proceed only if AUTO_MERGE_ENABLED is
     exactly "true". Anything else (unset, empty, "True", "false") logs
     KILL SWITCH and exits 0 with no merge.
  3. Candidates: open PRs based on the default branch, labelled `auto-merge`,
     whose head repository is this repository. The triggering event's payload
     is never read: every PR is re-read from the API inside the loop.
  4. Verdict, recomputed INLINE in this run at the PR's current head H, by the
     same function verdict.yml runs (.github/verdict/verdict.py,
     fetch_and_compute) with the same config. No check run, commit status or
     other workflow run's verdict is read. The recomputation is logged as a
     VERDICT-RECOMPUTED line (the #581 audit's marker) plus context lines.
  5. 7a path check, complete and fail closed: fetch the default branch and
     refs/pull/<n>/head (into an empty bare repo; nothing is checked out or
     run), require the fetched head to equal H, then
     `git diff --raw --no-renames <merge-base>..H`. Any changed path (both
     sides of a rename, every deletion) matching the 7a set, or any symlink or
     submodule change, skips the PR. The 7a set is the floor list in
     config.json plus the code derived along execution edges from the default
     branch's roots (derive_7a; precision rules above Deriver). A reference in
     derived code that cannot be bounded fails closed: no PR merges in that run.
     The tip is re-fetched and the set re-derived after every merge; if the tip
     has a 7a change the run's own definition (workflow_sha) lacks, the run
     stops (STALE-DEFINITION) and the next run uses the new definition.
  6. Kill switch (label), re-read immediately before the merge call, with the
     head, base and the `auto-merge` label.
  7. Merge: `gh pr merge <n> --squash --match-head-commit H`. If the call fails
     or times out, the PR is re-read: merged at H by merger_login counts as
     merged (MERGE-CONFIRMED + MERGED); otherwise MERGE-REFUSED. The next
     schedule run recomputes steps 2-6 from scratch.

Log contract with the #581 audit (fleet-pilot#4 .github/audit/audit.py,
MERGED_RE and VERDICT_LOG_RE): exactly these two whole lines, no PR text in them:
  VERDICT-RECOMPUTED pr=<n> head=<H> result=pass|fail
  MERGED pr=<n> head=<H> run_id=<run id> workflow_ref=<GITHUB_WORKFLOW_REF>
`result=pass` means the inline verdict passed AND its head equals H. Context
(verdict head, weight, run id) is on a separate VERDICT-CONTEXT line, reasons on
VERDICT-DETAIL lines. All PR-derived text is escaped by log() (see esc()).

Exit status: 0 = the run completed and nothing systemic went wrong (merged,
verdict FAIL, 7a skip, kill switch, stale definition). 1 = red: provenance or
the 7a set could not be established, or any candidate hit an API/git error or
a refused merge (RUN-RESULT line plus a ::error annotation).

Stdlib only (plus git and gh, preinstalled on the runner).
"""
from __future__ import annotations

import argparse
import ast
import base64
import importlib.util
import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
SHA_RE = re.compile(r"[0-9a-f]{40}")
SYMLINK_MODE = "120000"
SUBMODULE_MODE = "160000"


def load_verdict(name: str = "e5_verdict"):
    """Import .github/verdict/verdict.py by path (sys.modules first: dataclasses needs it)."""
    spec = importlib.util.spec_from_file_location(name, HERE.parent / "verdict" / "verdict.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Log contract with the #581 merge audit (fleet-pilot#4, .github/audit/audit.py
# MERGED_RE / VERDICT_LOG_RE). These two lines are printed WHOLE, by
# log_verdict_recomputed() and log_merged() only, and carry no PR-derived text:
#   VERDICT-RECOMPUTED pr=<n> head=<H> result=pass|fail
#   MERGED pr=<n> head=<H> run_id=<id> workflow_ref=<GITHUB_WORKFLOW_REF>
# Every other line starts with a fixed token of this file (PROVENANCE, CANDIDATE,
# VERDICT-CONTEXT, VERDICT-DETAIL, 7A-DERIVE, 7A-CLEAR, 7A-HIT, SKIP,
# MERGE-REFUSED, MERGE-CONFIRMED, RUN-RESULT, REFUSED, KILL SWITCH, STALE-DEFINITION).
# PR-derived values (file names, labels, API and exception messages, verdict
# reasons) are escaped by log(): no control character, line separator or newline
# survives, so a value can never start a line of its own, forge one of the two
# audit lines, or be read by the runner as a workflow command ("::...").
RESERVED_PREFIXES = ("VERDICT-RECOMPUTED", "MERGED", "::")
_UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\ufeff]")


def esc(s: Any) -> str:
    """One physical line, printable: control characters and line separators become \\xNN / \\uNNNN."""
    return _UNSAFE_RE.sub(lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100
                          else f"\\u{ord(m.group()):04x}", str(s))


def q(s: Any) -> str:
    """A PR-derived value, quoted and escaped (json string form, ASCII only)."""
    return json.dumps(str(s), ensure_ascii=True)


def log(line: str, *, _audit: bool = False) -> None:
    line = esc(line)
    if not _audit and line.lstrip().startswith(RESERVED_PREFIXES):
        line = "LOG " + line  # never reached by this file's own lines; defence in depth
    print(line, flush=True)


def log_verdict_recomputed(n: int, head: str, passed: bool) -> None:
    if not (isinstance(n, int) and SHA_RE.fullmatch(head)):
        raise ValueError("VERDICT-RECOMPUTED: malformed pr or head")
    log(f"VERDICT-RECOMPUTED pr={n} head={head} result={'pass' if passed else 'fail'}", _audit=True)


def log_merged(n: int, head: str, ctx: "Ctx") -> None:
    if not (isinstance(n, int) and SHA_RE.fullmatch(head) and ctx.run_id.isdigit()
            and re.fullmatch(r"\S+", ctx.workflow_ref)):
        raise ValueError("MERGED: malformed pr, head, run_id or workflow_ref")
    log(f"MERGED pr={n} head={head} run_id={ctx.run_id} workflow_ref={ctx.workflow_ref}", _audit=True)


@dataclass
class Ctx:
    repo: str
    run_id: str
    workflow_ref: str
    workflow_sha: str
    event: str

    def tag(self) -> str:
        return f"run_id={self.run_id} workflow_ref={self.workflow_ref}"


def kill_switch_allows(value: str | None) -> bool:
    """Fail closed: only the exact string "true" enables merging."""
    return value == "true"


def expected_workflow_ref(repo: str, branch: str) -> str:
    return f"{repo}/.github/workflows/merge.yml@refs/heads/{branch}"


# --------------------------------------------------------------------------
# git (read-only, in a private bare repo)
# --------------------------------------------------------------------------

class GitError(Exception):
    pass


class DeriveError(Exception):
    """The 7a set could not be established: no PR may merge in this run."""


@dataclass
class Change:
    old_mode: str
    new_mode: str
    status: str
    path: str


class Git:
    """Fetches objects into an empty bare repository. Never checks out or runs
    fetched content. The token reaches git via GIT_CONFIG_* environment
    variables, never the command line."""

    def __init__(self, url: str, token: str | None = None, workdir: str | None = None,
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run):
        self.url = url
        self.run = run
        self.dir = workdir or tempfile.mkdtemp(prefix="auto-merge-")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        cfg = [("core.hooksPath", os.devnull)]
        if not url.startswith("https://"):
            cfg.append(("protocol.file.allow", "always"))  # local test remotes only
        if token and url.startswith("https://"):
            basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            if os.environ.get("GITHUB_ACTIONS") == "true":
                # The runner masks the token, not its base64 form: register that too.
                print(f"::add-mask::{basic}", flush=True)
            cfg.append(("http.extraheader", f"AUTHORIZATION: basic {basic}"))
        env["GIT_CONFIG_COUNT"] = str(len(cfg))
        for i, (k, v) in enumerate(cfg):
            env[f"GIT_CONFIG_KEY_{i}"] = k
            env[f"GIT_CONFIG_VALUE_{i}"] = v
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_DIR"] = self.dir
        self.env = env
        self._git("init", "-q", "--bare", self.dir)

    def _git(self, *args: str) -> bytes:
        try:
            p = self.run(["git", *args], env=self.env, capture_output=True, timeout=300)
        except Exception as e:  # noqa: BLE001 - any failure is a skip
            raise GitError(f"git {args[0]}: {type(e).__name__}: {e}") from e
        if p.returncode != 0:
            err = p.stderr.decode("utf-8", "replace").strip().splitlines()
            raise GitError(f"git {args[0]} exit {p.returncode}: {err[-1] if err else ''}")
        return p.stdout

    def fetch(self, src: str, dst: str) -> str:
        self._git("fetch", "--no-tags", "--quiet", self.url, f"+{src}:{dst}")
        return self.rev_parse(dst)

    def rev_parse(self, ref: str) -> str:
        sha = self._git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").decode().strip()
        if not SHA_RE.fullmatch(sha):
            raise GitError(f"rev-parse {ref}: {sha!r}")
        return sha

    def merge_base(self, a: str, b: str) -> str:
        sha = self._git("merge-base", a, b).decode().strip()
        if not SHA_RE.fullmatch(sha):
            raise GitError(f"merge-base: {sha!r}")
        return sha

    def diff(self, a: str, b: str) -> list[Change]:
        out = self._git("diff", "--raw", "-z", "--no-renames", "--no-ext-diff", "--no-textconv",
                        "--full-index", a, b)
        return parse_raw_diff(out)

    def tree(self, commit: str) -> dict[str, str]:
        """path -> mode for every entry (recursive) at `commit`."""
        out = self._git("ls-tree", "-r", "-z", "--full-tree", commit)
        entries: dict[str, str] = {}
        for rec in out.split(b"\0"):
            if not rec:
                continue
            meta, _, path = rec.partition(b"\t")
            parts = meta.split()
            if len(parts) != 3 or not path:
                raise GitError("ls-tree: malformed entry")
            entries[path.decode("utf-8", "surrogateescape")] = parts[0].decode()
        return entries

    def show(self, commit: str, path: str) -> bytes:
        return self._git("cat-file", "blob", f"{commit}:{path}")


def parse_raw_diff(out: bytes) -> list[Change]:
    """Parse `git diff --raw -z --no-renames`: ':om nm os ns S\\0path\\0' records."""
    toks = out.split(b"\0")
    if toks and toks[-1] == b"":
        toks.pop()
    if len(toks) % 2:
        raise GitError("diff: malformed raw output")
    changes = []
    for i in range(0, len(toks), 2):
        meta = toks[i].decode()
        parts = meta.split()
        if len(parts) != 5 or not parts[0].startswith(":") or parts[4][:1] in ("R", "C"):
            raise GitError(f"diff: unexpected record {meta!r}")
        changes.append(Change(parts[0][1:], parts[1], parts[4], toks[i + 1].decode("utf-8", "surrogateescape")))
    return changes


# --------------------------------------------------------------------------
# 7a path set: floor + transitive derivation (merge-model.md section 5)
# --------------------------------------------------------------------------
#
# What is derived: the code that runs automatically, followed from derive_roots
# along EXECUTION edges only (review of fleet-pilot#3, challenger I3, wario I-1):
# - an interpreter or `source` argument (`bash x`, `python3 x`, `. x`), a command
#   word that is a path (`./x`, `tools/x.sh`, `"$CLAUDE_PROJECT_DIR"/x`), or any
#   path-like token ending in a script extension (.sh .py .js ...);
# - a Python import, a dynamic loader with a literal or path-joined target, a
#   path-joined or literal script path in Python;
# - a local action (`uses: ./x`), a symlink's target, a Markdown `@path` import;
# - the command a shell command position runs, read structurally (fleet-pilot#3
#   verify N1/N2): through assignments (`FOO=1 x`), keywords (`if`, `!`, `then`),
#   `$(...)`, backticks, `<(...)`, pipes, `find -exec`, `cd D && ./x` and a step's
#   working-directory, and wrappers (timeout, xargs, env, nice, nohup, sudo, exec,
#   command, time, stdbuf, setsid, ionice, flock, watch, eval, uv/poetry run, ...)
#   with their options and fixed arguments skipped; an option a wrapper table
#   does not know is read both ways (flag, or option + argument);
# - `python -m a.b`: a/b.py, a/b/__init__.py, a/b/__main__.py, a/__init__.py,
#   all 7a whether present or not (a PR that creates one shadows the module);
#   `python -c CODE` and a python here-document are read as Python;
# - `make`: the makefile it reads (and its includes) is derived and its recipes
#   read as shell; `just`: the justfile; npm/pnpm/yarn/bun: package.json, whose
#   scripts are read as shell (lifecycle hooks run on install). Makefiles,
#   justfiles, Taskfiles, Dockerfiles and compose files are also on the floor;
# - subprocess/os.system/os.exec*/os.spawn*/os.posix_spawn*/pty.spawn/
#   runpy.run_path targets in Python, evaluated statically (literals, __file__
#   with .parent/.parents[N]/.joinpath/Path(...)/os.path.join/dirname/abspath/
#   realpath, +, f-strings, names assigned in the file). The call is found by its
#   name or through an alias (`import subprocess as sp`, `from subprocess import
#   run as r`, `sp = subprocess`, `r = sp.run`, `getattr(subprocess, "run")`),
#   and `functools.partial(subprocess.run, [...])` is read as the call. A target
#   that is not static, `getattr(<os|subprocess|pty...>, <non-literal>)`, a
#   bound-nothing partial, and an exec function used as a value (passed, stored)
#   are bounded by what the file names: every static string or path value in it
#   naming an existing tree file (a bare name: a file beside it) becomes an
#   edge; if it names none, the run fails closed;
# - every existing candidate of a relative reference (root and the referring
#   file's directories), not only the first hit; and any token naming an
#   executable-bit (100755) file in the tree.
# Residual, measured (fleet-pilot#3 round 3): in that bound the file's own path
# counts as a tree file it names (it does whenever the file writes its own name
# or uses Path(__file__) in an expression), so for such a file the fallback adds
# nothing and does not fail closed. Excluding it was tried: on PAU main two
# derived files (tools/registry.py runs `gh_bin()`, tools/agent-gh runs a
# `git_bin` parameter) name nothing else, and every run went red. Call shapes not
# listed above (exec/eval of a built string, getattr on a module bound through
# importlib) are also not seen. Both are accepted because exploiting them needs that
# call to sit already in a derived file, every derived file is itself 7a, and
# adding the call required an operator merge.
# Residual, by design: a test runner's arguments (`pytest tests/`) are not edges,
# so tests/** is not 7a unless named on the floor. Taskfile recipes are not
# derived (a `task` invocation fails closed). JavaScript in a github-script
# `script:` is scanned for edges, but its syntax is not shell, so the structural
# pass reports nothing from it.
# Mentions are not edges: a bare word (`tests`, `name: docs`), a data path, a
# directory argument to a test runner, a `paths:` filter. They used to swallow
# whole directories (docs/**, kb/**, tools/**) and made nothing auto-mergeable.
# Each file kind is read only where it names things that run: YAML run/entry/
# command/script values and `uses:`; JSON keys ending in "command" plus run/
# script/args/program/entry; Markdown `@path` imports; Python via its AST;
# anything else as shell.
# Shell variables assigned literally in the same file (`LINT="$SCRIPT_DIR/x.py"`,
# `dir="${0%/*}"`) are substituted, every assigned value tried.
# A literal script reference that does not resolve (an optional hook, a file not
# created yet) is still added to the 7a set, so a PR that creates it is 7a; a
# glob in an execution position (`bash scripts/*.sh`) is added as a pattern.
# Fail closed: a reference that still cannot be bounded (an interpreter argument
# built from an unknown variable, a loader with no literal target in a module
# that names no script literally, unparsable Python, a symlink out of the repo)
# is "unresolved", and no PR merges in that run. Only derived files are scanned,
# so an unresolved reference is always in code that runs automatically.

TOKEN_RE = re.compile(r"[A-Za-z0-9_.\-/${}()\[\]\"'@~*?]+")
KNOWN_PREFIXES = re.compile(
    r"""^(?:\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?|\$\{?CLAUDE_PROJECT_DIR\}?|"""
    r"""\$\(git rev-parse --show-toplevel\))/""")
SELFDIR_RE = re.compile(
    r"""\$\(\s*dirname\s+["']?\$(?:0|\{0\}|\{BASH_SOURCE\[0\]\}|\{BASH_SOURCE\}|BASH_SOURCE)["']?\s*\)"""
    r"""|\$\{(?:0|BASH_SOURCE(?:\[0\])?)%/\*\}""")
CD_PWD_RE = re.compile(r"""\$\(\s*cd\s+["']?([^"'\s)]+)["']?\s*(?:&&|;)\s*pwd(?:\s+-P)?\s*\)""")
ACTION_PATH_RE = re.compile(r"""\$\{\{\s*github\.action_path\s*\}\}|\$\{?GITHUB_ACTION_PATH\}?""")
SELFDIR = "__SELFDIR__"
SHELL_LOAD_RE = re.compile(r"""(?:^|[;&|(]|\bthen\b|\bdo\b)[ \t]*(?:source|\.)[ \t]+(\S+)""", re.MULTILINE)
SHELL_EXEC_RE = re.compile(
    r"""(?:^|[ \t;&|(])(?:bash|sh|zsh|python3?|node|ruby|perl|uv[ \t]+run|exec)[ \t]+((?:-\S+[ \t]+)*)([^\s;&|)]+)""",
    re.MULTILINE)
CMD_POS_RE = re.compile(
    r"""(?:^|[;&|]|\bthen\b|\bdo\b)[ \t]*(?:sudo[ \t]+|env[ \t]+(?:[A-Za-z_]+=\S*[ \t]+)*)?([^\s;&|()]+)""",
    re.MULTILINE)
ASSIGN_RE = re.compile(
    r"""(?:^|[ \t;)(])(?:export[ \t]+|local[ \t]+|readonly[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)="""
    r"""("[^"\n]*"|'[^'\n]*'|\$\([^()\n]*\)|[^\s;]+)""",
    re.MULTILINE)
SHELL_COMMENT_RE = re.compile(r"""(?:^|(?<=[ \t]))#.*$""", re.MULTILINE)
VAR_RE = re.compile(r"""\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))""")
POSITIONAL_RE = re.compile(r"""^\$(?:@|\*|[0-9]|\{[0-9@*]\})$""")
QUOTED_VAR = re.compile(r"""["'](\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)["']""")
PATH_CHARS = re.compile(r"[A-Za-z0-9_.\-/]+")
GLOB_CHARS = re.compile(r"[A-Za-z0-9_.\-/*?]+")
EXT_RE = re.compile(r"\.[A-Za-z0-9]{1,10}$")
SCRIPT_EXTS = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl")
YAML_KEY_RE = re.compile(r"""^(\s*)(?:-\s+)?["']?([A-Za-z0-9_-]+)["']?\s*:(?:\s(.*))?$""")
YAML_CMD_KEYS = {"run", "entry", "command", "script"}
JSON_CMD_KEYS = {"run", "script", "args", "program", "entry"}
MD_IMPORT_RE = re.compile(r"""(?:^|\s)@([A-Za-z0-9_.\-/]+)""")
DYNAMIC_CALLS = {"import_module", "__import__", "run_path", "run_module", "spec_from_file_location",
                 "SourceFileLoader", "load_source"}
MAX_EXPANSIONS = 16
PY_M_OPT_RE = re.compile(r"(?:^|\s)-[A-Za-z]*m\s+$")


def _clean(tok: str) -> str:
    return tok.strip("\"'()[]{}@,;:")


def _normjoin(base: str, rel: str) -> str | None:
    p = posixpath.normpath(posixpath.join(base, rel)) if base else posixpath.normpath(rel)
    if p.startswith("../") or p == ".." or p.startswith("/"):
        return None
    return "" if p == "." else p


def path_like(tok: str) -> bool:
    """A token that can name a file: contains "/" or ends in an extension, and is not a URL or option."""
    if not tok or tok.startswith("-") or "://" in tok or tok.startswith(("http:", "https:")):
        return False
    return "/" in tok or bool(EXT_RE.search(tok))


def is_script(tok: str) -> bool:
    return tok.lower().endswith(SCRIPT_EXTS)


# --- Shell command positions --------------------------------------------
# A second, structural pass over shell text: split it into simple commands,
# drop assignments, keywords and redirections, look through wrapper commands
# (timeout, xargs, env, sudo, ...) to the command they run, and follow what
# that command executes: a path, `python -m mod`, `make`, an npm-family run.
# The regex passes above stay; this pass only adds edges. Rule: when a
# wrapper option is not known, both readings (flag, or option with an
# argument) are followed, so an unknown option can over-include, never drop.

def _wrapper(arg: str = "", flags: str = "", larg: str = "", lflags: str = "", pos: int = 0,
             attached: str = "", assigns: bool = False, cmdstr: str = "", numeric: bool = False,
             joined: bool = False, nocmd: bool = False) -> dict:
    return {"arg": set(arg.split()), "flags": set(flags.split()), "larg": set(larg.split()),
            "lflags": set(lflags.split()), "pos": pos, "attached": set(attached.split()),
            "assigns": assigns, "cmdstr": set(cmdstr.split()), "numeric": numeric, "joined": joined,
            "nocmd": nocmd}


WRAPPERS: dict[str, dict] = {
    "timeout": _wrapper("-s -k", "-v", "--signal --kill-after", "--foreground --preserve-status --verbose", pos=1),
    "xargs": _wrapper("-n -L -P -s -d -E -I -a", "-0 -r -t -p -x -o", "--max-args --max-lines --max-procs "
                      "--max-chars --delimiter --eof --replace --arg-file --process-slot-var",
                      "--null --no-run-if-empty --verbose --interactive --exit --open-tty", attached="-e -i -l"),
    "env": _wrapper("-u -C -S", "-i -0 -v -", "--unset --chdir --split-string",
                    "--ignore-environment --null --debug", assigns=True, cmdstr="-S --split-string"),
    "nice": _wrapper("-n", "", "--adjustment", "", numeric=True),
    "nohup": _wrapper(),
    "sudo": _wrapper("-u -g -h -C -D -p -r -t -U -T -R", "-A -b -E -H -i -k -K -l -n -P -S -s -v -V -B -N",
                     "--user --group --host --close-from --chdir --prompt --role --type --other-user "
                     "--command-timeout --chroot", "--preserve-env --login --non-interactive --shell --stdin "
                     "--askpass --background --set-home --reset-timestamp --remove-timestamp", assigns=True),
    "doas": _wrapper("-u -C", "-n -s -L"),
    "exec": _wrapper("-a", "-c -l"),
    "command": _wrapper("", "-p -v -V"),
    "builtin": _wrapper(),
    "time": _wrapper("-f -o", "-p -a -v -q", "--format --output", "--portability --append --verbose --quiet"),
    "stdbuf": _wrapper("-i -o -e", "", "--input --output --error"),
    "setsid": _wrapper("", "-c -f -w", "", "--ctty --fork --wait"),
    "ionice": _wrapper("-c -n -p -P -u", "-t", "--class --classdata --pid --pgid --uid", "--ignore"),
    "flock": _wrapper("-w -E", "-s -x -e -u -n -o -F", "--timeout --conflict-exit-code",
                      "--shared --exclusive --unlock --nonblock --close --no-fork --verbose", pos=1,
                      cmdstr="-c --command"),
    "watch": _wrapper("-n -q", "-b -c -C -d -e -g -p -r -t -w -x", "--interval --equexit",
                      "--beep --color --no-color --differences --errexit --chgexit --precise --no-rerun "
                      "--no-title --no-wrap --exec", joined=True),
    "chrt": _wrapper("-T -P -D", "-a -b -d -e -f -i -m -o -p -r -R -v", pos=1),
    "taskset": _wrapper("", "-a -p -c", "", "--all-tasks --pid --cpu-list", pos=1),
    "unbuffer": _wrapper("", "-p"),
    "caffeinate": _wrapper("-t -w", "-d -i -m -s -u"),
    "strace": _wrapper("-o -e -p -s -u -E -P -a -b -I -O -S -X", "-f -F -c -C -d -D -h -i -k -n -q -r -t -T -v "
                       "-V -w -x -y -z -Z"),
    "valgrind": _wrapper("", "-q -v -s"),
    "xvfb-run": _wrapper("-e -f -n -p -s -w", "-a -l", "--error-file --auth-file --server-num --xauth-protocol "
                         "--server-args --wait", "--listen-tcp"),
    "dbus-run-session": _wrapper(),
    "su": _wrapper("-s -g -G -w", "-l -m -p -P -f -", "--shell --group --supp-group --whitelist-environment",
                   "--login --preserve-environment --pty --fast", cmdstr="-c --command", nocmd=True),
    "runuser": _wrapper("-u -s -g -G -w", "-l -m -p -P -f -", "--user --shell --group --supp-group",
                        "--login --preserve-environment --pty --fast", cmdstr="-c --command"),
    "eval": _wrapper(joined=True),
    "npx": _wrapper("-p --package", "-y -q", "--package --call", "--yes --no --quiet", cmdstr="-c --call"),
}
# Wrappers spelled as two words: the second word is the subcommand.
SUBCMD_WRAPPERS: dict[tuple[str, str], dict] = {
    ("uv", "run"): _wrapper("-p", "-q -v", "--with --with-requirements --with-editable --python --project "
                            "--directory --package --extra --group --only-group --no-group --env-file --index "
                            "--default-index --index-url --extra-index-url --find-links --config-file "
                            "--cache-dir --python-preference", "--quiet --verbose --frozen --locked --no-sync "
                            "--isolated --no-project --script --all-extras --no-dev --active --no-env-file "
                            "--no-config --offline --exact --refresh --no-cache"),
    ("uvx", ""): _wrapper("-p", "-q -v", "--from --with --python --index --index-url", "--quiet --verbose "
                          "--isolated --offline --refresh --no-cache"),
    ("poetry", "run"): _wrapper("-C -P", "-q -v -n", "--directory --project", "--quiet --verbose --no-interaction"),
    ("pipenv", "run"): _wrapper(),
    ("pdm", "run"): _wrapper("-p", "-g -v -q", "--project", "--global --verbose --quiet"),
    ("hatch", "run"): _wrapper(),
    ("rye", "run"): _wrapper(),
    ("pixi", "run"): _wrapper("-e", "", "--environment --manifest-path"),
    ("conda", "run"): _wrapper("-n -p", "-v", "--name --prefix --cwd", "--no-capture-output --live-stream"),
    ("mamba", "run"): _wrapper("-n -p", "-v", "--name --prefix --cwd", "--no-capture-output --live-stream"),
    ("micromamba", "run"): _wrapper("-n -p", "-v", "--name --prefix --cwd", ""),
    ("bundle", "exec"): _wrapper("", "", "--gemfile", "--keep-file-descriptors"),
    ("pnpm", "exec"): _wrapper("-C", "-r -c", "--dir --filter", "--recursive --shell-mode"),
    ("npm", "exec"): _wrapper("-c -w", "-y", "--package --call --workspace", "--yes --no"),
    ("yarn", "exec"): _wrapper(),
}
SHELL_KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}"}
NON_EXEC_HEADS = {"for", "case", "esac", "select", "function", "in", "[", "[[", "]]", "test", "export",
                  "local", "readonly", "declare", "typeset", "unset", "echo", "printf", "return", "exit"}
ASSIGN_WORD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
REDIR_RE = re.compile(r"^[0-9]*(?:&>>?|>>?\|?|<<<|<<-?|<>|>&|<&|<)(.*)$")
HEREDOC_RE = re.compile(r"""(?<!<)<<(-?)[ \t]*(["']?)([A-Za-z_][A-Za-z0-9_]*)\2""")
SHELL_OPS = ("&&", "||", ";;", "|&", ";", "&", "|", "\n", "(", ")")
PY_INTERP_RE = re.compile(r"^(?:python(?:[0-9]+(?:\.[0-9]+)*)?|pypy[0-9.]*)$")
SH_INTERP = {"bash", "sh", "zsh", "dash", "ksh", "mksh", "ash"}
# Other interpreters: (options taking an argument, options whose argument is
# inline code, options whose argument is a file or module that is loaded).
OTHER_INTERP: dict[str, tuple[set[str], set[str], set[str]]] = {
    "node": ({"-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions",
              "--env-file", "--input-type", "--title"}, {"-e", "--eval", "-p", "--print"},
             {"-r", "--require", "--import", "--loader", "--experimental-loader"}),
    "bun": ({"-r", "--preload"}, {"-e", "--eval", "-p", "--print"}, {"-r", "--preload"}),
    "deno": (set(), set(), set()),
    "tsx": (set(), {"-e", "--eval"}, set()),
    "ts-node": ({"-r", "--require"}, {"-e", "--eval", "-p", "--print"}, {"-r", "--require"}),
    "ruby": ({"-r", "-I", "-C", "-F", "-K", "-T", "-W", "-x"}, {"-e"}, {"-r"}),
    "perl": ({"-I", "-M", "-m", "-x", "-C", "-d", "-D", "-l", "-0"}, {"-e", "-E"}, set()),
    "Rscript": (set(), {"-e"}, set()),
    "lua": ({"-l"}, {"-e"}, {"-l"}),
}
PY_FLAGS = set("bBdEhiIOPqRsSuvVx?")
MAKE_PROGS = {"make", "gmake", "bmake"}
MAKEFILES = ("GNUmakefile", "makefile", "Makefile")
MAKE_ARG = {"-f", "--file", "--makefile", "-C", "--directory", "-I", "--include-dir", "-o", "--old-file",
            "--assume-old", "-W", "--what-if", "--new-file", "--assume-new"}
MAKE_ATTACHED = set("jlO")
NPM_PROGS = {"npm", "pnpm", "yarn", "bun", "corepack"}
NPM_DIR_OPTS = {"--prefix", "-C", "--dir", "--cwd"}
MAKE_INCLUDE_RE = re.compile(r"^[ \t]*-?s?include[ \t]+(.+)$", re.MULTILINE)
MODULE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
SUBPROC_SHELL_CALLS = {"system", "popen", "getoutput", "getstatusoutput", "create_subprocess_shell"}
SUBPROC_ARGV_CALLS = {"run", "call", "check_call", "check_output", "Popen", "create_subprocess_exec",
                      "spawn"}  # pty.spawn(argv), pexpect.spawn(cmd)
SUBPROC_PATH_CALLS = {"execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
                      "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe",
                      "posix_spawn", "posix_spawnp", "startfile"}
EXEC_CALLS = SUBPROC_SHELL_CALLS | SUBPROC_ARGV_CALLS | SUBPROC_PATH_CALLS
EXEC_MODULES = {"subprocess", "os", "posix", "nt", "pty", "asyncio", "commands"}
EXEC_MODE = "100755"
TOPLEVEL_RE = re.compile(r"\$\(\s*git\s+rev-parse\s+--show-toplevel\s*\)")
DYN_PATH_RE = re.compile(r"[A-Za-z0-9_.\-/${}]+")
MAX_CMD_DEPTH = 8


def _extract_substitutions(text: str) -> tuple[str, list[str]]:
    """Pull $(...), <(...), >(...) and `...` out of shell text; each body is a script of its own."""
    out: list[str] = []
    inner: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith(("$(", "<(", ">("), i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                j += 1
            inner.append(text[i + 2:j - 1] if not depth else text[i + 2:])
            out.append("__SUBST__")
            i = j
            continue
        if text[i] == "`":
            j = text.find("`", i + 1)
            if j > i:
                inner.append(text[i + 1:j])
                out.append("__SUBST__")
                i = j + 1
                continue
        out.append(text[i])
        i += 1
    return "".join(out), inner


def _lex(text: str) -> list[list[str]] | None:
    """Split shell text into simple commands (lists of words, quotes removed).
    None if a quote is left open."""
    segs: list[list[str]] = [[]]
    cur: list[str] = []
    inword = False
    q = ""
    i, n = 0, len(text)

    def flush() -> None:
        nonlocal cur, inword
        if inword:
            segs[-1].append("".join(cur))
        cur, inword = [], False

    while i < n:
        c = text[i]
        if q == "'":
            if c == "'":
                q = ""
            else:
                cur.append(c)
            i += 1
            continue
        if q == '"':
            if c == '"':
                q = ""
            elif c == "\\" and i + 1 < n:
                cur.append(text[i + 1])
                i += 1
            else:
                cur.append(c)
            i += 1
            continue
        if c in "'\"":
            q, inword = c, True
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            if text[i + 1] != "\n":
                cur.append(text[i + 1])
                inword = True
            i += 2
            continue
        if c == "#" and not inword:
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        op = next((o for o in SHELL_OPS if text.startswith(o, i)), None)
        if op:
            flush()
            if segs[-1]:
                segs.append([])
            i += len(op)
            continue
        if c in " \t\r":
            flush()
            i += 1
            continue
        cur.append(c)
        inword = True
        i += 1
    flush()
    if q:
        return None
    return [s for s in segs if s]


def _lex_lenient(text: str) -> list[list[str]]:
    segs = _lex(text)
    if segs is not None:
        return segs
    out: list[list[str]] = []  # an open quote: read line by line, closing quotes at line end
    for line in text.split("\n"):
        r = _lex(line) or _lex(line + "'") or _lex(line + '"') or [line.split()]
        out.extend(s for s in r if s)
    return out


NONLITERAL = "$NONLITERAL/arg"


def _pdir(p: str) -> str:
    d = posixpath.dirname(posixpath.normpath(p))
    return d or "."


def _dedent(text: str) -> str:
    lines = text.split("\n")
    ind = min((len(ln) - len(ln.lstrip()) for ln in lines if ln.strip()), default=0)
    return "\n".join(ln[ind:] for ln in lines)


def _strip_comments(text: str) -> str:
    """Remove shell comments: `#` at the start of a word, outside quotes, to the end of the line."""
    out: list[str] = []
    q = ""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if q:
            if c == q:
                q = ""
            elif c == "\\" and q == '"' and i + 1 < n:
                out.append(c)
                i += 1
                c = text[i]
            out.append(c)
            i += 1
            continue
        if c in "'\"":
            q = c
        elif c == "\\" and i + 1 < n:
            out.append(c)
            i += 1
            c = text[i]
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;&|("):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _split_heredocs(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Remove here-document bodies; return the rest and (introducing line, body) pairs.
    A body whose terminator is never found is left in place (read as commands)."""
    lines = text.split("\n")
    out: list[str] = []
    bodies: list[tuple[str, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for hm in HEREDOC_RE.finditer(_strip_comments(line)):
            delim = hm.group(3)
            j = i
            while j < len(lines) and lines[j].strip() != delim:
                j += 1
            if j >= len(lines):
                break  # no terminator: keep the lines as commands
            bodies.append((line, "\n".join(lines[i:j])))
            i = j + 1
    return "\n".join(out), bodies


class Deriver:
    def __init__(self, tree: dict[str, str], read: Callable[[str], bytes], matches: Callable[[str, list[str]], bool],
                 config: dict):
        self.tree = tree
        self.read = read
        self.matches = matches
        self.config = config
        self.dirs: set[str] = set()
        for p in tree:
            parts = p.split("/")
            for i in range(1, len(parts)):
                self.dirs.add("/".join(parts[:i]))
        self.files: set[str] = set()      # derived literal files
        self.dir_globs: set[str] = set()  # derived directories, as "<dir>/**"
        self.missing: set[str] = set()    # literal script references with no tree entry (yet)
        self.globs: set[str] = set()      # globs in an execution position
        self.unresolved: list[str] = []
        self.queue: list[str] = []
        self.cur = ""                     # file being scanned
        self._cwd = ""                    # directory of the last literal `cd` in the shell text being scanned
        self._js = False                  # scanning a github-script `script:` (JavaScript)
        self._pyenv: dict[str, list[ast.AST]] = {}  # simple assignments in the Python file being scanned
        self.cur_py = ""                  # the Python file whose __file__ that is
        self._pytree: ast.AST | None = None
        self._pyouter: ast.AST | None = None
        self._py_unbounded_done: set[str] = set()
        self._pyalias: dict[str, str] = {}  # local name -> the exec function it is bound to
        self._pymods: set[str] = set()      # local names bound to an EXEC_MODULES module

    # -- adding --------------------------------------------------------
    def add(self, path: str) -> bool:
        if path in self.tree:
            if path not in self.files:
                self.files.add(path)
                self.queue.append(path)
            return True
        if path in self.dirs:
            g = f"{path}/**"
            if g not in self.dir_globs:
                self.dir_globs.add(g)
                pre = path + "/"
                for p in self.tree:
                    if p.startswith(pre):
                        self.add(p)
            return True
        return False

    def report(self, msg: str) -> None:
        self.unresolved.append(f"{self.cur}: {msg}")

    @staticmethod
    def _candidates(rel: str, src: str) -> list[str]:
        """rel against the repo root, then src's directory and its ancestors."""
        d = posixpath.dirname(src)
        bases = [""]
        while d:
            bases.append(d)
            d = posixpath.dirname(d)
        out = []
        for b in bases:
            p = _normjoin(b, rel)
            if p and p not in out:
                out.append(p)
        return out

    def ref(self, tok: str, src: str, *, execd: bool = False) -> bool:
        """Follow one literal reference if it is an execution edge. Returns True if bounded."""
        rel = KNOWN_PREFIXES.sub("", tok)
        absolute = rel == tok and tok.startswith(("/", "~"))
        if rel.startswith("./"):
            rel = rel[2:]
        rel = rel.lstrip("/")  # "/tools/x" read as repo-relative: over-matching only costs availability
        if not rel or "$" in rel or rel.startswith("~"):
            return False
        if not (execd or is_script(rel)):
            return False  # a mention, not an execution edge
        if any(c in rel for c in "*?["):
            if execd and not absolute and GLOB_CHARS.fullmatch(rel):
                self.globs.add(self._candidates(rel, src)[0])
                return True
            return False
        cands = self._candidates(rel, src)
        hits = [p for p in cands if self.add(p)]  # every existing candidate, not the first hit
        if hits:
            return True
        if not absolute and PATH_CHARS.fullmatch(rel):
            # Fail closed on availability: a PR that creates this file is 7a.
            self.missing.update(cands[:2])
            return True
        return False

    # -- shell ---------------------------------------------------------
    def _assignments(self, text: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for mm in ASSIGN_RE.finditer(text):
            v = mm.group(2)
            if v[:1] in "\"'" and v[-1:] == v[:1] and len(v) > 1:
                v = v[1:-1]
            cd = CD_PWD_RE.fullmatch(v)
            if cd:
                v = cd.group(1)
            out.setdefault(mm.group(1), [])
            if v not in out[mm.group(1)]:
                out[mm.group(1)].append(v)
        return out

    @staticmethod
    def _expand(s: str, env: dict[str, list[str]], depth: int = 0) -> list[str]:
        mm = next((x for x in VAR_RE.finditer(s) if (x.group(1) or x.group(2)) in env), None)
        if not mm or depth > 4:
            return [s]
        out: list[str] = []
        for v in env[mm.group(1) or mm.group(2)]:
            for e in Deriver._expand(s[:mm.start()] + v + s[mm.end():], env, depth + 1):
                if e not in out:
                    out.append(e)
                if len(out) >= MAX_EXPANSIONS:
                    return out
        return out

    def _selfdir(self, a: str, src: str) -> str:
        d = posixpath.dirname(src)
        if a == SELFDIR:
            return d or "."
        if a.startswith(SELFDIR + "/"):
            return (d + "/" if d else "") + a[len(SELFDIR) + 1:]
        return a

    def scan_shell(self, src: str, text: str, cwd: str = "") -> None:
        original = text
        text = QUOTED_VAR.sub(r"\1", text.replace('\\"', '"'))
        text = SHELL_COMMENT_RE.sub("", SELFDIR_RE.sub(SELFDIR, text))
        if src.endswith(("action.yml", "action.yaml")):
            text = ACTION_PATH_RE.sub(SELFDIR, text)
        env = self._assignments(text)
        # Interpreter and `source` arguments: must be bounded, or the run fails closed.
        args = [m.group(1) for m in SHELL_LOAD_RE.finditer(text)]
        # `python -m mod`: the module is resolved by the command pass below, not read as a file.
        args += [m.group(2) for m in SHELL_EXEC_RE.finditer(text)
                 if not (PY_M_OPT_RE.search(m.group(1)) and "/" not in m.group(2))]
        for raw in args:
            if POSITIONAL_RE.match(raw.strip("\"'")):
                continue  # "$@": runs what the caller passes (followed in the caller)
            a0 = _clean(raw)
            if not a0 or a0.startswith("-"):
                continue  # an option, or "$@": runs what the caller passes (followed in the caller)
            for a in self._expand(a0, env):
                a = KNOWN_PREFIXES.sub("", self._selfdir(_clean(a), src))
                if "$" in a or SELFDIR in a:
                    self.report(f"dynamic shell reference {a0!r}")
                elif path_like(a):
                    self.ref(a, src, execd=True)
        # Command words that are literal paths.
        for mm in CMD_POS_RE.finditer(text):
            a0 = _clean(mm.group(1))
            if "=" in a0:
                continue
            for a in self._expand(a0, env):
                a = KNOWN_PREFIXES.sub("", self._selfdir(_clean(a), src))
                if PATH_CHARS.fullmatch(a) and "/" in a:
                    self.ref(a, src, execd=True)
        # Any other token naming a script.
        for raw in TOKEN_RE.findall(text):
            for tok in self._expand(_clean(raw), env):
                tok = KNOWN_PREFIXES.sub("", self._selfdir(_clean(tok), src))
                if "$" not in tok and path_like(tok) and is_script(tok):
                    self.ref(tok, src)
        # Command positions, read structurally (wrappers, -m, make, npm, cd).
        saved, self._cwd = self._cwd, cwd
        self._shell_commands(src, original, env)
        self._cwd = saved
        self._exec_bit(text, src)

    # -- shell command positions ---------------------------------------
    def _sreport(self, msg: str) -> None:
        """A report from the structural pass. Silent inside JavaScript (actions/github-script
        `script:`), which is scanned for edges but is not shell, so its syntax is not evidence."""
        if not self._js:
            self.report(msg)

    def _word(self, w: str, src: str, env: dict[str, list[str]]) -> list[str]:
        return [KNOWN_PREFIXES.sub("", self._selfdir(a, src)) for a in self._expand(w, env)]

    def _exec_path(self, w: str, src: str, env: dict[str, list[str]], *, bare_ok: bool = False,
                   what: str = "command") -> None:
        """A word the shell executes or loads: follow it if it names a repo path."""
        if not w or POSITIONAL_RE.match(w) or w.startswith("-"):
            return
        if w == NONLITERAL:
            self._py_unbounded("subprocess", self.cur_py or src)
            return
        for a in self._word(w, src, env):
            if "__SUBST__" in a or "$" in a or SELFDIR in a:
                # A computed path: fail closed, but only for a word that reads as a path
                # (JavaScript in a github-script `script:` is scanned too, and is not shell).
                if "/" in w and DYN_PATH_RE.fullmatch(w):
                    self._sreport(f"dynamic {what} {w!r}")
                continue
            if not PATH_CHARS.fullmatch(a):
                continue  # a glob or case pattern, or not a path
            if "/" not in a and not (bare_ok and (path_like(a) or a in self.tree)):
                continue  # a bare command word is looked up on PATH
            self.ref(a, src, execd=True)
            if self._cwd and not a.startswith("/"):
                j = _normjoin(self._cwd, a[2:] if a.startswith("./") else a)
                if j:
                    self.ref(j, src, execd=True)

    def _exec_bit(self, text: str, src: str) -> None:
        """Any token naming an executable file in the tree (mode 100755) is an edge."""
        for raw in TOKEN_RE.findall(text):
            tok = _clean(raw)
            tok = tok[2:] if tok.startswith("./") else tok
            if "/" not in tok or not PATH_CHARS.fullmatch(tok):
                continue
            for c in self._candidates(tok.lstrip("/"), src):
                if self.tree.get(c) == EXEC_MODE:
                    self.add(c)
                    break

    def _shell_commands(self, src: str, text: str, env: dict[str, list[str]], depth: int = 0) -> None:
        if depth > MAX_CMD_DEPTH:
            self._sreport("shell command nesting too deep to follow")
            return
        text = SELFDIR_RE.sub(SELFDIR, text)
        if src.endswith(("action.yml", "action.yaml")):
            text = ACTION_PATH_RE.sub(SELFDIR, text)
        # Known substitutions before the generic $(...) extraction: the repo root and $(cd D && pwd).
        text = TOPLEVEL_RE.sub("$GITHUB_WORKSPACE", text)
        text = CD_PWD_RE.sub(lambda mm: mm.group(1), text)
        text, bodies = _split_heredocs(text)
        text = _strip_comments(text)
        for line, body in bodies:
            names = {posixpath.basename(w) for w in re.findall(r"[A-Za-z0-9_.\-/]+", line)}
            if any(PY_INTERP_RE.match(n) for n in names):
                self.scan_python(src, _dedent(body))
            elif names & SH_INTERP:
                self._shell_commands(src, body, env, depth + 1)
        text, inner = _extract_substitutions(text)
        for t in inner:
            self._shell_commands(src, t, env, depth + 1)
        for seg in _lex_lenient(text):
            words: list[str] = []
            skip = False
            for w in seg:
                if skip:
                    skip = False
                    continue
                rm = REDIR_RE.match(w)
                if rm:
                    skip = not rm.group(1)
                    continue
                words.append(w)
            i = 0
            while i < len(words) and (words[i] in SHELL_KEYWORDS or ASSIGN_WORD_RE.match(words[i])):
                i += 1
            self._run_words(words[i:], src, env, depth)

    def _run_words(self, words: list[str], src: str, env: dict[str, list[str]], depth: int) -> None:
        if not words:
            return
        if depth > MAX_CMD_DEPTH:
            self._sreport("shell command nesting too deep to follow")
            return
        w, rest = words[0], words[1:]
        name = posixpath.basename(w)
        if w in NON_EXEC_HEADS:
            return
        if name in ("cd", "pushd"):
            args = [a for a in rest if not a.startswith("-")]
            vals = self._word(args[0], src, env) if args else []
            v = vals[0] if len(vals) == 1 else "$"
            ok = "$" not in v and "__SUBST__" not in v and SELFDIR not in v and not v.startswith(("/", "~"))
            self._cwd = (_normjoin(self._cwd, v) or "") if ok else ""
            return
        if name in ("source", "."):
            if rest:
                self._exec_path(rest[0], src, env, bare_ok=True, what="sourced file")
            return
        if rest and (name, rest[0]) in SUBCMD_WRAPPERS:
            self._wrapped(rest[1:], SUBCMD_WRAPPERS[(name, rest[0])], src, env, depth + 1)
        elif name == "uvx":
            self._wrapped(rest, SUBCMD_WRAPPERS[("uvx", "")], src, env, depth + 1)
        elif name in WRAPPERS:
            self._wrapped(rest, WRAPPERS[name], src, env, depth + 1)
        elif PY_INTERP_RE.match(name):
            self._python(rest, src, env)
        elif name in SH_INTERP:
            self._sh(rest, src, env, depth)
        elif name in OTHER_INTERP:
            self._interp(name, rest, src, env)
        elif name in MAKE_PROGS:
            self._make(rest, src, env)
        elif name in NPM_PROGS:
            self._npm(rest, src, env)
        elif name == "just":
            for jf in ("justfile", "Justfile", ".justfile"):  # recipes are shell; the files are on the floor
                self.add(posixpath.join(self._cwd, jf) if self._cwd else jf)
        elif name in ("task", "go-task"):
            self._sreport(f"{name} (Taskfile) recipes are not derived")
        elif name == "find":
            for k, a in enumerate(rest):
                if a in ("-exec", "-execdir", "-ok", "-okdir"):
                    end = next((j for j in range(k + 1, len(rest)) if rest[j] in (";", "+")), len(rest))
                    self._run_words(rest[k + 1:end], src, env, depth + 1)
        else:
            self._exec_path(w, src, env)

    def _wrapped(self, words: list[str], spec: dict, src: str, env: dict[str, list[str]], depth: int) -> None:
        """Skip a wrapper's options and fixed arguments, then follow the command it runs.
        An option the table does not know is read both ways (flag, or option + argument)."""
        if depth > MAX_CMD_DEPTH:
            self._sreport("shell command nesting too deep to follow")
            return
        i = 0
        while i < len(words):
            w = words[i]
            if w == "--":
                i += 1
                break
            if spec["assigns"] and ASSIGN_WORD_RE.match(w):
                i += 1
                continue
            if w == "-" and "-" in spec["flags"]:
                i += 1
                continue
            if not w.startswith("-") or w == "-":
                break
            if w.startswith("--"):
                opt, eq, val = w.partition("=")
                if opt in spec["cmdstr"]:
                    s = val if eq else (words[i + 1] if i + 1 < len(words) else "")
                    self._shell_commands(src, " ".join([s] + words[i + (1 if eq else 2):]), env, depth + 1)
                    return
                if eq or opt in spec["lflags"]:
                    i += 1
                elif opt in spec["larg"]:
                    i += 2
                else:
                    self._wrapped(words[i + 2:], spec, src, env, depth + 1)
                    i += 1
                continue
            if spec["numeric"] and w[1:].isdigit():
                i += 1
                continue
            step, unknown = 1, False
            for j in range(1, len(w)):
                c = "-" + w[j]
                if c in spec["cmdstr"]:
                    s = w[j + 1:]
                    used = 1 if s else 2
                    if not s:
                        s = words[i + 1] if i + 1 < len(words) else ""
                    self._shell_commands(src, " ".join([s] + words[i + used:]), env, depth + 1)
                    return
                if c in spec["arg"]:
                    step = 1 if j < len(w) - 1 else 2
                    break
                if c in spec["attached"]:
                    break
                if c not in spec["flags"]:
                    unknown = True
                    break
            if unknown:
                self._wrapped(words[i + 2:], spec, src, env, depth + 1)
            i += step
        if spec["nocmd"]:
            return
        rest = words[i + spec["pos"]:]
        if spec["pos"] and rest and rest[0].startswith("-"):
            self._wrapped(rest, {**spec, "pos": 0}, src, env, depth + 1)  # flock FILE -c CMD
            return
        if spec["joined"]:
            self._shell_commands(src, " ".join(rest), env, depth + 1)
        else:
            self._run_words(rest, src, env, depth + 1)

    def _python(self, words: list[str], src: str, env: dict[str, list[str]]) -> None:
        i = 0
        while i < len(words):
            w = words[i]
            if w == "-":
                return  # stdin; a here-document body is scanned on its own
            if w == "--":
                i += 1
                break
            if not w.startswith("-"):
                break
            if w.startswith("--"):
                i += 2 if w == "--check-hash-based-pycs" else 1
                continue
            for j in range(1, len(w)):
                c = w[j]
                if c in "mcWX":
                    val = w[j + 1:]
                    if not val:
                        val = words[i + 1] if i + 1 < len(words) else ""
                        i += 1
                    if c == "m":
                        self._py_module(val, src, env)
                        return
                    if c == "c":
                        self.scan_python(src, val)
                        return
                    break
                if c not in PY_FLAGS:
                    self._sreport(f"python option {w!r} not understood")
                    return
            i += 1
        if i < len(words):
            self._exec_path(words[i], src, env, bare_ok=True, what="python script")

    def _py_module(self, mod: str, src: str, env: dict[str, list[str]]) -> None:
        """`python -m a.b` runs a/b.py, or a/b/__main__.py after a/b/__init__.py, and imports a/__init__.py.
        Every candidate is 7a, existing or not: a PR that creates one shadows the module."""
        for m in self._word(mod, src, env):
            if not MODULE_RE.fullmatch(m):
                self._sreport(f"python -m module {mod!r} not resolvable")
                continue
            parts = m.split(".")
            for base in dict.fromkeys(["", self._cwd]):
                stem = posixpath.join(base, *parts) if base else posixpath.join(*parts)
                cands = [stem + ".py", stem + "/__init__.py", stem + "/__main__.py"]
                for k in range(1, len(parts)):
                    pre = posixpath.join(base, *parts[:k]) if base else posixpath.join(*parts[:k])
                    cands.append(pre + "/__init__.py")
                for c in cands:
                    if not self.add(c):
                        self.missing.add(c)

    def _sh(self, words: list[str], src: str, env: dict[str, list[str]], depth: int) -> None:
        i, cmd_mode = 0, False
        while i < len(words):
            w = words[i]
            if w in ("--", "-"):
                i += 1
                break
            if w[:1] not in "-+" or len(w) == 1:
                break
            if w.startswith("--"):
                i += 2 if w in ("--rcfile", "--init-file") else 1
                continue
            step = 1
            for c in w[1:]:
                if c == "c":
                    cmd_mode = True
                elif c in "oO":
                    step = 2
            i += step
        if i >= len(words):
            return  # reads its script from stdin
        if cmd_mode:
            self._shell_commands(src, words[i], env, depth + 1)
        else:
            self._exec_path(words[i], src, env, bare_ok=True, what="shell script")

    def _interp(self, name: str, words: list[str], src: str, env: dict[str, list[str]]) -> None:
        argopts, codeopts, loadopts = OTHER_INTERP[name]
        i = 0
        while i < len(words):
            w = words[i]
            if w == "--":
                i += 1
                break
            if not w.startswith("-") or w == "-":
                break
            opt, eq, val = w.partition("=")
            if opt not in argopts and opt not in codeopts and w[:2] in (argopts | codeopts) and len(w) > 2:
                opt, eq, val = w[:2], "=", w[2:]  # attached short argument
            if opt in codeopts:
                self._sreport(f"inline {name} code ({opt}) not followed")
                return
            if opt in argopts:
                v = val if eq else (words[i + 1] if i + 1 < len(words) else "")
                if opt in loadopts:
                    self._exec_path(v, src, env, what=f"{name} {opt} file")
                i += 1 if eq else 2
                continue
            i += 1
        if i < len(words):
            self._exec_path(words[i], src, env, bare_ok=True, what=f"{name} script")

    def _make(self, words: list[str], src: str, env: dict[str, list[str]]) -> None:
        """make runs recipes from the makefile it reads: derive that makefile (scanned as shell).
        Makefiles are also on the floor, so a PR that creates or edits one is 7a."""
        files: list[str] = []
        base = self._cwd
        i = 0
        while i < len(words):
            w = words[i]
            if w == "--":
                break
            if not w.startswith("-") or w == "-":
                i += 1
                continue  # a target or VAR=value
            opt, eq, val = w.partition("=")
            if opt not in MAKE_ARG and not w.startswith("--") and w[:2] in MAKE_ARG and len(w) > 2:
                opt, eq, val = w[:2], "=", w[2:]
            if opt in MAKE_ARG:
                v = val if eq else (words[i + 1] if i + 1 < len(words) else "")
                i += 1 if eq else 2
                if opt in ("-f", "--file", "--makefile"):
                    files.append(v)
                elif opt in ("-C", "--directory"):
                    vals = self._word(v, src, env)
                    if len(vals) != 1 or "$" in vals[0] or "__SUBST__" in vals[0] or vals[0].startswith("/"):
                        self._sreport(f"make directory {v!r} not resolvable")
                        return
                    base = _normjoin(base, vals[0]) or ""
                continue
            i += 1
        if files:
            for f in files:
                for a in self._word(f, src, env):
                    if "$" in a or "__SUBST__" in a or not PATH_CHARS.fullmatch(a):
                        self._sreport(f"make file {f!r} not resolvable")
                    else:
                        self.ref(_normjoin(base, a) or a, src, execd=True)
            return
        for mf in MAKEFILES:
            self.add(posixpath.join(base, mf) if base else mf)

    def scan_make(self, src: str, text: str) -> None:
        for mm in MAKE_INCLUDE_RE.finditer(text):
            for f in mm.group(1).split():
                if "$" in f or not PATH_CHARS.fullmatch(f):
                    self._sreport(f"make include {f!r} not resolvable")
                else:
                    self.ref(f, src, execd=True)
        assigns: dict[str, list[str]] = {}
        for am in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)[ \t]*[:+?!]?=[ \t]*(.*)$", text, re.MULTILINE):
            assigns.setdefault(am.group(1), []).append(am.group(2).strip())
        text = re.sub(r"\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]",
                      lambda mm: assigns[mm.group(1)][0] if len(assigns.get(mm.group(1), [])) == 1 else mm.group(0),
                      text)
        self.scan_shell(src, re.sub(r"(?m)^\t[@+\-]+", "\t", text))

    def _npm(self, words: list[str], src: str, env: dict[str, list[str]]) -> None:
        """npm/pnpm/yarn/bun run scripts and lifecycle hooks from package.json: derive it."""
        d = self._cwd
        for k, w in enumerate(words):
            opt, eq, val = w.partition("=")
            if opt in NPM_DIR_OPTS:
                v = val if eq else (words[k + 1] if k + 1 < len(words) else "")
                vals = self._word(v, src, env)
                if len(vals) != 1 or "$" in vals[0] or "__SUBST__" in vals[0] or vals[0].startswith("/"):
                    self._sreport(f"package directory {v!r} not resolvable")
                    return
                d = _normjoin(d, vals[0]) or ""
        if any(w in ("-r", "--recursive", "-w", "--workspace", "--workspaces", "--filter", "workspaces",
                     "workspace", "foreach") for w in words):
            targets = [p for p in self.tree if posixpath.basename(p) == "package.json"]
        else:
            targets = [posixpath.join(d, "package.json") if d else "package.json"]
        for p in targets:
            self.add(p)  # absent: a PR that creates it is 7a by the floor (**/package.json)

    def _py_unbounded(self, name: str, src: str) -> None:
        """A derived Python file runs a command that is not static. Bound it by what the file
        can name: every static string or path value in it that names an existing tree file
        (a bare name: a file beside it) becomes an execution edge. Fail closed if the file
        names nothing at all. The file's own path counts as a name (residual, see the
        notes above Deriver)."""
        if src in self._py_unbounded_done:
            return
        self._py_unbounded_done.add(src)
        trees = [t for t in (self._pytree, self._pyouter) if t is not None]
        hits = 0
        here = posixpath.dirname(src)
        for node in (n for t in trees for n in ast.walk(t)):
            if not (isinstance(node, (ast.Constant, ast.BinOp, ast.Call, ast.JoinedStr))):
                continue
            for v in self._py_value(node) or []:
                v = v.strip()
                if not v or "\n" in v or not PATH_CHARS.fullmatch(v):
                    continue
                if "/" in v:
                    p0 = posixpath.normpath(v)
                    cands = [] if p0.startswith(("/", "../")) or p0 == ".." else self._candidates(p0, src)
                else:
                    cands = [posixpath.join(here, v) if here else v]
                for c in cands:
                    if self.tree.get(c) not in (None, SUBMODULE_MODE) and c not in self.dirs:
                        self.add(c)
                        hits += 1
        if not hits:
            self.report(f"{name}() runs a non-literal command and the file names no tree file")

    def _py_subprocess(self, call: ast.Call, name: str, src: str) -> None:
        """subprocess / os.system / os.exec* / os.spawn*: follow the command when it is static
        (literals, __file__-relative paths, names assigned in the file); fail closed when not."""
        args = list(call.args)
        if name.startswith("spawn") and name != "spawn":
            args = args[1:]  # os.spawn*(mode, path, ...)
        if not args:
            return
        first = args[0]
        shell = name in SUBPROC_SHELL_CALLS or any(
            k.arg == "shell" and isinstance(k.value, ast.Constant) and bool(k.value.value) for k in call.keywords)
        if name in SUBPROC_PATH_CALLS:
            vals = self._py_value(first)
            if vals is None:
                self._py_unbounded(name, src)
            for v in vals or []:
                self._py_exec_target(v, src)
            return
        variants = self._py_argv(first)
        if variants is None:
            self._py_unbounded(name, src)
            return
        for words in variants:
            if shell:
                if NONLITERAL in words:
                    self._py_unbounded(name, src)
                else:
                    self._shell_commands(src, " ".join(words), {})
                continue
            self._run_words(words, src, {}, 0)

    # -- other kinds ---------------------------------------------------
    def scan_yaml(self, src: str, text: str) -> None:
        lines = text.splitlines()
        # A step's (or a `defaults:`) working-directory changes where relative commands resolve.
        # Each run block is also read from every literal working-directory in the file.
        cwds = [""]
        for wm in re.finditer(r"""^\s*(?:-\s+)?working-directory\s*:\s*["']?([^"'#\n]*?)["']?\s*(?:#.*)?$""",
                              text, re.MULTILINE):
            d = KNOWN_PREFIXES.sub("", wm.group(1).strip().rstrip("/") + "/").rstrip("/")
            if "$" in d or d.startswith(("/", "~")):
                self.report(f"working-directory {wm.group(1).strip()!r} not resolvable")
            else:
                d = _normjoin("", d)
                if d is not None and d not in cwds:
                    cwds.append(d)
        i = 0
        while i < len(lines):
            m = YAML_KEY_RE.match(lines[i])
            i += 1
            if not m:
                continue
            indent, key, val = len(m.group(1)), m.group(2), (m.group(3) or "").strip()
            if key == "uses":
                v = val.strip("\"'")
                if v.startswith("./") and not self.ref(v, src, execd=True):
                    self.report(f"local action {v!r} does not resolve")
                continue
            if key not in YAML_CMD_KEYS:
                continue
            self._js = key == "script" and self._in_github_script_step(lines, i - 1, indent)
            if val[:1] in ("|", ">"):
                block = []
                while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                    block.append(lines[i])
                    i += 1
                body = "\n".join(block)
            else:
                body = val.strip("\"'")
            for d in cwds:
                self.scan_shell(src, body, d)
            self._js = False

    @staticmethod
    def _in_github_script_step(lines: list[str], at: int, indent: int) -> bool:
        """True if the `script:` key on line `at` belongs to a step that uses actions/github-script."""
        start = at
        while start >= 0 and not (lines[start].lstrip().startswith("- ")
                                  and len(lines[start]) - len(lines[start].lstrip()) < indent):
            start -= 1
        if start < 0:
            return False
        item = len(lines[start]) - len(lines[start].lstrip())
        for k in range(start, len(lines)):
            ln = lines[k]
            if k > start and ln.strip() and len(ln) - len(ln.lstrip()) <= item:
                break
            if re.match(r"""^\s*(?:-\s+)?uses:\s*["']?actions/github-script@""", ln):
                return True
        return False

    def scan_json(self, src: str, text: str) -> None:
        try:
            doc = json.loads(text)
        except ValueError:
            self.scan_shell(src, text)  # JSONC and friends: read it all as shell, conservatively
            return

        def is_cmd(key: str) -> bool:
            return key.lower().endswith("command") or key in JSON_CMD_KEYS

        def walk(node: Any, key: str = "") -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, str(k))
            elif isinstance(node, list):
                if key and node and all(isinstance(x, str) for x in node) and is_cmd(key):
                    self.scan_shell(src, " ".join(node))
                else:
                    for x in node:
                        walk(x, key)
            elif isinstance(node, str) and is_cmd(key):
                self.scan_shell(src, node)
        walk(doc)
        if posixpath.basename(src) == "package.json" and isinstance(doc, dict) \
                and isinstance(doc.get("scripts"), dict):
            for v in doc["scripts"].values():  # every script: npm runs lifecycle hooks too
                if isinstance(v, str):
                    self.scan_shell(src, v)

    def scan_markdown(self, src: str, text: str) -> None:
        for mm in MD_IMPORT_RE.finditer(text):
            tok = mm.group(1).rstrip(".,;:")
            if path_like(tok):
                cands = self._candidates(tok[2:] if tok.startswith("./") else tok, src)
                any(self.add(p) for p in cands)

    # -- Python path values --------------------------------------------
    def _py_value(self, node: ast.AST | None, depth: int = 0) -> list[str] | None:
        """Evaluate a Python string or path expression statically: literals, __file__,
        Path(...), .parent, .parents[N], .joinpath(...), /, os.path.join/dirname/abspath/realpath, str(),
        + and f-strings, and names assigned in the same file. Paths built from __file__ come
        out repo-relative ("." is the root). None if any part is not static."""
        if node is None or depth > 8:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Name):
            if node.id == "__file__":
                return [self.cur_py]
            out: list[str] = []
            for v in self._pyenv.get(node.id, []):
                r = self._py_value(v, depth + 1)
                if r is None:
                    return None
                out.extend(x for x in r if x not in out)
            return out[:MAX_EXPANSIONS] or None
        if isinstance(node, ast.Attribute) and node.attr == "parent":
            r = self._py_value(node.value, depth + 1)
            return None if r is None else [_pdir(x) for x in r]
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) \
                and node.value.attr == "parents" and isinstance(node.slice, ast.Constant) \
                and type(node.slice.value) is int and 0 <= node.slice.value < 32:
            r = self._py_value(node.value.value, depth + 1)
            if r is None:
                return None
            for _ in range(node.slice.value + 1):
                r = [_pdir(x) for x in r]
            return r
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._py_join([node.left, node.right], depth)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            a, b = self._py_value(node.left, depth + 1), self._py_value(node.right, depth + 1)
            return None if a is None or b is None else [x + y for x in a for y in b][:MAX_EXPANSIONS]
        if isinstance(node, ast.JoinedStr):
            acc = [""]
            for part in node.values:
                r = self._py_value(part.value if isinstance(part, ast.FormattedValue) else part, depth + 1)
                if r is None:
                    return None
                acc = [x + y for x in acc for y in r][:MAX_EXPANSIONS]
            return acc
        if isinstance(node, ast.Call):
            fn = node.func
            fname = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
            recv = fn.value if isinstance(fn, ast.Attribute) else None
            if fname in ("Path", "PurePath", "PurePosixPath", "PosixPath"):
                return self._py_join(list(node.args), depth) if node.args else ["."]
            if fname == "joinpath" and recv is not None:
                return self._py_join([recv] + list(node.args), depth)
            if fname == "join" and recv is not None and (
                    (isinstance(recv, ast.Attribute) and recv.attr == "path")
                    or (isinstance(recv, ast.Name) and recv.id in ("path", "posixpath", "osp"))):
                return self._py_join(list(node.args), depth)
            if fname == "dirname" and node.args:
                r = self._py_value(node.args[0], depth + 1)
                return None if r is None else [_pdir(x) for x in r]
            if fname in ("abspath", "realpath", "normpath", "str", "fspath") and len(node.args) == 1:
                return self._py_value(node.args[0], depth + 1)
            if fname in ("resolve", "absolute", "as_posix", "__fspath__") and recv is not None and not node.args:
                return self._py_value(recv, depth + 1)
        return None

    def _py_join(self, parts: list[ast.AST], depth: int) -> list[str] | None:
        acc = [""]
        for p in parts:
            r = self._py_value(p, depth + 1)
            if r is None:
                return None
            acc = [posixpath.join(x, y) if x else y for x in acc for y in r][:MAX_EXPANSIONS]
        return acc

    def _py_exec_target(self, value: str, src: str) -> None:
        """A statically known path that Python executes or runs."""
        if not posixpath.normpath(value).startswith(("/", "../")):
            self._exec_path(value, src, {}, what="python exec target")

    def _py_argv(self, node: ast.AST) -> list[list[str]] | None:
        """argv variants for a subprocess-style first argument; NONLITERAL marks an unknown element.
        None if the command itself is not static."""
        if isinstance(node, ast.Name) and node.id in self._pyenv and all(
                isinstance(v, (ast.List, ast.Tuple)) for v in self._pyenv[node.id]):
            out: list[list[str]] = []
            for v in self._pyenv[node.id]:
                r = self._py_argv(v)
                if r is None:
                    return None
                out.extend(r)
            return out[:MAX_EXPANSIONS]
        if isinstance(node, (ast.List, ast.Tuple)):
            acc: list[list[str]] = [[]]
            for k, e in enumerate(node.elts):
                if isinstance(e, ast.Attribute) and e.attr == "executable" and \
                        isinstance(e.value, ast.Name) and e.value.id == "sys":
                    r: list[str] | None = ["python3"]
                else:
                    r = None if isinstance(e, ast.Starred) else self._py_value(e)
                if r is None:
                    if k == 0:
                        return None
                    r = [NONLITERAL]
                acc = [a + [x] for a in acc for x in r][:MAX_EXPANSIONS]
            return acc
        r = self._py_value(node)
        return None if r is None else [[x] for x in r]

    # -- Python --------------------------------------------------------
    def scan_python(self, src: str, text: str) -> None:
        try:
            tree = ast.parse(text, filename=src)
        except (SyntaxError, ValueError) as e:
            self.report(f"cannot parse as Python ({type(e).__name__})")
            return
        pkg = posixpath.dirname(src)
        saved = (self._pyenv, self.cur_py, self._pytree, self._pyouter, self._pyalias, self._pymods)
        # Inline code (`python -c`, a here-document) run by a Python file belongs to that file.
        self._pyouter = saved[2] if saved[1] == src else None
        self._pyenv, self.cur_py, self._pytree = {}, src, tree
        self._pyalias, self._pymods = {}, set(EXEC_MODULES)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                self._pyenv.setdefault(node.targets[0].id, []).append(node.value)
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name):
                if node.value is None:
                    continue
                if isinstance(node, ast.AugAssign):
                    self._pyenv.setdefault(node.target.id, []).append(ast.Name(id="__unknown__"))
                else:
                    self._pyenv.setdefault(node.target.id, []).append(node.value)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith, ast.comprehension)):
                for tgt in ([node.target] if hasattr(node, "target") else
                            [i.optional_vars for i in node.items if i.optional_vars is not None]):
                    for nm in ast.walk(tgt):
                        if isinstance(nm, ast.Name):
                            self._pyenv.setdefault(nm.id, []).append(ast.Name(id="__unknown__"))
        self._py_aliases(tree)
        try:
            self._scan_python_tree(src, tree, pkg)
        finally:
            self._pyenv, self.cur_py, self._pytree, self._pyouter, self._pyalias, self._pymods = saved

    def _py_aliases(self, tree: ast.AST) -> None:
        """Names bound to an exec module or function: `import subprocess as sp`,
        `from subprocess import run as r`, `sp = subprocess`, `r = sp.run`,
        `r = getattr(subprocess, "run")` (followed through chains of such assignments)."""
        assigns: list[tuple[str, ast.AST]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name in EXEC_MODULES:
                        self._pymods.add(a.asname or a.name)
            elif isinstance(node, ast.ImportFrom) and node.module in EXEC_MODULES and not node.level:
                for a in node.names:
                    if a.name in EXEC_CALLS:
                        self._pyalias[a.asname or a.name] = a.name
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        assigns.append((t.id, node.value))
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and isinstance(node.target, ast.Name) \
                    and node.value is not None:
                assigns.append((node.target.id, node.value))
        for _ in range(MAX_CMD_DEPTH):
            grew = False
            for tgt, val in assigns:
                if isinstance(val, ast.Name) and val.id in self._pymods and tgt not in self._pymods:
                    self._pymods.add(tgt)
                    grew = True
                fn = self._py_exec_fn(val)
                if fn and self._pyalias.get(tgt) != fn:
                    self._pyalias[tgt] = fn
                    grew = True
            if not grew:
                break

    def _py_exec_fn(self, node: ast.AST) -> str | None:
        """The exec function an expression refers to (`subprocess.run`, `sp.run`, an alias name,
        `getattr(os, "system")`), or None."""
        if isinstance(node, ast.Attribute) and node.attr in EXEC_CALLS and \
                isinstance(node.value, ast.Name) and node.value.id in self._pymods:
            return node.attr
        if isinstance(node, ast.Name):
            return self._pyalias.get(node.id)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" \
                and len(node.args) >= 2 and isinstance(node.args[0], ast.Name) and node.args[0].id in self._pymods \
                and isinstance(node.args[1], ast.Constant) and node.args[1].value in EXEC_CALLS:
            return node.args[1].value
        return None

    def _scan_python_tree(self, src: str, tree: ast.AST, pkg: str) -> None:
        docstrings = set()
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and body \
                    and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
        dynamic: list[tuple[ast.Call, str]] = []
        literal_hits = 0
        used: set[int] = set()  # exec-function references that are resolved below
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                used.add(id(node.func))
            elif isinstance(node, ast.Assign) and all(isinstance(t, ast.Name) for t in node.targets):
                used.add(id(node.value))  # an alias, resolved by _py_aliases
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and isinstance(node.target, ast.Name) \
                    and node.value is not None:
                used.add(id(node.value))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.resolve_module(a.name, 0, pkg)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                self.resolve_module(mod, node.level, pkg)
                for a in node.names:
                    if a.name != "*":
                        self.resolve_module(f"{mod}.{a.name}" if mod else a.name, node.level, pkg)
            elif isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else None
                name = self._py_exec_fn(fn) or name
                if isinstance(fn, ast.Attribute) and fn.attr in self._pyalias:
                    name = self._pyalias[fn.attr]  # `r = subprocess.run` in a class body, called as self.r(...)
                if name in EXEC_CALLS:
                    self._py_subprocess(node, name, src)
                elif name == "partial" and node.args:
                    # functools.partial(subprocess.run, [...]): the bound arguments are the call's.
                    inner = node.args[0]
                    iname = self._py_exec_fn(inner) or (inner.attr if isinstance(inner, ast.Attribute) else None)
                    if iname in EXEC_CALLS:
                        used.add(id(inner))
                        if len(node.args) > 1:
                            self._py_subprocess(ast.Call(func=inner, args=node.args[1:], keywords=node.keywords),
                                                iname, src)
                        else:
                            self._py_unbounded(f"partial({iname})", src)
                elif name == "getattr" and len(node.args) >= 2 and isinstance(node.args[0], ast.Name) \
                        and node.args[0].id in self._pymods and not (
                            isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
                    self._py_unbounded(f"getattr({node.args[0].id}, <non-literal>)", src)
                if name in DYNAMIC_CALLS:
                    dynamic.append((node, name))
                elif name in ("join", "Path", "PurePath", "PurePosixPath"):
                    literal_hits += self._joined(src, list(node.args))
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                literal_hits += self._joined(src, self._div_chain(node))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                self._exec_bit(node.value, src)
                for raw in TOKEN_RE.findall(node.value):
                    tok = _clean(raw)
                    if "$" not in tok and path_like(tok) and is_script(tok) and self.ref(tok, src):
                        literal_hits += 1
        for node in ast.walk(tree):
            # An exec function used as a value (passed, stored, returned): its call is not seen.
            if isinstance(node, (ast.Attribute, ast.Name, ast.Call)) and id(node) not in used:
                ref = self._py_exec_fn(node)
                if ref and not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)):
                    self._py_unbounded(f"{ref} used as a value", src)
        for call, name in dynamic:
            self.resolve_dynamic(call, src, pkg, name, literal_hits)

    @staticmethod
    def _div_chain(node: ast.AST) -> list[ast.AST]:
        out: list[ast.AST] = []
        while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            out.insert(0, node.right)
            node = node.left
        out.insert(0, node)
        return out

    def _joined(self, src: str, parts: list[ast.AST]) -> int:
        """Path("a", "b"), os.path.join(X, "a", "b"), X / "a" / "b": follow the trailing literal run."""
        tail: list[str] = []
        for p in reversed(parts):
            if isinstance(p, ast.Constant) and isinstance(p.value, str):
                tail.insert(0, p.value)
            else:
                break
        joined = "/".join(t.strip("/") for t in tail if t.strip("/"))
        return 1 if joined and path_like(joined) and self.ref(joined, src) else 0

    def resolve_module(self, name: str, level: int, pkg: str) -> None:
        if level:
            base = pkg
            for _ in range(level - 1):
                base = posixpath.dirname(base)
            roots = [base]
        else:
            roots = ["", pkg]
        parts = [p for p in name.split(".") if p]
        for r in roots:
            for i in range(1, len(parts) + 1):
                stem = posixpath.join(r, *parts[:i]) if r else posixpath.join(*parts[:i])
                for cand in (stem + ".py", stem + "/__init__.py"):
                    if cand in self.tree:
                        self.add(cand)
        # Not found in the tree: stdlib or a third-party package (manifests are on the floor).

    def resolve_dynamic(self, call: ast.Call, src: str, pkg: str, name: str, literal_hits: int) -> None:
        first = call.args[0] if call.args else None
        if name in ("import_module", "__import__", "run_module"):
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                mod = first.value
                self.resolve_module(mod.lstrip("."), len(mod) - len(mod.lstrip(".")), pkg)
                return  # a literal name: repo module added, or stdlib/third-party
        else:
            found = False
            for a in list(call.args) + [k.value for k in call.keywords]:
                if self._joined(src, self._div_chain(a) if isinstance(a, ast.BinOp) else [a]):
                    found = True
                for v in self._py_value(a) or []:  # __file__-relative and assigned paths
                    if "/" in v and not posixpath.normpath(v).startswith(("/", "../")):
                        self._py_exec_target(v, src)
                        found = True
            if found:
                return
            if name == "run_path":
                self._py_unbounded(name, src)  # runs a file: bound by what the module names, or fail closed
                return
        if literal_hits:
            # No literal target at the call, but the module names its scripts
            # literally (SCRIPT = ROOT / "tools" / "x.py"), and those are derived.
            return
        if self._pyouter is not None:
            # Inline code whose target comes from the enclosing file's argv: bound it by that file.
            self._py_unbounded(name, src)
            return
        self.report(f"dynamic {name}() reference not resolvable to a literal path")

    def scan(self, path: str) -> None:
        self.cur = path
        self._cwd = ""
        mode = self.tree.get(path)
        if mode == SUBMODULE_MODE:
            self.report("submodule reached by derivation")
            return
        try:
            blob = self.read(path)
        except Exception as e:  # noqa: BLE001
            self.report(f"cannot read ({type(e).__name__})")
            return
        if mode == SYMLINK_MODE:
            target = _normjoin(posixpath.dirname(path), blob.decode("utf-8", "surrogateescape"))
            if target is None or not self.add(target):
                self.report("symlink target outside the repo or missing")
            return
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            return  # binary: nothing to follow
        first = text.split("\n", 1)[0]
        low = path.lower()
        if low.endswith(".py") or (first.startswith("#!") and "python" in first):
            self.scan_python(path, text)
        elif low.endswith((".yml", ".yaml")):
            self.scan_yaml(path, text)
        elif low.endswith((".json", ".jsonc")):
            self.scan_json(path, text)
        elif low.endswith((".md", ".markdown")):
            self.scan_markdown(path, text)
        elif posixpath.basename(path) in MAKEFILES or low.endswith(".mk"):
            self.scan_make(path, text)
        else:
            self.scan_shell(path, text)

    def run(self) -> tuple[list[str], list[str]]:
        roots = self.config["derive_roots"]
        for p in sorted(self.tree):
            if self.matches(p, roots):
                self.add(p)
        seen: set[str] = set()
        while self.queue:
            p = self.queue.pop()
            if p in seen:
                continue
            seen.add(p)
            self.scan(p)
        patterns = (list(self.config["floor_7a"]) + sorted(self.dir_globs) + sorted(self.files)
                    + sorted(self.missing - self.files) + sorted(self.globs))
        return patterns, sorted(set(self.unresolved))


def derive_7a(tree: dict[str, str], read: Callable[[str], bytes], matches: Callable[[str, list[str]], bool],
              config: dict) -> tuple[list[str], list[str]]:
    """Return (7a patterns, unresolved references). Non-empty unresolved = fail closed."""
    return Deriver(tree, read, matches, config).run()


def check_7a(changes: list[Change], patterns: list[str], matches: Callable[[str, list[str]], bool]) -> list[str]:
    """Reasons the change set is 7a (empty = not 7a)."""
    reasons = []
    if not changes:
        reasons.append("empty diff against the merge base (fail closed)")
    for c in changes:
        if c.old_mode in (SYMLINK_MODE, SUBMODULE_MODE) or c.new_mode in (SYMLINK_MODE, SUBMODULE_MODE):
            reasons.append(f"symlink or submodule change: {q(c.path)}")
        elif matches(c.path, patterns):
            reasons.append(f"7a path: {q(c.path)}")
    return reasons


# --------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------

def label_names(labels: Any) -> set[str]:
    if not isinstance(labels, list):
        raise ValueError("labels: not a list")
    out = set()
    for lab in labels:
        name = lab.get("name") if isinstance(lab, dict) else None
        if not isinstance(name, str):
            raise ValueError("labels: malformed entry")
        out.add(name)
    return out


def gh_merge(repo: str, number: int, head: str, method: str,
             run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> tuple[bool, str]:
    args = ["gh", "pr", "merge", str(number), "--repo", repo, f"--{method}", "--match-head-commit", head]
    try:
        p = run(args, capture_output=True, timeout=120)
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    msg = (p.stderr or b"").decode("utf-8", "replace").strip() or (p.stdout or b"").decode("utf-8", "replace").strip()
    return p.returncode == 0, " ".join(msg.split())[:500]


class StaleDefinition(Exception):
    """The default branch moved past this run's definition with a 7a change."""


# Outcomes of process(). "error" and "refused" are systemic: they make the run red.
MERGED_, SKIPPED, ERROR, REFUSED_ = "merged", "skipped", "error", "refused"


class Runner:
    def __init__(self, ctx: Ctx, gh: Any, git: Git, verdict: Any, verdict_config: dict, config: dict,
                 merger: Callable[[str, int, str, str], tuple[bool, str]]):
        self.ctx = ctx
        self.gh = gh
        self.git = git
        self.v = verdict
        self.vcfg = verdict_config
        self.cfg = config
        self.merger = merger
        self.base_sha: str | None = None
        self.patterns: list[str] | None = None

    def skip(self, n: int, head: str, reason: str, outcome: str = SKIPPED) -> str:
        log(f"SKIP pr={n} head={head} outcome={outcome} reason={reason}")
        return outcome

    def prepare_7a(self, branch: str) -> list[str]:
        """Fetch the default branch and derive the 7a set from it. Raises DeriveError or StaleDefinition.

        Called again after every merge in the run, so later candidates are checked
        against the new tip and the set derived from it (challenger I5)."""
        try:
            self.base_sha = self.git.fetch(f"refs/heads/{branch}", "refs/e5/base")
            tree = self.git.tree(self.base_sha)
            base = self.base_sha
            patterns, unresolved = derive_7a(tree, lambda p: self.git.show(base, p), self.v.matches_any, self.cfg)
        except GitError as e:
            raise DeriveError(f"7a derivation failed (fail closed): {e}") from e
        if unresolved:
            for u in unresolved:
                log(f"7A-DERIVE unresolved: {u}")
            raise DeriveError(f"7a derivation found {len(unresolved)} unresolvable reference(s) (fail closed)")
        log(f"7A-DERIVE base={self.base_sha} patterns={len(patterns)} "
            f"derived={len(patterns) - len(self.cfg['floor_7a'])}")
        self.check_definition_current(patterns)
        return patterns

    def check_definition_current(self, patterns: list[str]) -> None:
        """This run executes the merge.py/config.json of workflow_sha. If the default branch has
        since gained a 7a change (a floor tightening, a new derived script), stop: the next run
        uses the new definition."""
        wsha = self.ctx.workflow_sha
        if wsha == self.base_sha:
            return
        try:
            if self.git.merge_base(wsha, self.base_sha) != wsha:
                raise DeriveError(f"workflow_sha {wsha} is not an ancestor of the default branch (fail closed)")
            hits = check_7a(self.git.diff(wsha, self.base_sha), patterns, self.v.matches_any)
        except GitError as e:
            raise DeriveError(f"cannot compare workflow_sha with the default branch (fail closed): {e}") from e
        if hits:
            raise StaleDefinition(f"default branch {self.base_sha} has 7a changes since workflow_sha {wsha}")

    def reread_after_failed_merge(self, n: int, head: str, msg: str) -> str:
        """A failed or timed-out `gh pr merge` may still have merged: re-read the PR (challenger I2)."""
        try:
            pr = self.gh.get(f"repos/{self.ctx.repo}/pulls/{n}")
        except Exception as e:  # noqa: BLE001
            log(f"MERGE-REFUSED pr={n} head={head} reason={q(msg)} reread=failed:{q(type(e).__name__)}")
            return REFUSED_
        merged_by = ((pr.get("merged_by") or {}).get("login"))
        pr_head = (pr.get("head") or {}).get("sha")
        if pr.get("merged") is True and pr_head == head:
            if merged_by == self.cfg["merger_login"]:
                log(f"MERGE-CONFIRMED pr={n} head={head} by=reread (merge call reported {q(msg)})")
                log_merged(n, head, self.ctx)
                self.patterns = None
                return MERGED_
            return self.skip(n, head, f"merged by another actor {q(merged_by)}; not this run")
        kind = "check-stale" if "required status check" in msg.lower() else "other"
        log(f"MERGE-REFUSED pr={n} head={head} kind={kind} reason={q(msg)}")
        if kind == "check-stale":
            log(f"MERGE-REFUSED pr={n} hint=the review-verdict check on the PR head predates the review "
                f"records; a PR event (relabel auto-merge) re-runs verdict.yml")
        return REFUSED_

    def process(self, n: int, branch: str) -> str:
        cfg = self.cfg
        repo = self.ctx.repo
        pr = self.gh.get(f"repos/{repo}/pulls/{n}")
        head = (pr.get("head") or {}).get("sha")
        if not isinstance(head, str) or not SHA_RE.fullmatch(head):
            return self.skip(n, "?", "head SHA missing or malformed")
        log(f"CANDIDATE pr={n} head={head}")
        try:
            labels = label_names(pr.get("labels"))
        except ValueError as e:
            return self.skip(n, head, q(str(e)))
        if pr.get("state") != "open":
            return self.skip(n, head, f"state {q(pr.get('state'))}")
        if cfg["auto_merge_label"] not in labels:
            return self.skip(n, head, f"no {q(cfg['auto_merge_label'])} label")
        if cfg["kill_label"] in labels:
            return self.skip(n, head, f"{q(cfg['kill_label'])} label present")
        if cfg["operator_merge_label"] in labels:
            return self.skip(n, head, f"{q(cfg['operator_merge_label'])} label present (operator merges)")
        if (((pr.get("head") or {}).get("repo")) or {}).get("full_name") != repo:
            return self.skip(n, head, "head repository is not this repository (fork PRs are never merged)")
        if (pr.get("base") or {}).get("ref") != branch:
            return self.skip(n, head, f"base is not {q(branch)}")

        # 4. Verdict, recomputed inline at H.
        outcome_on_fail = SKIPPED
        try:
            res = self.v.fetch_and_compute(self.gh, repo, n, self.vcfg)
        except Exception as e:  # noqa: BLE001 - VerdictError or anything else: fail closed
            msg = str(e)
            systemic = not isinstance(e, self.v.VerdictError) or msg.startswith(("GET ", "refusing to send"))
            if systemic:
                outcome_on_fail = ERROR  # the API or the token is broken, not the PR
            res = self.v.Result(passed=False, head_sha=head,
                                reasons=[f"cannot compute verdict (fail closed): {type(e).__name__}: {msg}"])
        ok = bool(res.passed) and res.head_sha == head
        log_verdict_recomputed(n, head, ok)
        log(f"VERDICT-CONTEXT pr={n} head={head} verdict_head={q(res.head_sha)} weight={q(res.weight)} "
            f"{self.ctx.tag()}")
        for r in res.reasons:
            log(f"VERDICT-DETAIL pr={n} FAIL: {r}")
        for note in res.notes:
            log(f"VERDICT-DETAIL pr={n} note: {note}")
        if not ok:
            why = "verdict head differs from H" if res.passed else "verdict FAIL"
            return self.skip(n, head, why, outcome_on_fail)

        # 5. 7a path check, against the current tip of the default branch.
        if self.patterns is None:
            self.patterns = self.prepare_7a(branch)
        try:
            fetched = self.git.fetch(f"refs/pull/{n}/head", f"refs/e5/pr/{n}")
            if fetched != head:
                return self.skip(n, head, f"fetched head {fetched} is not H (head moved)")
            mb = self.git.merge_base(self.base_sha, head)
            changes = self.git.diff(mb, head)
        except GitError as e:
            return self.skip(n, head, f"7a check could not complete (fail closed): {q(str(e))}", ERROR)
        hits = check_7a(changes, self.patterns, self.v.matches_any)
        if hits:
            for h in hits[:20]:
                log(f"7A-HIT pr={n} {h}")
            return self.skip(n, head, "touches a 7a path; skip (operator merges)")
        log(f"7A-CLEAR pr={n} head={head} merge_base={mb} files={len(changes)}")

        # 6. Label kill switch, head and base, re-read now.
        again = self.gh.get(f"repos/{repo}/pulls/{n}")
        now_labels = label_names(self.gh.paged(f"repos/{repo}/issues/{n}/labels"))
        if (again.get("head") or {}).get("sha") != head:
            return self.skip(n, head, "head moved before merge")
        if again.get("state") != "open":
            return self.skip(n, head, "closed before merge")
        if (again.get("base") or {}).get("ref") != branch:
            return self.skip(n, head, "base changed before merge")
        if cfg["kill_label"] in now_labels:
            return self.skip(n, head, f"{q(cfg['kill_label'])} label present (re-read before merge)")
        if cfg["auto_merge_label"] not in now_labels or cfg["operator_merge_label"] in now_labels:
            return self.skip(n, head, "labels changed before merge")

        # 7. Merge, pinned to H.
        merged, msg = self.merger(repo, n, head, cfg["merge_method"])
        if merged:
            log_merged(n, head, self.ctx)
            self.patterns = None  # re-fetch the tip and re-derive before the next candidate
            return MERGED_
        return self.reread_after_failed_merge(n, head, msg)

    def run(self, kill_value: str | None) -> int:
        ctx = self.ctx
        log(f"PROVENANCE workflow_ref={ctx.workflow_ref} workflow_sha={ctx.workflow_sha} "
            f"run_id={ctx.run_id} event={ctx.event}")
        if not kill_switch_allows(kill_value):
            log(f"KILL SWITCH: AUTO_MERGE_ENABLED={q(kill_value)} is not exactly 'true'; no merges")
            return 0
        branch = self.cfg["default_branch"]
        if ctx.event not in ("pull_request_target", "schedule") \
                or ctx.workflow_ref != expected_workflow_ref(ctx.repo, branch):
            log(f"REFUSED: event={ctx.event} workflow_ref={ctx.workflow_ref}; expected pull_request_target or "
                f"schedule from {expected_workflow_ref(ctx.repo, branch)}")
            return 1
        if not ctx.run_id.isdigit() or not SHA_RE.fullmatch(ctx.workflow_sha):
            log("REFUSED: GITHUB_RUN_ID or GITHUB_WORKFLOW_SHA missing or malformed (fail closed)")
            return 1
        try:
            meta = self.gh.get(f"repos/{ctx.repo}")
            if meta.get("default_branch") != branch:
                log(f"REFUSED: repository default branch {q(meta.get('default_branch'))} is not {q(branch)}")
                return 1
            q_ = f"repos/{ctx.repo}/pulls?state=open&base={branch}"
            prs = self.gh.paged(q_, limit=10)
        except Exception as e:  # noqa: BLE001
            log(f"REFUSED: cannot list candidates (fail closed): {type(e).__name__}: {e}")
            return 1
        cands = []
        for pr in prs:
            try:
                names = label_names(pr.get("labels"))
            except ValueError:
                continue
            n = pr.get("number")
            head_repo = (((pr.get("head") or {}).get("repo")) or {}).get("full_name")
            if isinstance(n, int) and self.cfg["auto_merge_label"] in names and head_repo == ctx.repo:
                cands.append(n)
        cands = sorted(cands)
        cap = self.cfg["max_candidates"]
        if len(cands) > cap:
            log(f"CANDIDATES dropped (over max_candidates={cap}): {cands[cap:]}")
        cands = cands[:cap]
        log(f"CANDIDATES {cands}")
        counts = {MERGED_: 0, SKIPPED: 0, ERROR: 0, REFUSED_: 0}
        for n in cands:
            try:
                out = self.process(n, branch)
            except DeriveError as e:
                log(f"SKIP pr={n} head=? outcome=error reason={e}")
                log("REFUSED: 7a set unavailable; no merges this run (fail closed)")
                log("::error title=auto-merge::7a set unavailable; no merges this run", _audit=True)
                return 1
            except StaleDefinition as e:
                log(f"STALE-DEFINITION: {e}; stopping this run, the next run uses the new definition")
                break
            except Exception as e:  # noqa: BLE001 - one bad PR never merges, never stops the others
                log(f"SKIP pr={n} head=? outcome=error reason=error (fail closed): {type(e).__name__}: {e}")
                out = ERROR
            counts[out] = counts.get(out, 0) + 1
        log("RUN-RESULT " + " ".join(f"{k}={v}" for k, v in counts.items()))
        if counts[ERROR] or counts[REFUSED_]:
            log(f"::error title=auto-merge::{counts[ERROR]} candidate(s) errored and {counts[REFUSED_]} "
                f"merge(s) were refused; see the SKIP/MERGE-REFUSED lines", _audit=True)
            return 1
        return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--config", required=True)
    args = ap.parse_args(argv)
    env = os.environ
    ctx = Ctx(args.repo, env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_WORKFLOW_REF", ""),
              env.get("GITHUB_WORKFLOW_SHA", ""), env.get("GITHUB_EVENT_NAME", ""))
    token = env.get("GH_TOKEN", "")
    try:
        cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
        v = load_verdict()
        vcfg = json.loads(Path(cfg["verdict_config"]).read_text(encoding="utf-8"))
        if not token:
            raise RuntimeError("GH_TOKEN not set")
        gh = v.GitHub(token, env.get("GITHUB_API_URL", "https://api.github.com"))
        url = f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/{args.repo}.git"
        git = Git(url, token)
    except Exception as e:  # noqa: BLE001
        log(f"PROVENANCE workflow_ref={ctx.workflow_ref} workflow_sha={ctx.workflow_sha} "
            f"run_id={ctx.run_id} event={ctx.event}")
        log(f"REFUSED: setup failed (fail closed): {type(e).__name__}: {e}")
        return 1
    return Runner(ctx, gh, git, v, vcfg, cfg, gh_merge).run(env.get("AUTO_MERGE_ENABLED"))


if __name__ == "__main__":
    sys.exit(main())
