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
# - a local action (`uses: ./x`), a symlink's target, a Markdown `@path` import.
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
        for p in cands:
            if self.add(p):
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

    def scan_shell(self, src: str, text: str) -> None:
        text = QUOTED_VAR.sub(r"\1", text.replace('\\"', '"'))
        text = SHELL_COMMENT_RE.sub("", SELFDIR_RE.sub(SELFDIR, text))
        if src.endswith(("action.yml", "action.yaml")):
            text = ACTION_PATH_RE.sub(SELFDIR, text)
        env = self._assignments(text)
        # Interpreter and `source` arguments: must be bounded, or the run fails closed.
        args = [m.group(1) for m in SHELL_LOAD_RE.finditer(text)]
        args += [m.group(2) for m in SHELL_EXEC_RE.finditer(text)]
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

    # -- other kinds ---------------------------------------------------
    def scan_yaml(self, src: str, text: str) -> None:
        lines = text.splitlines()
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
            if val[:1] in ("|", ">"):
                block = []
                while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                    block.append(lines[i])
                    i += 1
                self.scan_shell(src, "\n".join(block))
            else:
                self.scan_shell(src, val.strip("\"'"))

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

    def scan_markdown(self, src: str, text: str) -> None:
        for mm in MD_IMPORT_RE.finditer(text):
            tok = mm.group(1).rstrip(".,;:")
            if path_like(tok):
                cands = self._candidates(tok[2:] if tok.startswith("./") else tok, src)
                any(self.add(p) for p in cands)

    # -- Python --------------------------------------------------------
    def scan_python(self, src: str, text: str) -> None:
        try:
            tree = ast.parse(text, filename=src)
        except (SyntaxError, ValueError) as e:
            self.report(f"cannot parse as Python ({type(e).__name__})")
            return
        pkg = posixpath.dirname(src)
        docstrings = set()
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and body \
                    and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
        dynamic: list[tuple[ast.Call, str]] = []
        literal_hits = 0
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
                if name in DYNAMIC_CALLS:
                    dynamic.append((node, name))
                elif name in ("join", "Path", "PurePath", "PurePosixPath"):
                    literal_hits += self._joined(src, list(node.args))
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                literal_hits += self._joined(src, self._div_chain(node))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                for raw in TOKEN_RE.findall(node.value):
                    tok = _clean(raw)
                    if "$" not in tok and path_like(tok) and is_script(tok) and self.ref(tok, src):
                        literal_hits += 1
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
            if found:
                return
        if literal_hits:
            # No literal target at the call, but the module names its scripts
            # literally (SCRIPT = ROOT / "tools" / "x.py"), and those are derived.
            return
        self.report(f"dynamic {name}() reference not resolvable to a literal path")

    def scan(self, path: str) -> None:
        self.cur = path
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
