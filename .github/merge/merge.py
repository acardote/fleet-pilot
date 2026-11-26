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
     VERDICT-INLINE line plus the verdict's own lines, for the #581 audit.
  5. 7a path check, complete and fail closed: fetch the default branch and
     refs/pull/<n>/head (into an empty bare repo; nothing is checked out or
     run), require the fetched head to equal H, then
     `git diff --raw --no-renames <merge-base>..H`. Any changed path (both
     sides of a rename, every deletion) matching the 7a set, or any symlink or
     submodule change, skips the PR. The 7a set is the floor list in
     config.json plus the paths derived transitively from the default
     branch's roots (derive_7a). An unresolvable reference fails closed: no PR
     is merged in that run.
  6. Kill switch (label), re-read immediately before the merge call, with the
     head and the `auto-merge` label.
  7. Merge: `gh pr merge <n> --squash --match-head-commit H`, logged as
     `MERGED pr=<n> head=<H> run_id=<id> workflow_ref=<ref>` or
     `merge refused: ...`. A refused merge is retried by the next schedule run,
     which recomputes steps 2-6 from scratch.

Stdlib only (plus git and gh, preinstalled on the runner). Exit 0 = the run
completed (merged or not); 1 = the run could not establish its own provenance
or the 7a set (fail closed, nothing merged).
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


def log(line: str) -> None:
    print(line, flush=True)


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

TOKEN_RE = re.compile(r"[A-Za-z0-9_.\-/${}()\[\]\"'@]+")
KNOWN_PREFIXES = re.compile(
    r"""^(?:\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?|\$\{?CLAUDE_PROJECT_DIR\}?|"""
    r"""\$\(git rev-parse --show-toplevel\))/""")
SELFDIR_RE = re.compile(r"""\$\(\s*dirname\s+["']?\$(?:0|\{0\}|\{BASH_SOURCE\[0\]\}|\{BASH_SOURCE\}|BASH_SOURCE)["']?\s*\)""")
SELFDIR = "__SELFDIR__"
SHELL_LOAD_RE = re.compile(r"""^\s*(?:source|\.)\s+(\S+)""", re.MULTILINE)
SHELL_EXEC_RE = re.compile(
    r"""(?:^|[\s;&|(])(?:bash|sh|zsh|python3?|node|ruby|perl|uv run|exec)\s+((?:-\S+\s+)*)([^\s;&|)]+)""",
    re.MULTILINE)
QUOTED_VAR = re.compile(r"""["'](\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)["']""")
DYNAMIC_CALLS = {"import_module", "__import__", "run_path", "run_module", "spec_from_file_location",
                 "SourceFileLoader", "load_source"}


def _clean(tok: str) -> str:
    return tok.strip("\"'()[]{}@,;:")


def _normjoin(base: str, rel: str) -> str | None:
    p = posixpath.normpath(posixpath.join(base, rel)) if base else posixpath.normpath(rel)
    if p.startswith("../") or p == ".." or p.startswith("/"):
        return None
    return "" if p == "." else p


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
        self.unresolved: list[str] = []
        self.queue: list[str] = []

    # -- adding --------------------------------------------------------
    def add(self, path: str, why: str) -> bool:
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
                    if p.startswith(pre) and p not in self.files:
                        self.files.add(p)
                        self.queue.append(p)
            return True
        return False

    def try_paths(self, rel: str, src: str) -> bool:
        """Resolve `rel` against the repo root and against src's directory and its ancestors."""
        rel = KNOWN_PREFIXES.sub("", rel)
        if rel.startswith("./"):
            rel = rel[2:]
        rel = rel.lstrip("/")  # "/tools/x" read as repo-relative: over-matching only costs availability
        if not rel or "$" in rel or any(c in rel for c in "*?"):
            return False
        d = posixpath.dirname(src)
        bases = [""]
        while d:
            bases.append(d)
            d = posixpath.dirname(d)
        for b in bases:
            p = _normjoin(b, rel)
            if p and self.add(p, src):
                return True
        return False

    # -- scanning ------------------------------------------------------
    def scan_text(self, src: str, text: str) -> None:
        # Unquote "$VAR"/'$VAR' and JSON-escaped quotes so "$CLAUDE_PROJECT_DIR"/x reads as one token.
        text = QUOTED_VAR.sub(r"\1", text.replace('\\"', '"'))
        for raw in TOKEN_RE.findall(text):
            tok = _clean(raw)
            if tok and ("$" not in tok or KNOWN_PREFIXES.match(tok)):
                self.try_paths(tok, src)
        self.scan_shell(src, text)

    def scan_shell(self, src: str, text: str) -> None:
        text = SELFDIR_RE.sub(SELFDIR, text)
        args = [m.group(1) for m in SHELL_LOAD_RE.finditer(text)]
        args += [m.group(2) for m in SHELL_EXEC_RE.finditer(text)]
        for a in args:
            a = _clean(a)
            if "$" not in a and SELFDIR not in a:
                continue
            d = posixpath.dirname(src)
            resolved = a.replace(SELFDIR + "/", d + "/" if d else "", 1) if a.startswith(SELFDIR + "/") else a
            resolved = KNOWN_PREFIXES.sub("", resolved)
            if SELFDIR in resolved:
                resolved = "$" + resolved  # self-dir not at the start: unresolved
            if "$" in resolved or not self.try_paths(resolved, src):
                self.unresolved.append(f"{src}: dynamic shell reference {a!r}")

    def scan_python(self, src: str, text: str) -> None:
        try:
            tree = ast.parse(text, filename=src)
        except (SyntaxError, ValueError) as e:
            self.unresolved.append(f"{src}: cannot parse as Python ({type(e).__name__})")
            return
        pkg = posixpath.dirname(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.resolve_module(a.name, src, 0, pkg)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                self.resolve_module(mod, src, node.level, pkg)
                for a in node.names:
                    if a.name != "*":
                        self.resolve_module(f"{mod}.{a.name}" if mod else a.name, src, node.level, pkg)
            elif isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else None
                if name in DYNAMIC_CALLS:
                    self.resolve_dynamic(node, src, pkg, name)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.scan_text_tokens(src, node.value)

    def scan_text_tokens(self, src: str, s: str) -> None:
        for raw in TOKEN_RE.findall(s):
            tok = _clean(raw)
            if tok and "$" not in tok:
                self.try_paths(tok, src)

    def resolve_module(self, name: str, src: str, level: int, pkg: str) -> None:
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
                        self.add(cand, src)
        # Not found in the tree: stdlib or a third-party package (manifests are on the floor).

    def resolve_dynamic(self, call: ast.Call, src: str, pkg: str, name: str) -> None:
        consts = [n.value for a in list(call.args) + [k.value for k in call.keywords]
                  for n in ast.walk(a) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        found = False
        if name in ("import_module", "__import__", "run_module"):
            first = call.args[0] if call.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                mod = first.value
                self.resolve_module(mod.lstrip("."), src, len(mod) - len(mod.lstrip(".")), pkg)
                found = True  # a literal name: repo module added, or stdlib/third-party
        else:
            for cand in consts + (["/".join(consts)] if len(consts) > 1 else []):
                if self.try_paths(cand, src):
                    found = True
        if not found:
            self.unresolved.append(f"{src}: dynamic {name}() reference not resolvable to a literal path")

    def scan(self, path: str) -> None:
        mode = self.tree.get(path)
        if mode == SUBMODULE_MODE:
            self.unresolved.append(f"{path}: submodule reached by derivation")
            return
        try:
            blob = self.read(path)
        except Exception as e:  # noqa: BLE001
            self.unresolved.append(f"{path}: cannot read ({type(e).__name__})")
            return
        if mode == SYMLINK_MODE:
            target = _normjoin(posixpath.dirname(path), blob.decode("utf-8", "surrogateescape"))
            if target is None or not self.add(target, path):
                self.unresolved.append(f"{path}: symlink target outside the repo or missing")
            return
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            return  # binary: nothing to follow
        first = text.split("\n", 1)[0]
        if path.endswith(".py") or (first.startswith("#!") and "python" in first):
            self.scan_python(path, text)
        else:
            self.scan_text(path, text)

    def run(self) -> tuple[list[str], list[str]]:
        roots = self.config["derive_roots"]
        for p in sorted(self.tree):
            if self.matches(p, roots):
                self.add(p, "root")
        seen: set[str] = set()
        while self.queue:
            p = self.queue.pop()
            if p in seen:
                continue
            seen.add(p)
            self.scan(p)
        patterns = list(self.config["floor_7a"]) + sorted(self.dir_globs) + sorted(self.files)
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
            reasons.append(f"symlink or submodule change: {c.path}")
        elif matches(c.path, patterns):
            reasons.append(f"7a path: {c.path}")
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

    def skip(self, n: int, head: str, reason: str) -> str:
        log(f"SKIP pr={n} head={head} reason={reason}")
        return "skipped"

    def prepare_7a(self, branch: str) -> list[str]:
        """Fetch the default branch and derive the 7a set from it. Raises DeriveError."""
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
        return patterns

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
            return self.skip(n, head, str(e))
        if pr.get("state") != "open":
            return self.skip(n, head, f"state {pr.get('state')!r}")
        if cfg["auto_merge_label"] not in labels:
            return self.skip(n, head, f"no {cfg['auto_merge_label']!r} label")
        if cfg["kill_label"] in labels:
            return self.skip(n, head, f"{cfg['kill_label']!r} label present")
        if cfg["operator_merge_label"] in labels:
            return self.skip(n, head, f"{cfg['operator_merge_label']!r} label present (operator merges)")
        if (((pr.get("head") or {}).get("repo")) or {}).get("full_name") != repo:
            return self.skip(n, head, "head repository is not this repository (fork PRs are never merged)")
        if (pr.get("base") or {}).get("ref") != branch:
            return self.skip(n, head, f"base is not {branch!r}")

        # 4. Verdict, recomputed inline at H.
        try:
            res = self.v.fetch_and_compute(self.gh, repo, n, self.vcfg)
        except Exception as e:  # noqa: BLE001 - VerdictError or anything else: fail closed
            res = self.v.Result(passed=False, head_sha=head,
                                reasons=[f"cannot compute verdict (fail closed): {type(e).__name__}: {e}"])
        ok = bool(res.passed) and res.head_sha == head
        log(f"VERDICT-INLINE pr={n} head={head} verdict_head={res.head_sha} "
            f"result={'PASS' if ok else 'FAIL'} weight={res.weight} {self.ctx.tag()}")
        for line in res.render().splitlines():
            log(f"  {line}")
        if not ok:
            why = "verdict head differs from H" if res.passed else "verdict FAIL"
            return self.skip(n, head, why)

        # 5. 7a path check.
        if self.patterns is None:
            self.patterns = self.prepare_7a(branch)
        try:
            fetched = self.git.fetch(f"refs/pull/{n}/head", f"refs/e5/pr/{n}")
            if fetched != head:
                return self.skip(n, head, f"fetched head {fetched} is not H (head moved)")
            mb = self.git.merge_base(self.base_sha, head)
            changes = self.git.diff(mb, head)
        except GitError as e:
            return self.skip(n, head, f"7a check could not complete (fail closed): {e}")
        hits = check_7a(changes, self.patterns, self.v.matches_any)
        if hits:
            for h in hits[:20]:
                log(f"  7a: {h}")
            return self.skip(n, head, "touches a 7a path; skip (operator merges)")
        log(f"7A-CLEAR pr={n} head={head} merge_base={mb} files={len(changes)}")

        # 6. Label kill switch and head, re-read now.
        again = self.gh.get(f"repos/{repo}/pulls/{n}")
        now_labels = label_names(self.gh.paged(f"repos/{repo}/issues/{n}/labels"))
        if (again.get("head") or {}).get("sha") != head:
            return self.skip(n, head, "head moved before merge")
        if again.get("state") != "open":
            return self.skip(n, head, "closed before merge")
        if cfg["kill_label"] in now_labels:
            return self.skip(n, head, f"{cfg['kill_label']!r} label present (re-read before merge)")
        if cfg["auto_merge_label"] not in now_labels or cfg["operator_merge_label"] in now_labels:
            return self.skip(n, head, "labels changed before merge")

        # 7. Merge, pinned to H.
        merged, msg = self.merger(repo, n, head, cfg["merge_method"])
        if merged:
            log(f"MERGED pr={n} head={head} {self.ctx.tag()}")
            return "merged"
        log(f"merge refused: pr={n} head={head} reason={msg}")
        return "refused"

    def run(self, kill_value: str | None) -> int:
        ctx = self.ctx
        log(f"PROVENANCE workflow_ref={ctx.workflow_ref} workflow_sha={ctx.workflow_sha} "
            f"run_id={ctx.run_id} event={ctx.event}")
        if not kill_switch_allows(kill_value):
            log(f"KILL SWITCH: AUTO_MERGE_ENABLED={kill_value!r} is not exactly 'true'; no merges")
            return 0
        branch = self.cfg["default_branch"]
        if ctx.event not in ("pull_request_target", "schedule") \
                or ctx.workflow_ref != expected_workflow_ref(ctx.repo, branch):
            log(f"REFUSED: event={ctx.event} workflow_ref={ctx.workflow_ref}; expected pull_request_target or "
                f"schedule from {expected_workflow_ref(ctx.repo, branch)}")
            return 1
        try:
            meta = self.gh.get(f"repos/{ctx.repo}")
            if meta.get("default_branch") != branch:
                log(f"REFUSED: repository default branch {meta.get('default_branch')!r} is not {branch!r}")
                return 1
            q = f"repos/{ctx.repo}/pulls?state=open&base={branch}"
            prs = self.gh.paged(q, limit=10)
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
        cands = sorted(cands)[: self.cfg["max_candidates"]]
        log(f"CANDIDATES {cands}")
        for n in cands:
            try:
                self.process(n, branch)
            except DeriveError as e:
                log(f"SKIP pr={n} head=? reason={e}")
                log("REFUSED: 7a set unavailable; no merges this run (fail closed)")
                return 1
            except Exception as e:  # noqa: BLE001 - one bad PR never merges, never stops the others
                log(f"SKIP pr={n} head=? reason=error (fail closed): {type(e).__name__}: {e}")
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
