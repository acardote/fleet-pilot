#!/usr/bin/env python3
"""review-verdict: the E5 verdict function (acardote/personal-assistant-ultra#579).

Design: acardote/personal-assistant-ultra docs/design/merge-model.md, section 2
(verdict workflow) and section 3 step 4 (verdict, recomputed inline at head H).
The merge workflow (#580) is meant to import `compute_verdict` and run the same
function inline in its own run.

The verdict passes only if ALL of these hold at the PR's current head H:
  0. the PR is open, not a draft, based on the default branch, and its head
     repository is the base repository (fork PRs never pass);
  1. the objective weight can be recomputed (fail closed otherwise) and the PR
     carries exactly one weight label that is not lighter than it (A7). The
     recompute matches security-boundary paths case-insensitively, treats a
     changed symlink or submodule, any symlink at a security-boundary path, and
     any binary or mode-only change (no patch, 0 LOC) as heavy;
  2. every reviewer in the review set for max(label, objective) has a latest
     `VERDICT: pass` record naming sha=H, from a trusted record author;
  3. no `critical` is open. A critical closes only on a `VERIFY: pass` record
     from a reviewer agent other than the PR's author, at a fix SHA that is a
     strict descendant (by the commits' parent links) of the critical's SHA,
     both in the PR's current commit list (A9). If the critical's SHA is no
     longer a commit of the PR (rebase, amend, force-push, typo), no VERIFY can
     close it: the raising reviewer re-raises it at a current SHA first. A
     false-positive critical is withdrawn the same way, which needs a new
     commit (and so a fresh review round at the new head). An author's "fixed"
     comment is not a record and closes nothing. A critical id is unique per
     PR: reuse by a different reviewer fails closed;
  4. every required CI workflow has a completed `push` run with head_sha == H,
     head_branch == the PR's head ref, head and run repository == this
     repository, the expected workflow path, and conclusion `success`, read
     from the Actions runs API (never from check-run names or statuses).
     A push run's workflow definition is the file in H's own tree, so the run
     counts only if H's blob for that path equals the default branch's blob.
     `pull_request` runs never count: their definition comes from a merge
     commit with whatever base triggered them (possibly another PR's base),
     and the runs API exposes neither that merge commit nor the base, so the
     definition cannot be established (fail closed). Consequence: CI is
     evidence about H itself, not about H merged with the current base;
  5. H did not move while the verdict was computed.

Record formats (one per line, starting in column 0, full 40-hex SHAs):
  VERDICT: <pass|fail> reviewer=<agent> sha=<H>
  CRITICAL: id=<id> reviewer=<agent> sha=<sha>
  VERIFY: <pass|fail> closes=<id> reviewer=<agent> sha=<fix-sha>

Records are read from PR issue comments, submitted PR review bodies and PR
review (inline) comments authored by a login in `trusted_record_authors`.
Every other author is ignored, whatever it says. Lines inside fenced code,
HTML comments, block quotes or indented lines are never records. In a
trusted comment, any line that looks like a CRITICAL but is not a live,
well-formed record fails the verdict closed ("unparseable critical"), unless
it is a quote of a live CRITICAL with the same id and SHA. A trusted comment
that carries record-like text and was edited after posting fails closed.
Deleted comments cannot be detected by a stateless check; that is an audit
job. No check run or commit status is read.

The function contract for importers (#580): `compute_verdict` never raises
and returns a Result with passed=False on any problem; `fetch_and_compute`
raises only VerdictError. Neither checks mergeability. To import this file
by path, register the module in sys.modules before exec_module (dataclasses
needs it): spec_from_file_location -> module_from_spec -> sys.modules[name] =
mod -> spec.loader.exec_module(mod).

Stdlib only: this runs on a bare runner from default-branch code and installs
nothing. Exit 0 = pass, 1 = fail, 2 = could not compute (fail closed).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

SHA_RE = r"[0-9a-f]{40}"
_SHA = r"[0-9a-fA-F]{40}"
_ID = r"[A-Za-z0-9._-]+"
VERDICT_RE = re.compile(rf"^VERDICT:[ \t]+(pass|fail)[ \t]+reviewer=({_ID})[ \t]+sha=({_SHA})[ \t]*$")
CRITICAL_RE = re.compile(rf"^CRITICAL:[ \t]+id=({_ID})[ \t]+reviewer=({_ID})[ \t]+sha=({_SHA})[ \t]*$")
VERIFY_RE = re.compile(
    rf"^VERIFY:[ \t]+(pass|fail)[ \t]+closes=({_ID})[ \t]+reviewer=({_ID})[ \t]+sha=({_SHA})[ \t]*$"
)
# Anything that looks like a critical record, in any formatting.
CRITICAL_LIKE_RE = re.compile(r"(?i)\bcritical\b.*\b(?:id|reviewer|sha)[ \t]*=")
RECORD_LIKE_RE = re.compile(r"(?i)\b(?:verdict|critical|verify)\b.*\b(?:reviewer|sha)[ \t]*=")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
RETRY_STATUS = {429, 500, 502, 503, 504}
AUTHOR_AGENT_RE = re.compile(r"^[ \t]*Author-Agent:[ \t]*([A-Za-z0-9._-]+)[ \t]*$", re.MULTILINE)


class VerdictError(Exception):
    """The verdict cannot be computed. Callers must treat this as a failure."""


@dataclass
class Result:
    passed: bool
    head_sha: str | None = None
    weight: str | None = None
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        head = self.head_sha or "?"
        lines = [
            f"review-verdict: {'PASS' if self.passed else 'FAIL'} head={head} weight={self.weight or '?'}"
        ]
        lines += [f"- FAIL: {r}" for r in self.reasons]
        lines += [f"- note: {n}" for n in self.notes]
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Objective weight recompute (A7)
# --------------------------------------------------------------------------

def _norm(s: str) -> str:
    """Case- and Unicode-insensitive form: the operator's checkouts are on
    case-insensitive, normalization-insensitive filesystems (APFS)."""
    return unicodedata.normalize("NFKC", s).casefold()


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    pattern = _norm(pattern)
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def matches_any(path: str, patterns: list[str]) -> bool:
    """True if `path`, or `path` taken as a directory (a bare `.husky` against
    `.husky/**`), matches a pattern. Case- and normalization-insensitive."""
    p = _norm(path)
    return any(glob_to_regex(pat).match(cand) for pat in patterns for cand in (p, p + "/"))


SYMLINK_MODE = "120000"
SUBMODULE_MODE = "160000"


def tree_entries(tree: dict) -> dict[str, dict]:
    """Path -> entry of a recursive git tree at H. Fails closed if incomplete."""
    if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
        raise VerdictError("tree at head: missing or malformed")
    if tree.get("truncated") is not False:
        raise VerdictError("tree at head: truncated or completeness unknown")
    out: dict[str, dict] = {}
    for e in tree["tree"]:
        if not isinstance(e, dict) or not isinstance(e.get("path"), str):
            raise VerdictError("tree at head: malformed entry")
        out[e["path"]] = e
    return out


def recompute_weight(pr: dict, files: list[dict], tree: dict[str, dict],
                     config: dict) -> tuple[str, list[str]]:
    """Return (weight, why). Raises VerdictError when it cannot compute (fail closed)."""
    tiers = config["weight_tiers"]
    th = config["weight_thresholds"]
    heavy_paths = config["heavy_paths"]
    for key in ("additions", "deletions", "changed_files"):
        if not isinstance(pr.get(key), int) or pr[key] < 0:
            raise VerdictError(f"weight: PR field {key!r} missing or invalid")
    changed = pr["changed_files"]
    if changed >= config["max_pr_files"]:
        raise VerdictError(
            f"weight: PR changes {changed} files, at or over the {config['max_pr_files']}-file API cap"
        )
    if len(files) != changed:
        raise VerdictError(
            f"weight: file list incomplete ({len(files)} listed, PR reports {changed})"
        )
    paths: list[str] = []
    opaque: list[str] = []  # binary or mode-only changes: 0 LOC, no patch
    special: list[str] = []  # changed symlinks / submodules
    for f in files:
        name = f.get("filename")
        if not isinstance(name, str) or not name:
            raise VerdictError("weight: a changed file has no filename")
        paths.append(name)
        prev = f.get("previous_filename")
        if isinstance(prev, str) and prev:
            paths.append(prev)  # a rename touches both sides
        if f.get("status") != "removed":
            if "patch" not in f and (f.get("additions") or 0) + (f.get("deletions") or 0) == 0:
                opaque.append(name)
            if (tree.get(name) or {}).get("mode") in (SYMLINK_MODE, SUBMODULE_MODE):
                special.append(name)
    loc = pr["additions"] + pr["deletions"]
    why: list[str] = []
    level = 0  # index into tiers; most restrictive criterion wins

    def show(xs: list[str]) -> str:
        xs = sorted(set(xs))
        return ", ".join(xs[:5]) + (" ..." if len(xs) > 5 else "")

    if loc > th["standard_max_loc"]:
        level = max(level, 2)
        why.append(f"loc={loc}>{th['standard_max_loc']}")
    elif loc > th["trivial_max_loc"]:
        level = max(level, 1)
        why.append(f"loc={loc}>{th['trivial_max_loc']}")
    if len(set(paths)) > th["trivial_max_files"]:
        level = max(level, 1)
        why.append(f"files={len(set(paths))}>{th['trivial_max_files']}")
    heavy_hits = [p for p in paths if matches_any(p, heavy_paths)]
    if heavy_hits:
        level = max(level, 2)
        why.append(f"security-boundary paths: {show(heavy_hits)}")
    if special:
        level = max(level, 2)
        why.append(f"symlink or submodule changed: {show(special)}")
    if opaque:
        level = max(level, 2)
        why.append(f"binary or mode-only change (no patch, 0 LOC): {show(opaque)}")
    # A symlink at a security-boundary path redirects later, non-heavy edits.
    heavy_links = [p for p, e in tree.items() if e.get("mode") == SYMLINK_MODE and matches_any(p, heavy_paths)]
    if heavy_links:
        level = max(level, 2)
        why.append(f"symlink at a security-boundary path in the tree: {show(heavy_links)}")
    if not why:
        why.append(f"loc={loc}, files={len(set(paths))}")
    return tiers[level], why


def declared_weight(labels: list[str], config: dict) -> str:
    prefix = config["weight_label_prefix"]
    found = [l[len(prefix):] for l in labels if l.startswith(prefix)]
    if len(found) != 1:
        raise VerdictError(
            f"weight: expected exactly one '{prefix}<tier>' label, found {len(found)}"
        )
    if found[0] not in config["weight_tiers"]:
        raise VerdictError(f"weight: unknown weight label '{prefix}{found[0]}'")
    return found[0]


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

@dataclass
class Record:
    kind: str  # VERDICT | CRITICAL | VERIFY
    result: str | None
    reviewer: str
    sha: str
    closes: str | None
    crit_id: str | None
    created_at: str
    order: int  # tiebreaker: comment order, then line order
    author: str


def split_live(body: str) -> tuple[list[str], list[str]]:
    """Split a markdown body into (live lines, non-live lines).

    Live lines are outside fenced code and HTML comments, are not block
    quotes, and do not start with whitespace. Only live lines can be records.
    An unclosed fence or comment runs to the end of the body (CommonMark)."""
    body = body.replace("\r\n", "\n").replace("\r", "\n")
    hidden: list[str] = []

    def _hide(m: re.Match[str]) -> str:
        hidden.extend(m.group(0).split("\n"))
        return "\n" * m.group(0).count("\n")

    body = re.sub(r"<!--.*?(?:-->|\Z)", _hide, body, flags=re.S)
    live: list[str] = []
    other: list[str] = list(hidden)
    fence: str | None = None
    for line in body.split("\n"):
        m = FENCE_RE.match(line)
        if fence is not None:
            other.append(line)
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) \
                    and not line.strip()[len(m.group(1)):].strip():
                fence = None
            continue
        if m:
            fence = m.group(1)
            other.append(line)
            continue
        if line[:1] in (" ", "\t", ">"):
            other.append(line)
        else:
            live.append(line)
    return live, other


def _strict(line: str) -> tuple[str, re.Match[str]] | None:
    for kind, rx in (("VERDICT", VERDICT_RE), ("CRITICAL", CRITICAL_RE), ("VERIFY", VERIFY_RE)):
        m = rx.match(line)
        if m:
            return kind, m
    return None


def normalize_sources(comments: list[dict], reviews: list[dict], review_comments: list[dict]) -> list[dict]:
    """One list of {body, user, created_at, updated_at, where} from the three
    places a reviewer can write on a PR. Pending (unsubmitted) reviews are
    invisible to others and are skipped."""
    out: list[dict] = []
    for c in comments:
        out.append({**c, "where": "issue comment"})
    for r in reviews:
        if r.get("state") == "PENDING":
            continue
        out.append({"body": r.get("body"), "user": r.get("user"), "created_at": r.get("submitted_at"),
                    "updated_at": None, "where": "review"})
    for c in review_comments:
        out.append({**c, "where": "review comment"})
    return out


def parse_records(comments: list[dict], trusted: set[str]) -> tuple[list[Record], list[str], list[str]]:
    """Return (records, notes, fail-closed reasons)."""
    records: list[Record] = []
    reasons: list[str] = []
    ignored: dict[str, int] = {}
    quoted_crits: list[tuple[str, str, str]] = []  # (id, sha, login)
    ordered = sorted(enumerate(comments), key=lambda ic: (ic[1].get("created_at") or "", ic[0]))
    seq = 0
    for _, c in ordered:
        body = c.get("body") or ""
        login = ((c.get("user") or {}).get("login")) or ""
        created = c.get("created_at") or ""
        where = c.get("where") or "comment"
        live, other = split_live(body)
        found: list[Record] = []
        for line in live:
            hit = _strict(line)
            if hit:
                kind, m = hit
                if kind == "VERDICT":
                    found.append(Record("VERDICT", m.group(1), m.group(2), m.group(3).lower(), None, None, created, 0, login))
                elif kind == "CRITICAL":
                    found.append(Record("CRITICAL", None, m.group(2), m.group(3).lower(), None, m.group(1), created, 0, login))
                else:
                    found.append(Record("VERIFY", m.group(1), m.group(3), m.group(4).lower(), m.group(2), None, created, 0, login))
        if login not in trusted:
            if found:
                ignored[login] = ignored.get(login, 0) + len(found)
            continue
        # Fail closed on anything that looks like a critical but is not a live record.
        for line in live:
            hit = _strict(line)
            if CRITICAL_LIKE_RE.search(line) and not (hit and hit[0] == "CRITICAL"):
                reasons.append(f"unparseable critical in {where} by {login!r} at {created}: {line.strip()[:80]!r}")
        for line in other:
            if CRITICAL_LIKE_RE.search(line):
                m = CRITICAL_RE.match(line.lstrip(" \t>"))
                if m:
                    quoted_crits.append((m.group(1), m.group(3).lower(), login))
                else:
                    reasons.append(
                        f"unparseable critical (quoted, fenced, indented or hidden) in {where} by {login!r} "
                        f"at {created}: {line.strip()[:80]!r}"
                    )
        # Records in an edited comment are void, and void records fail closed.
        upd = c.get("updated_at")
        if upd and created and upd != created and any(RECORD_LIKE_RE.search(l) for l in live + other):
            reasons.append(f"{where} by {login!r} at {created} carries records and was edited at {upd}; "
                           "post records in a new comment and delete the edited one")
            continue
        for rec in found:
            rec.order = seq
            seq += 1
            records.append(rec)
    live_crits = {(r.crit_id, r.sha) for r in records if r.kind == "CRITICAL"}
    for cid, sha, login in quoted_crits:
        if (cid, sha) not in live_crits:
            reasons.append(f"critical {cid!r} at {sha[:12]} appears only quoted/fenced/hidden (by {login!r}); "
                           "post it as a live record")
    notes = [f"ignored {n} record(s) from untrusted author {who!r}" for who, n in sorted(ignored.items())]
    return records, notes, reasons


def author_agents_for(pr: dict, config: dict) -> set[str]:
    names = set(config["author_agents"])
    names.update(AUTHOR_AGENT_RE.findall(pr.get("body") or ""))
    return names


def parent_map(commits: list[dict]) -> dict[str, list[str]]:
    """sha -> parent shas, for the PR's own commits."""
    out: dict[str, list[str]] = {}
    for c in commits:
        sha = c.get("sha")
        if not isinstance(sha, str):
            raise VerdictError("a PR commit has no sha")
        out[sha] = [p.get("sha") for p in (c.get("parents") or []) if isinstance(p, dict)]
    return out


def is_strict_descendant(desc: str, anc: str, parents: dict[str, list[str]]) -> bool:
    """True if `anc` is reachable from `desc` through parent links, desc != anc,
    both in the PR's commit list. Every commit on such a path is itself a PR
    commit, so the PR's commit list is enough to decide."""
    if desc == anc or desc not in parents or anc not in parents:
        return False
    seen = {desc}
    stack = [desc]
    while stack:
        for p in parents.get(stack.pop(), []):
            if p == anc:
                return True
            if p in parents and p not in seen:
                seen.add(p)
                stack.append(p)
    return False


def open_criticals(records: list[Record], parents: dict[str, list[str]], authors: set[str],
                   reviewers: set[str]) -> tuple[list[str], list[str], list[str]]:
    """Replay CRITICAL/VERIFY records in order; return (open ids, notes, reasons)."""
    state: dict[str, dict[str, Any]] = {}
    notes: list[str] = []
    reasons: list[str] = []
    for rec in records:
        if rec.kind == "CRITICAL":
            prev = state.get(rec.crit_id)
            if prev and prev["reviewer"] != rec.reviewer:
                reasons.append(f"critical id {rec.crit_id!r} raised by {prev['reviewer']!r} was reused by "
                               f"{rec.reviewer!r}; ids must be unique per PR")
                prev["open"] = True
                continue
            state[rec.crit_id] = {"open": True, "sha": rec.sha, "reviewer": rec.reviewer}
        elif rec.kind == "VERIFY":
            cid = rec.closes
            if cid not in state:
                notes.append(f"VERIFY for unknown critical {cid!r} ignored")
                continue
            crit_sha = state[cid]["sha"]
            if rec.reviewer in authors:
                notes.append(f"VERIFY {cid!r} by author agent {rec.reviewer!r} ignored")
                continue
            if rec.reviewer not in reviewers:
                notes.append(f"VERIFY {cid!r} by non-reviewer {rec.reviewer!r} ignored")
                continue
            if crit_sha not in parents:
                notes.append(f"critical {cid!r} SHA {crit_sha[:12]} is not a commit of this PR "
                             "(rebased or force-pushed?); no VERIFY can close it until it is re-raised at a current SHA")
                continue
            if rec.sha not in parents:
                notes.append(f"VERIFY {cid!r} at {rec.sha[:12]} not a commit of this PR; ignored")
                continue
            if not is_strict_descendant(rec.sha, crit_sha, parents):
                notes.append(f"VERIFY {cid!r} at {rec.sha[:12]} is not a descendant of the critical's SHA; ignored")
                continue
            state[cid]["open"] = rec.result != "pass"
    return sorted(cid for cid, s in state.items() if s["open"]), notes, reasons


# --------------------------------------------------------------------------
# The verdict function (pure: all inputs already fetched)
# --------------------------------------------------------------------------

def compute_verdict(*, repo: str, pr: dict, files: list[dict], commits: list[dict],
                    comments: list[dict], reviews: list[dict], review_comments: list[dict],
                    tree: dict, default_ci_blobs: dict[str, str | None],
                    runs: list[dict], config: dict) -> Result:
    """Never raises. Any input it cannot use makes the result a failure.

    tree: the raw `git/trees/{H}?recursive=1` response.
    default_ci_blobs: required CI workflow path -> blob SHA on the default
    branch (None when absent or unreadable).
    runs: Actions runs with head_sha == H (any event; only `push` counts)."""
    res = Result(passed=False)
    try:
        head = (pr.get("head") or {}).get("sha")
        if not isinstance(head, str) or not re.fullmatch(SHA_RE, head):
            raise VerdictError("PR head SHA missing or malformed")
        res.head_sha = head
        head_ref = (pr.get("head") or {}).get("ref")
        if not isinstance(head_ref, str) or not head_ref:
            raise VerdictError("PR head ref missing")

        # 0. PR context.
        if pr.get("state") != "open":
            res.reasons.append(f"PR state is {pr.get('state')!r}, not open")
        if pr.get("draft") is not False:
            res.reasons.append(f"PR draft flag is {pr.get('draft')!r}, not false")
        head_repo = (((pr.get("head") or {}).get("repo")) or {}).get("full_name")
        if head_repo != repo:
            res.reasons.append(f"head repository {head_repo!r} is not {repo!r} (fork PRs never pass)")
        base = pr.get("base") or {}
        base_repo = base.get("repo") or {}
        if base_repo.get("full_name") != repo:
            res.reasons.append(f"base repository {base_repo.get('full_name')!r} is not {repo!r}")
        default_branch = base_repo.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            raise VerdictError("default branch unknown")
        if base.get("ref") != default_branch:
            res.reasons.append(f"PR base {base.get('ref')!r} is not the default branch {default_branch!r}")

        entries = tree_entries(tree)

        # 1. weight (A7): objective recompute, fail closed; a lighter label fails.
        tiers = config["weight_tiers"]
        objective, why = recompute_weight(pr, files, entries, config)
        labels = [l.get("name", "") for l in pr.get("labels") or []]
        declared = declared_weight(labels, config)
        res.notes.append(f"objective weight {objective} ({'; '.join(why)}); label weight {declared}")
        if tiers.index(declared) < tiers.index(objective):
            res.reasons.append(f"labelled weight:{declared} is lighter than objective weight {objective}")
        weight = tiers[max(tiers.index(declared), tiers.index(objective))]
        res.weight = weight

        # Records from trusted authors only.
        sources = normalize_sources(comments, reviews, review_comments)
        records, notes, rec_reasons = parse_records(sources, set(config["trusted_record_authors"]))
        res.notes += notes
        res.reasons += rec_reasons
        authors = author_agents_for(pr, config)
        reviewers = set(config["reviewer_agents"]) - authors

        # 2. full review set for the weight, each at H.
        required = config["review_sets"].get(weight)
        if not required:
            raise VerdictError(f"no review set configured for weight {weight!r}")
        for r in required:
            if r in authors:
                raise VerdictError(f"review set for {weight} names author agent {r!r}")
            at_head = [x for x in records if x.kind == "VERDICT" and x.reviewer == r and x.sha == head]
            if not at_head:
                res.reasons.append(f"no VERDICT from {r} at head {head[:12]}")
            elif at_head[-1].result != "pass":
                res.reasons.append(f"latest VERDICT from {r} at head {head[:12]} is {at_head[-1].result}")

        # 3. no open critical; closure only by a verify-only reviewer verdict at a descendant (A9).
        if len(commits) != pr.get("commits"):
            if (pr.get("commits") or 0) >= config["max_pr_commits"]:
                raise VerdictError(f"PR has {pr.get('commits')} commits, at or over the API cap")
            raise VerdictError(f"commit list incomplete ({len(commits)} listed, PR reports {pr.get('commits')})")
        parents = parent_map(commits)
        if head not in parents:
            raise VerdictError("PR commit list does not contain the head SHA")
        still_open, crit_notes, crit_reasons = open_criticals(records, parents, authors, reviewers)
        res.notes += crit_notes
        res.reasons += crit_reasons
        for cid in still_open:
            res.reasons.append(f"critical {cid!r} is open (closes only on a VERIFY pass by a non-author "
                               "reviewer at a descendant of the critical's SHA in this PR)")

        # 4. CI green at H: push runs, whose definition (H's tree) is the default branch's.
        required_ci = config["required_ci_workflows"]
        if not required_ci:
            raise VerdictError("no required CI workflows configured")
        for path in required_ci:
            want = default_ci_blobs.get(path)
            entry = entries.get(path) or {}
            have = entry.get("sha") if entry.get("type") == "blob" and entry.get("mode") != SYMLINK_MODE else None
            if not isinstance(want, str) or not re.fullmatch(SHA_RE, want):
                res.reasons.append(f"CI {path}: no blob on the default branch {default_branch!r}; cannot establish its definition")
                continue
            if have != want:
                res.reasons.append(f"CI {path}: definition at head (blob {str(have)[:12]}) is not the default "
                                   f"branch's (blob {want[:12]}); its runs cannot count")
                continue
            candidates = [
                run for run in runs
                if run.get("path") == path and run.get("head_sha") == head
                and run.get("event") == "push"
                and run.get("head_branch") == head_ref
                and (((run.get("head_repository") or {}).get("full_name")) == repo)
                and (((run.get("repository") or {}).get("full_name")) == repo)
            ]
            if not candidates:
                res.reasons.append(f"CI {path}: no push run on {head_ref!r} at head {head[:12]}")
                continue
            latest = max(candidates, key=lambda r: (r.get("created_at") or "", r.get("run_attempt") or 0, r.get("id") or 0))
            if latest.get("status") != "completed" or latest.get("conclusion") != "success":
                res.reasons.append(
                    f"CI {path}: latest run {latest.get('id')} is {latest.get('status')}/{latest.get('conclusion')}"
                )
    except VerdictError as e:
        res.reasons.append(f"cannot compute verdict (fail closed): {e}")
    except Exception as e:  # noqa: BLE001 - importers rely on "never raises"
        res.reasons.append(f"cannot compute verdict (fail closed): {type(e).__name__}: {e}")
    res.passed = not res.reasons
    return res


# --------------------------------------------------------------------------
# GitHub I/O (read-only)
# --------------------------------------------------------------------------

class GitHub:
    def __init__(self, token: str, api: str = "https://api.github.com",
                 opener: Callable[..., Any] | None = None, attempts: int = 3,
                 sleep: Callable[[float], None] = time.sleep):
        self.token = token
        self.api = api.rstrip("/")
        self.opener = opener or urllib.request.urlopen
        self.attempts = attempts
        self.sleep = sleep

    def _get(self, url: str) -> tuple[Any, str | None]:
        """GET with retry on 429/5xx and transport errors. Raises only VerdictError."""
        if not url.startswith(self.api + "/"):
            raise VerdictError(f"refusing to send the token to {url.split('?')[0]!r}: not under {self.api}")
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "review-verdict",
        })
        short = url.split("?")[0]
        last: BaseException | None = None
        for attempt in range(self.attempts):
            try:
                with self.opener(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    link = resp.headers.get("Link")
                break
            except urllib.error.HTTPError as e:
                last = e
                if e.code not in RETRY_STATUS:
                    raise VerdictError(f"GET {short} failed: HTTP {e.code}") from e
            except Exception as e:  # noqa: BLE001 - every transport/parse error fails closed
                last = e
            if attempt + 1 < self.attempts:
                self.sleep(2 ** attempt)
        else:
            raise VerdictError(f"GET {short} failed after {self.attempts} attempts: {type(last).__name__}: {last}")
        nxt = None
        if link:
            for part in link.split(","):
                seg = part.split(";")
                if len(seg) >= 2 and seg[1].strip() == 'rel="next"':
                    nxt = seg[0].strip()[1:-1]
        return data, nxt

    def get(self, path: str) -> Any:
        return self._get(f"{self.api}/{path}")[0]

    def paged(self, path: str, key: str | None = None, limit: int = 100) -> list:
        sep = "&" if "?" in path else "?"
        url: str | None = f"{self.api}/{path}{sep}per_page=100"
        out: list = []
        pages = 0
        while url:
            data, url = self._get(url)
            items = data.get(key) if key and isinstance(data, dict) else data
            if not isinstance(items, list):
                raise VerdictError(f"GET {path}: unexpected response shape")
            out.extend(items)
            pages += 1
            if pages > limit:
                raise VerdictError(f"GET {path}: more than {limit} pages")
        return out


def fetch_and_compute(gh: GitHub, repo: str, number: int, config: dict) -> Result:
    """Raises only VerdictError."""
    try:
        pr = gh.get(f"repos/{repo}/pulls/{number}")
        head = (pr.get("head") or {}).get("sha") or ""
        if not re.fullmatch(SHA_RE, head):
            raise VerdictError("PR head SHA missing or malformed")
        default_branch = (((pr.get("base") or {}).get("repo")) or {}).get("default_branch") or ""
        files = gh.paged(f"repos/{repo}/pulls/{number}/files", limit=40)
        commits = gh.paged(f"repos/{repo}/pulls/{number}/commits", limit=5)
        comments = gh.paged(f"repos/{repo}/issues/{number}/comments")
        reviews = gh.paged(f"repos/{repo}/pulls/{number}/reviews")
        review_comments = gh.paged(f"repos/{repo}/pulls/{number}/comments")
        tree = gh.get(f"repos/{repo}/git/trees/{head}?recursive=1")
        default_ci_blobs: dict[str, str | None] = {}
        for path in config["required_ci_workflows"]:
            try:
                q = urllib.parse.urlencode({"ref": default_branch})
                meta = gh.get(f"repos/{repo}/contents/{urllib.parse.quote(path)}?{q}")
                default_ci_blobs[path] = meta.get("sha") if isinstance(meta, dict) and meta.get("type") == "file" else None
            except VerdictError:
                default_ci_blobs[path] = None  # reported by compute_verdict, fail closed
        q = urllib.parse.urlencode({"head_sha": head, "event": "push"})
        runs = gh.paged(f"repos/{repo}/actions/runs?{q}", key="workflow_runs", limit=10)
        res = compute_verdict(repo=repo, pr=pr, files=files, commits=commits, comments=comments,
                              reviews=reviews, review_comments=review_comments, tree=tree,
                              default_ci_blobs=default_ci_blobs, runs=runs, config=config)
        # 5. H must not have moved while we computed.
        again = gh.get(f"repos/{repo}/pulls/{number}")
        if (again.get("head") or {}).get("sha") != head:
            res.reasons.append("head moved while the verdict was computed; re-run on the new head")
            res.passed = False
        return res
    except VerdictError:
        raise
    except Exception as e:  # noqa: BLE001
        raise VerdictError(f"{type(e).__name__}: {e}") from e


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--config", required=True)
    args = ap.parse_args(argv)
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        print("review-verdict: FAIL (fail closed): GH_TOKEN not set")
        return 2
    try:
        with open(args.config, encoding="utf-8") as fh:
            config = json.load(fh)
        gh = GitHub(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        res = fetch_and_compute(gh, args.repo, args.pr, config)
    except Exception as e:  # noqa: BLE001 - anything uncomputable is a failure
        print(f"review-verdict: FAIL (fail closed): {type(e).__name__}: {e}")
        return 2
    text = res.render()
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write("```\n" + text.replace("```", "'''") + "\n```\n")
        except OSError:
            pass
    return 0 if res.passed else 1


if __name__ == "__main__":
    sys.exit(main())
