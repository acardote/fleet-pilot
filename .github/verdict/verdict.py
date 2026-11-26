#!/usr/bin/env python3
"""review-verdict: the E5 verdict function (acardote/personal-assistant-ultra#579).

Design: acardote/personal-assistant-ultra docs/design/merge-model.md, section 2
(verdict workflow) and section 3 step 4 (verdict, recomputed inline at head H).
The merge workflow (#580) is meant to import `compute_verdict` and run the same
function inline in its own run.

The verdict passes only if ALL of these hold at the PR's current head H:
  1. the objective weight can be recomputed (fail closed otherwise) and the PR
     carries exactly one weight label that is not lighter than it (A7);
  2. every reviewer in the review set for max(label, objective) has a latest
     `VERDICT: pass` record naming sha=H, from a trusted record author;
  3. no `critical` is open. A critical closes only on a `VERIFY: pass` record
     from a reviewer agent other than the PR's author, at a fix SHA that is a
     commit of this PR after the critical's SHA (A9). An author's "fixed"
     comment is not a record and closes nothing;
  4. every required CI workflow has a completed `pull_request` run with
     head_sha == H, the expected workflow path, and conclusion `success`, read
     from the Actions runs API (never from check-run names or statuses);
  5. H did not move while the verdict was computed.

Record formats (one per line, at the start of the line, full 40-hex SHAs):
  VERDICT: <pass|fail> reviewer=<agent> sha=<H>
  CRITICAL: id=<id> reviewer=<agent> sha=<sha>
  VERIFY: <pass|fail> closes=<id> reviewer=<agent> sha=<fix-sha>

Only issue comments on the PR authored by a login in
`trusted_record_authors` are read. Every other comment is ignored, whatever it
says. No check run or commit status is read.

Stdlib only: this runs on a bare runner from default-branch code and installs
nothing. Exit 0 = pass, 1 = fail, 2 = could not compute (fail closed).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

SHA_RE = r"[0-9a-f]{40}"
VERDICT_RE = re.compile(
    rf"^[ \t]*VERDICT:[ \t]+(pass|fail)[ \t]+reviewer=(\S+)[ \t]+sha=({SHA_RE})[ \t]*$",
    re.MULTILINE,
)
CRITICAL_RE = re.compile(
    rf"^[ \t]*CRITICAL:[ \t]+id=([A-Za-z0-9._-]+)[ \t]+reviewer=(\S+)[ \t]+sha=({SHA_RE})[ \t]*$",
    re.MULTILINE,
)
VERIFY_RE = re.compile(
    rf"^[ \t]*VERIFY:[ \t]+(pass|fail)[ \t]+closes=([A-Za-z0-9._-]+)[ \t]+reviewer=(\S+)"
    rf"[ \t]+sha=({SHA_RE})[ \t]*$",
    re.MULTILINE,
)
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

def glob_to_regex(pattern: str) -> re.Pattern[str]:
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
    return any(glob_to_regex(p).match(path) for p in patterns)


def recompute_weight(pr: dict, files: list[dict], config: dict) -> tuple[str, list[str]]:
    """Return (weight, why). Raises VerdictError when it cannot compute (fail closed)."""
    tiers = config["weight_tiers"]
    th = config["weight_thresholds"]
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
    for f in files:
        name = f.get("filename")
        if not isinstance(name, str) or not name:
            raise VerdictError("weight: a changed file has no filename")
        paths.append(name)
        prev = f.get("previous_filename")
        if isinstance(prev, str) and prev:
            paths.append(prev)  # a rename touches both sides
    loc = pr["additions"] + pr["deletions"]
    why: list[str] = []
    level = 0  # index into tiers; most restrictive criterion wins
    if loc > th["standard_max_loc"]:
        level = max(level, 2)
        why.append(f"loc={loc}>{th['standard_max_loc']}")
    elif loc > th["trivial_max_loc"]:
        level = max(level, 1)
        why.append(f"loc={loc}>{th['trivial_max_loc']}")
    if len(set(paths)) > th["trivial_max_files"]:
        level = max(level, 1)
        why.append(f"files={len(set(paths))}>{th['trivial_max_files']}")
    heavy_hits = sorted({p for p in paths if matches_any(p, config["heavy_paths"])})
    if heavy_hits:
        level = max(level, 2)
        shown = ", ".join(heavy_hits[:5]) + (" ..." if len(heavy_hits) > 5 else "")
        why.append(f"security-boundary paths: {shown}")
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


def parse_records(comments: list[dict], trusted: set[str]) -> tuple[list[Record], list[str]]:
    records: list[Record] = []
    ignored: dict[str, int] = {}
    ordered = sorted(enumerate(comments), key=lambda ic: (ic[1].get("created_at") or "", ic[0]))
    seq = 0
    for _, c in ordered:
        body = c.get("body") or ""
        login = ((c.get("user") or {}).get("login")) or ""
        created = c.get("created_at") or ""
        found: list[tuple[int, Record]] = []
        for m in VERDICT_RE.finditer(body):
            found.append((m.start(), Record("VERDICT", m.group(1), m.group(2), m.group(3), None, None, created, 0, login)))
        for m in CRITICAL_RE.finditer(body):
            found.append((m.start(), Record("CRITICAL", None, m.group(2), m.group(3), None, m.group(1), created, 0, login)))
        for m in VERIFY_RE.finditer(body):
            found.append((m.start(), Record("VERIFY", m.group(1), m.group(3), m.group(4), m.group(2), None, created, 0, login)))
        if not found:
            continue
        if login not in trusted:
            ignored[login] = ignored.get(login, 0) + len(found)
            continue
        for _, rec in sorted(found, key=lambda t: t[0]):
            rec.order = seq
            seq += 1
            records.append(rec)
    notes = [f"ignored {n} record(s) from untrusted author {who!r}" for who, n in sorted(ignored.items())]
    return records, notes


def author_agents_for(pr: dict, config: dict) -> set[str]:
    names = set(config["author_agents"])
    names.update(AUTHOR_AGENT_RE.findall(pr.get("body") or ""))
    return names


def open_criticals(records: list[Record], commit_shas: list[str], authors: set[str],
                   reviewers: set[str]) -> tuple[list[str], list[str]]:
    """Replay CRITICAL/VERIFY records in order; return (open ids, notes)."""
    state: dict[str, dict[str, Any]] = {}
    notes: list[str] = []
    index = {sha: i for i, sha in enumerate(commit_shas)}
    for rec in records:
        if rec.kind == "CRITICAL":
            state[rec.crit_id] = {"open": True, "sha": rec.sha}
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
            if rec.sha not in index:
                notes.append(f"VERIFY {cid!r} at {rec.sha[:12]} not a commit of this PR; ignored")
                continue
            if rec.sha == crit_sha or (crit_sha in index and index[rec.sha] <= index[crit_sha]):
                notes.append(f"VERIFY {cid!r} at {rec.sha[:12]} is not after the critical's SHA; ignored")
                continue
            state[cid]["open"] = rec.result != "pass"
    return sorted(cid for cid, s in state.items() if s["open"]), notes


# --------------------------------------------------------------------------
# The verdict function (pure: all inputs already fetched)
# --------------------------------------------------------------------------

def compute_verdict(*, repo: str, pr: dict, files: list[dict], commits: list[dict],
                    comments: list[dict], runs: list[dict], config: dict) -> Result:
    res = Result(passed=False)
    try:
        head = (pr.get("head") or {}).get("sha")
        if not isinstance(head, str) or not re.fullmatch(SHA_RE, head):
            raise VerdictError("PR head SHA missing or malformed")
        res.head_sha = head
        if pr.get("state") != "open":
            res.reasons.append(f"PR state is {pr.get('state')!r}, not open")
        head_repo = (((pr.get("head") or {}).get("repo")) or {}).get("full_name")
        if head_repo != repo:
            res.reasons.append(f"head repository {head_repo!r} is not {repo!r} (fork PRs never pass)")

        # 1. weight (A7): objective recompute, fail closed; a lighter label fails.
        tiers = config["weight_tiers"]
        objective, why = recompute_weight(pr, files, config)
        labels = [l.get("name", "") for l in pr.get("labels") or []]
        declared = declared_weight(labels, config)
        res.notes.append(f"objective weight {objective} ({'; '.join(why)}); label weight {declared}")
        if tiers.index(declared) < tiers.index(objective):
            res.reasons.append(f"labelled weight:{declared} is lighter than objective weight {objective}")
        weight = tiers[max(tiers.index(declared), tiers.index(objective))]
        res.weight = weight

        # Records from trusted authors only.
        records, notes = parse_records(comments, set(config["trusted_record_authors"]))
        res.notes += notes
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

        # 3. no open critical; closure only by a verify-only reviewer verdict at the fix SHA (A9).
        if len(commits) != pr.get("commits"):
            if (pr.get("commits") or 0) >= config["max_pr_commits"]:
                raise VerdictError(f"PR has {pr.get('commits')} commits, at or over the API cap")
            raise VerdictError(f"commit list incomplete ({len(commits)} listed, PR reports {pr.get('commits')})")
        commit_shas = [c.get("sha") for c in commits]
        if not commit_shas or commit_shas[-1] != head:
            raise VerdictError("PR commit list does not end at the head SHA")
        still_open, crit_notes = open_criticals(records, commit_shas, authors, reviewers)
        res.notes += crit_notes
        for cid in still_open:
            res.reasons.append(f"critical {cid!r} is open (closes only on a VERIFY pass by a non-author reviewer at the fix SHA)")

        # 4. CI green at H, from the Actions runs API by workflow path.
        required_ci = config["required_ci_workflows"]
        if not required_ci:
            raise VerdictError("no required CI workflows configured")
        for path in required_ci:
            candidates = [
                run for run in runs
                if run.get("path") == path and run.get("head_sha") == head
                and run.get("event") == "pull_request"
                and (((run.get("head_repository") or {}).get("full_name")) == repo)
            ]
            if not candidates:
                res.reasons.append(f"CI {path}: no pull_request run at head {head[:12]}")
                continue
            latest = max(candidates, key=lambda r: (r.get("created_at") or "", r.get("run_attempt") or 0, r.get("id") or 0))
            if latest.get("status") != "completed" or latest.get("conclusion") != "success":
                res.reasons.append(
                    f"CI {path}: latest run {latest.get('id')} is {latest.get('status')}/{latest.get('conclusion')}"
                )
    except VerdictError as e:
        res.reasons.append(f"cannot compute verdict (fail closed): {e}")
    except (KeyError, TypeError, ValueError) as e:
        res.reasons.append(f"cannot compute verdict (fail closed): {type(e).__name__}: {e}")
    res.passed = not res.reasons
    return res


# --------------------------------------------------------------------------
# GitHub I/O (read-only)
# --------------------------------------------------------------------------

class GitHub:
    def __init__(self, token: str, api: str = "https://api.github.com",
                 opener: Callable[..., Any] | None = None):
        self.token = token
        self.api = api.rstrip("/")
        self.opener = opener or urllib.request.urlopen

    def _get(self, url: str) -> tuple[Any, str | None]:
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "review-verdict",
        })
        try:
            with self.opener(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                link = resp.headers.get("Link")
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            raise VerdictError(f"GET {url.split('?')[0]} failed: {e}") from e
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
            items = data.get(key) if key else data
            if not isinstance(items, list):
                raise VerdictError(f"GET {path}: unexpected response shape")
            out.extend(items)
            pages += 1
            if pages > limit:
                raise VerdictError(f"GET {path}: more than {limit} pages")
        return out


def fetch_and_compute(gh: GitHub, repo: str, number: int, config: dict) -> Result:
    pr = gh.get(f"repos/{repo}/pulls/{number}")
    head = (pr.get("head") or {}).get("sha") or ""
    files = gh.paged(f"repos/{repo}/pulls/{number}/files", limit=40)
    commits = gh.paged(f"repos/{repo}/pulls/{number}/commits", limit=5)
    comments = gh.paged(f"repos/{repo}/issues/{number}/comments")
    q = urllib.parse.urlencode({"head_sha": head, "event": "pull_request"})
    runs = gh.paged(f"repos/{repo}/actions/runs?{q}", key="workflow_runs", limit=10)
    res = compute_verdict(repo=repo, pr=pr, files=files, commits=commits,
                          comments=comments, runs=runs, config=config)
    # 5. H must not have moved while we computed.
    again = gh.get(f"repos/{repo}/pulls/{number}")
    if (again.get("head") or {}).get("sha") != head:
        res.reasons.append("head moved while the verdict was computed; re-run on the new head")
        res.passed = False
    return res


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
    except (VerdictError, OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        print(f"review-verdict: FAIL (fail closed): {type(e).__name__}: {e}")
        return 2
    text = res.render()
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write("```\n" + text + "\n```\n")
        except OSError:
            pass
    return 0 if res.passed else 1


if __name__ == "__main__":
    sys.exit(main())
