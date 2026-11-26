#!/usr/bin/env python3
"""merge-audit: the E5 merge audit (acardote/personal-assistant-ultra#581).

Design: acardote/personal-assistant-ultra docs/design/merge-model.md section 4
(rules R1-R5; R6 runs outside this repo, in the front door). This is
DETECTION, not prevention: it reports what already happened, as `FLAG` lines,
to the findings issue and the job summary. The operator confirms each FLAG.

Rules:
  R1  merge provenance. Every default-branch commit that is a PR merge by the
      bot merger (`merged_by`, read from the PR endpoint) needs a `merge.yml`
      run that (a) is TRUSTED by its API metadata alone: path is the merge
      workflow, repository is this repo, and either event `schedule` on the
      default branch or event `pull_request_target` whose PR base is the
      default branch (those two events always take the definition from the
      default branch); and (b) logged, as whole log lines,
        VERDICT-RECOMPUTED pr=<n> head=<H> result=pass
        MERGED pr=<n> head=<H> run_id=<run id> workflow_ref=<repo>/<merge.yml>@refs/heads/<default>
      with H the PR's merged head. A run on any other event or ref proves
      nothing, whatever its log says, and so does a matching time window or
      actor. A merge by anyone else is a FLAG too (the operator's merges are
      expected for 7a PRs; the operator confirms them).
  R2  direct pushes. Every default-branch commit that is not a PR merge (nor a
      commit of a PR merged into the same range) is a FLAG; so is history that
      no longer contains the last audited head (a force push), and every
      PushEvent to the default branch (events API, with its actor) whose head
      is not a PR merge commit.
  R3  control changes, compared with the previous run's snapshot: rulesets
      (id, name, enforcement, updated_at: an edit-and-restore still moves
      updated_at), the rules that apply to the default branch, the branch's
      `protected` summary, every workflow's `state` (a disabled audit or merge
      workflow), the kill-switch labels' existence, every repo variable
      (from the workflow's `vars` context, so AUTO_MERGE_ENABLED included),
      and every labeled/unlabeled event for a kill-switch label (issue events
      API, with its actor). Missing expected ruleset or label is a FLAG on
      every change of state.
  R4  forged checks. A completed `review-verdict` check run on an open PR head
      that is not from the GitHub Actions app, is not a job, or is a job with
      runner_name null or no steps, is a FLAG.
  R5  workflow files on branches. A non-default branch whose diff from its
      merge base with the default branch touches `.github/workflows/` is a
      FLAG.
  R7  review records. The verdict function reads records statelessly, so it
      cannot see a record edited away or deleted. The audit snapshots every
      record-like comment, review and review comment by a trusted record
      author on recent PRs (id -> body hash) and compares runs: an edited or
      vanished record is a FLAG, and so is a record already edited
      (updated_at != created_at) when first seen.

State (the previous run's snapshot) is a workflow ARTIFACT, `fleet-audit-state`,
not a committed file or an issue comment. GitHub binds an artifact to the run
that uploaded it, and the audit only reads state from an artifact whose run is
a trusted audit run (default-branch audit.yml, by API metadata). An issue
comment by github-actions[bot] can be written by ANY workflow run in the repo,
including the accepted bypass route (a branch push workflow), so it could
forge state that hides a deletion; a committed snapshot would need a direct
push to the default branch, which the ruleset blocks and R2 would flag.

Exit codes: 0 the audit ran (with or without FLAGs), 2 it could not run (fail
closed: no state is saved, the run is red, and the front door's liveness check
sees no recent successful run).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

STATE_VERSION = 1
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# A log line is "<ISO timestamp>Z <text>"; only <text> that is the WHOLE marker counts.
LOG_LINE_RE = re.compile(r"^﻿?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z (.*)$")
MERGED_RE = re.compile(r"^MERGED pr=([1-9][0-9]*) head=([0-9a-f]{40}) run_id=([1-9][0-9]*) workflow_ref=(\S+)$")
VERDICT_LOG_RE = re.compile(r"^VERDICT-RECOMPUTED pr=([1-9][0-9]*) head=([0-9a-f]{40}) result=(pass|fail)$")
# Kept identical to .github/verdict/verdict.py (a test checks it).
RECORD_LIKE_RE = re.compile(r"(?i)\b(?:verdict|critical|verify)\b.*\b(?:reviewer|sha)[ \t]*=")
CRITICAL_LIKE_RE = re.compile(r"(?i)\bcritical\b.*\b(?:id|reviewer|sha)[ \t]*=")
MERGE_EVENTS = {"schedule", "pull_request_target"}
AUDIT_EVENTS = {"schedule", "push", "workflow_dispatch"}
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_FLAGGED = 2000


class AuditError(Exception):
    """The audit cannot run; fail closed."""


class NotFound(AuditError):
    pass


def finding(rule: str, key: str, summary: str) -> dict:
    return {"rule": rule, "key": key, "summary": summary}


def h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def ts(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# GitHub I/O
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class GitHub:
    """Small REST client. The token goes only to the API host; a redirect
    (log and artifact downloads) is followed WITHOUT the token."""

    def __init__(self, token: str, api: str = "https://api.github.com",
                 opener: Callable[..., Any] | None = None, attempts: int = 3,
                 sleep: Callable[[float], None] = time.sleep):
        self.token = token
        self.api = api.rstrip("/")
        self.opener = opener or urllib.request.build_opener(_NoRedirect).open
        self.attempts = attempts
        self.sleep = sleep

    def _req(self, url: str, method: str = "GET", body: dict | None = None, auth: bool = True):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "merge-audit"}
        if auth:
            if not url.startswith(self.api + "/"):
                raise AuditError(f"refusing to send the token to {url.split('?')[0]!r}")
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        return urllib.request.Request(url, data=data, method=method, headers=headers)

    def _call(self, url: str, method: str = "GET", body: dict | None = None, auth: bool = True,
              raw: bool = False, max_bytes: int = 0):
        short = url.split("?")[0]
        last: BaseException | None = None
        for attempt in range(self.attempts):
            try:
                with self.opener(self._req(url, method, body, auth), timeout=60) as resp:
                    payload = resp.read(max_bytes + 1) if max_bytes else resp.read()
                    if max_bytes and len(payload) > max_bytes:
                        raise AuditError(f"{method} {short}: response over {max_bytes} bytes")
                    link = resp.headers.get("Link")
                    if raw:
                        return payload, None
                    return (json.loads(payload.decode("utf-8")) if payload else None), link
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308) and raw:
                    loc = e.headers.get("Location") or ""
                    if not loc.startswith("https://"):
                        raise AuditError(f"{method} {short}: redirect to a non-https location")
                    return self._call(loc, auth=False, raw=True, max_bytes=max_bytes)
                if e.code in (404, 410):
                    raise NotFound(f"{method} {short}: HTTP {e.code}") from e
                last = e
                if e.code not in RETRY_STATUS:
                    raise AuditError(f"{method} {short}: HTTP {e.code}") from e
            except AuditError:
                raise
            except Exception as e:  # noqa: BLE001 - transport errors retry, then fail closed
                last = e
            if attempt + 1 < self.attempts:
                self.sleep(2 ** attempt)
        raise AuditError(f"{method} {short} failed after {self.attempts} attempts: {type(last).__name__}: {last}")

    def get(self, path: str) -> Any:
        return self._call(f"{self.api}/{path}")[0]

    def post(self, path: str, body: dict) -> Any:
        return self._call(f"{self.api}/{path}", method="POST", body=body)[0]

    def download(self, path: str, max_bytes: int) -> bytes:
        return self._call(f"{self.api}/{path}", raw=True, max_bytes=max_bytes)[0]

    def paged(self, path: str, key: str | None = None, limit: int = 20) -> list:
        sep = "&" if "?" in path else "?"
        url: str | None = f"{self.api}/{path}{sep}per_page=100"
        out: list = []
        pages = 0
        while url:
            data, link = self._call(url)
            items = data.get(key) if key and isinstance(data, dict) else data
            if not isinstance(items, list):
                raise AuditError(f"GET {path}: unexpected response shape")
            out.extend(items)
            pages += 1
            url = None
            if link:
                for part in link.split(","):
                    seg = part.split(";")
                    if len(seg) >= 2 and seg[1].strip() == 'rel="next"':
                        url = seg[0].strip()[1:-1]
            if url and pages >= limit:
                raise AuditError(f"GET {path}: more than {limit} pages")
        return out


# --------------------------------------------------------------------------
# Run trust, by API metadata only
# --------------------------------------------------------------------------

def merge_run_untrusted(run: dict, repo: str, default: str, merge_path: str) -> str | None:
    """None when the run's definition provably came from the default branch."""
    if run.get("path") != merge_path:
        return f"path {run.get('path')!r}"
    if (run.get("repository") or {}).get("full_name") != repo:
        return "another repository"
    event = run.get("event")
    if event == "schedule":
        if run.get("head_branch") != default:
            return f"schedule on {run.get('head_branch')!r}"
        return None
    if event == "pull_request_target":
        prs = run.get("pull_requests") or []
        if not prs:
            return "pull_request_target with no PR (fork or unknown base)"
        if any((p.get("base") or {}).get("ref") != default for p in prs):
            return "pull_request_target on a PR not based on the default branch"
        return None
    return f"event {event!r} on {run.get('head_branch')!r} (not schedule/pull_request_target from {default})"


def audit_run_untrusted(run: dict, repo: str, default: str, audit_path: str) -> str | None:
    if run.get("path") != audit_path:
        return f"path {run.get('path')!r}"
    if (run.get("repository") or {}).get("full_name") != repo:
        return "another repository"
    if (run.get("head_repository") or {}).get("full_name") != repo:
        return "head repository is not this repository"
    if run.get("event") not in AUDIT_EVENTS:
        return f"event {run.get('event')!r}"
    if run.get("head_branch") != default:
        return f"ref {run.get('head_branch')!r}"
    return None


def log_proves_merge(zbytes: bytes, pr: int, head: str, run_id: int, expected_ref: str,
                     max_unzipped: int) -> tuple[bool, str]:
    merged = verdict = False
    try:
        with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if sum(i.file_size for i in infos) > max_unzipped:
                return False, "log archive too large to read (fail closed)"
            for info in infos:
                for raw in z.read(info).decode("utf-8", "replace").splitlines():
                    m = LOG_LINE_RE.match(raw)
                    if not m:
                        continue
                    line = m.group(1).rstrip("\r")
                    mm = MERGED_RE.match(line)
                    if mm and int(mm[1]) == pr and mm[2] == head and int(mm[3]) == run_id and mm[4] == expected_ref:
                        merged = True
                    vm = VERDICT_LOG_RE.match(line)
                    if vm and int(vm[1]) == pr and vm[2] == head and vm[3] == "pass":
                        verdict = True
    except zipfile.BadZipFile:
        return False, "log archive unreadable"
    if merged and verdict:
        return True, "logged VERDICT-RECOMPUTED pass and MERGED for this head"
    missing = [n for n, ok in (("VERDICT-RECOMPUTED pass", verdict), ("MERGED", merged)) if not ok]
    return False, "no " + " and no ".join(missing) + f" line for pr={pr} head={head[:12]}"


# --------------------------------------------------------------------------
# R1 / R2: commits on the default branch
# --------------------------------------------------------------------------

class Auditor:
    def __init__(self, gh: GitHub, repo: str, cfg: dict, now: datetime | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.gh = gh
        self.repo = repo
        self.cfg = cfg
        self.default = cfg["default_branch"]
        self.now = now or datetime.now(timezone.utc)
        self.sleep = sleep
        self.findings: list[dict] = []
        self.ledger: list[str] = []
        self.notes: list[str] = []

    def flag(self, rule: str, key: str, summary: str) -> None:
        self.findings.append(finding(rule, key, summary))

    # ---- commits
    def range_commits(self, base: str | None, head: str) -> list[dict]:
        cap = int(self.cfg["max_commits_per_run"])
        if base == head:
            return []
        if base:
            try:
                first = self.gh.get(f"repos/{self.repo}/compare/{base}...{head}?per_page=100")
            except NotFound:
                self.flag("R2", f"R2:base-gone:{base}:{head}",
                          f"last audited head {base[:12]} no longer exists: history was rewritten (force push)")
                base = None
            else:
                status = first.get("status")
                if status in ("diverged", "behind"):
                    self.flag("R2", f"R2:rewrite:{base}:{head}",
                              f"default branch history no longer contains the last audited head {base[:12]} "
                              f"(compare status {status}): force push or ruleset bypass")
                if status in ("identical", "behind"):
                    return []
                total = int(first.get("total_commits") or 0)
                if total > cap:
                    raise AuditError(f"{total} new commits on {self.default}, over the cap {cap}")
                commits = list(first.get("commits") or [])
                page = 2
                while len(commits) < total:
                    more = self.gh.get(f"repos/{self.repo}/compare/{base}...{head}?per_page=100&page={page}")
                    batch = more.get("commits") or []
                    if not batch:
                        raise AuditError("compare pagination ended before total_commits")
                    commits.extend(batch)
                    page += 1
                return commits
        limit = int(self.cfg["initial_commit_limit"])
        commits = self.gh.paged(f"repos/{self.repo}/commits?sha={head}", limit=max(1, limit // 100 + 1))
        if len(commits) > limit:
            self.flag("R2", f"R2:initial-truncated:{head}",
                      f"first run: only the newest {limit} commits audited, older history unaudited")
            commits = commits[:limit]
        commits.reverse()   # oldest first, as compare returns them
        return commits

    def pulls_for(self, sha: str) -> list[dict]:
        pulls = self.gh.get(f"repos/{self.repo}/commits/{sha}/pulls")
        if not pulls:   # association can lag a fresh merge by seconds
            self.sleep(15)
            pulls = self.gh.get(f"repos/{self.repo}/commits/{sha}/pulls")
        return pulls or []

    def audit_commits(self, last: str | None, head: str) -> str:
        """Audit last..head; returns the new audited head (stops early at a
        merge whose run has not finished, so the next run re-checks it)."""
        base = last or self.cfg.get("baseline_sha") or None
        commits = self.range_commits(base, head)
        shas = {c["sha"] for c in commits}
        audited = last or base
        for c in commits:
            sha = c["sha"]
            pulls = self.pulls_for(sha)
            merged = next((p for p in pulls if p.get("merged_at") and p.get("merge_commit_sha") == sha), None)
            if merged is None:
                carrier = next((p for p in pulls if p.get("merged_at") and p.get("merge_commit_sha") in shas), None)
                if carrier is not None:
                    self.ledger.append(f"{sha[:12]} commit of PR #{carrier['number']} (merged in this range)")
                else:
                    author = ((c.get("author") or {}).get("login")) or ((c.get("commit") or {}).get("author") or {}).get("name")
                    self.flag("R2", f"R2:direct:{sha}",
                              f"{sha[:12]} is on {self.default} but is not a PR merge: direct push "
                              f"(commit author {author!r}; pusher, when known, in the PushEvent FLAGs)")
                    self.ledger.append(f"{sha[:12]} DIRECT PUSH")
                audited = sha
                continue
            pr = self.gh.get(f"repos/{self.repo}/pulls/{merged['number']}")
            by = (pr.get("merged_by") or {}).get("login")
            n = pr["number"]
            if by == self.cfg["bot_merger"]:
                verdict = self.verify_bot_merge(pr, sha)
                if verdict == "pending":
                    self.notes.append(f"{sha[:12]} PR #{n}: merging run still in progress; re-checked next run")
                    return audited
                self.ledger.append(f"{sha[:12]} PR #{n} merged by {by}: {verdict}")
            elif by in self.cfg["operator_logins"]:
                self.flag("R1", f"R1:operator:{sha}",
                          f"{sha[:12]} PR #{n} merged by {by} (operator login: operator, a v1 agent session or the "
                          f"front door, A11). Expected for 7a PRs; confirm")
                self.ledger.append(f"{sha[:12]} PR #{n} merged by {by} (confirm)")
            else:
                self.flag("R1", f"R1:merger:{sha}", f"{sha[:12]} PR #{n} merged by {by!r}, not by merge.yml")
                self.ledger.append(f"{sha[:12]} PR #{n} merged by {by!r} (FLAG)")
            audited = sha
        return audited

    def verify_bot_merge(self, pr: dict, sha: str) -> str:
        n = pr["number"]
        head = (pr.get("head") or {}).get("sha") or ""
        merged_at = ts(pr.get("merged_at"))
        mpath = self.cfg["merge_workflow"]
        expected_ref = f"{self.repo}/{mpath}@refs/heads/{self.default}"
        if not SHA_RE.match(head) or merged_at is None:
            self.flag("R1", f"R1:unreadable:{sha}", f"{sha[:12]} PR #{n}: merged head or time unreadable")
            return "FLAG (unreadable)"
        lo = merged_at - timedelta(minutes=int(self.cfg["merge_run_window_minutes"]))
        hi = merged_at + timedelta(minutes=2)
        try:
            runs = self.gh.paged(f"repos/{self.repo}/actions/workflows/{mpath.rsplit('/', 1)[-1]}/runs"
                                 f"?created={iso(lo)}..{iso(hi)}", key="workflow_runs", limit=5)
        except NotFound:
            runs = []
        seen: list[str] = []
        pending = False
        for run in sorted(runs, key=lambda r: r.get("created_at") or "", reverse=True):
            rid = run.get("id")
            why = merge_run_untrusted(run, self.repo, self.default, mpath)
            if why:
                seen.append(f"run {rid} untrusted: {why}")
                continue
            created = ts(run.get("created_at"))
            if created is not None and created > merged_at:
                continue
            if run.get("status") != "completed":
                pending = True
                continue
            try:
                z = self.gh.download(f"repos/{self.repo}/actions/runs/{rid}/logs", int(self.cfg["max_log_bytes"]))
            except NotFound:
                seen.append(f"run {rid}: logs unavailable")
                continue
            ok, why = log_proves_merge(z, n, head, int(rid), expected_ref, 4 * int(self.cfg["max_log_bytes"]))
            if ok:
                return f"verified by run {rid}"
            seen.append(f"run {rid}: {why}")
        if pending:
            return "pending"
        detail = "; ".join(seen[:8]) or "no merge.yml run in the window"
        self.flag("R1", f"R1:provenance:{sha}",
                  f"{sha[:12]} PR #{n} merged by {self.cfg['bot_merger']} at head {head[:12]} with no default-branch "
                  f"merge.yml run that logged its inline recomputation and the merge ({detail})")
        return "FLAG (no provenance)"

    # ---- R2: push events
    def push_events(self, cursor: int | None, audited_shas: set[str]) -> int | None:
        events = self.gh.paged(f"repos/{self.repo}/events", limit=3)
        ids = [int(e["id"]) for e in events if str(e.get("id", "")).isdigit()]
        newest = max(ids) if ids else cursor
        if cursor is None:
            self.notes.append("first run: push-event cursor set, earlier pushes covered by the commit audit")
            return newest
        if ids and min(ids) > cursor and len(events) >= 300:
            self.flag("R2", f"R2:events-gap:{cursor}", "more than 300 repo events since the last run: pushes in the gap unread")
        for e in sorted(events, key=lambda x: int(x["id"])):
            if int(e["id"]) <= cursor or e.get("type") != "PushEvent":
                continue
            p = e.get("payload") or {}
            if p.get("ref") != f"refs/heads/{self.default}":
                continue
            actor = (e.get("actor") or {}).get("login")
            head = p.get("head") or ""
            ok = False
            if SHA_RE.match(head):
                try:
                    ok = any(x.get("merged_at") and x.get("merge_commit_sha") == head for x in self.pulls_for(head))
                except NotFound:
                    ok = False
            if not ok:
                self.flag("R2", f"R2:push:{e['id']}",
                          f"push to {self.default} by {actor!r} at {e.get('created_at')}: head {head[:12]} "
                          f"(before {str(p.get('before', ''))[:12]}) is not a PR merge commit")
            else:
                self.ledger.append(f"push {e['id']} by {actor}: PR merge {head[:12]}")
        return newest

    # ---- R3: controls
    def controls(self, prev: dict | None, vars_ctx: dict) -> dict:
        r, d = self.repo, self.default
        rulesets = {str(x["id"]): {k: x.get(k) for k in ("name", "enforcement", "updated_at", "target", "source_type")}
                    for x in self.gh.get(f"repos/{r}/rulesets?includes_parents=true&per_page=100") or []}
        rules = self.gh.paged(f"repos/{r}/rules/branches/{urllib.parse.quote(d)}", limit=5)
        branch = self.gh.get(f"repos/{r}/branches/{urllib.parse.quote(d)}")
        wfs = {w.get("path"): w.get("state")
               for w in self.gh.paged(f"repos/{r}/actions/workflows", key="workflows", limit=5)}
        labels = {}
        for name in self.cfg["kill_switch_labels"]:
            try:
                lab = self.gh.get(f"repos/{r}/labels/{urllib.parse.quote(name, safe='')}")
                labels[name] = {k: lab.get(k) for k in ("id", "name", "color")}
            except NotFound:
                labels[name] = None
        snap = {"rulesets": rulesets, "rules": h(rules),
                "protection": {"protected": branch.get("protected"), "protection": h(branch.get("protection"))},
                "workflows": wfs, "labels": labels, "vars": dict(sorted(vars_ctx.items()))}
        exp = self.cfg.get("expected_ruleset")
        if exp and not any(v["name"] == exp and v["enforcement"] == "active" for v in rulesets.values()):
            now_sets = ", ".join("{}={}".format(v["name"], v["enforcement"]) for v in rulesets.values()) or "none"
            self.flag("R3", f"R3:ruleset-missing:{h(rulesets)}",
                      f"no active ruleset named {exp!r} on this repo (rulesets now: {now_sets})")
        for name, lab in labels.items():
            if lab is None:
                self.flag("R3", f"R3:label-missing:{name}:{h(prev.get('labels', {}).get(name) if prev else None)}",
                          f"kill-switch label {name!r} does not exist")
        for wf in self.cfg["watched_workflows"]:
            if wf in wfs and wfs[wf] != "active":
                self.flag("R3", f"R3:workflow-state:{wf}:{wfs[wf]}:{h(prev.get('workflows') if prev else None)}",
                          f"{wf} state is {wfs[wf]!r}, not active")
        if prev:
            for part, label in (("rulesets", "rulesets"), ("rules", "rules applying to the default branch"),
                                ("protection", "branch protection summary"), ("workflows", "workflow set/state"),
                                ("labels", "kill-switch labels"), ("vars", "repo variables")):
                old, new = prev.get(part), snap[part]
                if old != new:
                    self.flag("R3", f"R3:{part}:{h(old)}:{h(new)}",
                              f"{label} changed since the last run: {self._diff(old, new)} "
                              f"(actor not observable from the API for this repo type)")
        return snap

    @staticmethod
    def _diff(old: Any, new: Any) -> str:
        if isinstance(old, dict) and isinstance(new, dict):
            keys = sorted(set(old) | set(new))
            parts = [f"{k}: {json.dumps(old.get(k))} -> {json.dumps(new.get(k))}" for k in keys if old.get(k) != new.get(k)]
            return "; ".join(parts)[:900]
        return f"{json.dumps(old)[:200]} -> {json.dumps(new)[:200]}"

    def label_events(self, cursor: int | None) -> int | None:
        events = self.gh.paged(f"repos/{self.repo}/issues/events", limit=3)
        ids = [int(e["id"]) for e in events if isinstance(e.get("id"), int)]
        newest = max(ids) if ids else cursor
        if cursor is None:
            return newest
        if ids and min(ids) > cursor and len(events) >= 300:
            self.flag("R3", f"R3:issue-events-gap:{cursor}", "more than 300 issue events since the last run: label changes in the gap unread")
        watched = set(self.cfg["kill_switch_labels"])
        for e in events:
            if not isinstance(e.get("id"), int) or e["id"] <= cursor:
                continue
            if e.get("event") in ("labeled", "unlabeled") and (e.get("label") or {}).get("name") in watched:
                num = (e.get("issue") or {}).get("number")
                self.flag("R3", f"R3:label-event:{e['id']}",
                          f"{(e.get('actor') or {}).get('login')!r} {e['event']} {(e.get('label') or {}).get('name')!r} "
                          f"on #{num} at {e.get('created_at')}")
        return newest

    # ---- R7: review records
    def records(self, prev: dict | None) -> dict:
        r = self.repo
        trusted = set(self.cfg["trusted_record_authors"])
        horizon = self.now - timedelta(days=int(self.cfg["record_scope_days"]))
        prs = {}
        for p in self.gh.paged(f"repos/{r}/pulls?state=all&sort=updated&direction=desc", limit=3):
            if p.get("state") == "open" or (ts(p.get("updated_at")) or self.now) >= horizon:
                prs[p["number"]] = p
        prev = prev or {}
        for key, rec in prev.items():
            n = rec["pr"]
            if n not in prs:
                p = self.gh.get(f"repos/{r}/pulls/{n}")
                closed = ts(p.get("closed_at"))
                if p.get("state") == "open" or closed is None or closed >= horizon:
                    prs[n] = p
        snap: dict[str, dict] = {}
        for n in sorted(prs):
            items = [("ic", c, c.get("created_at"), c.get("updated_at"))
                     for c in self.gh.paged(f"repos/{r}/issues/{n}/comments", limit=50)]
            items += [("rv", c, c.get("submitted_at"), None)
                      for c in self.gh.paged(f"repos/{r}/pulls/{n}/reviews", limit=50) if c.get("state") != "PENDING"]
            items += [("rc", c, c.get("created_at"), c.get("updated_at"))
                      for c in self.gh.paged(f"repos/{r}/pulls/{n}/comments", limit=50)]
            seen = set()
            for kind, c, created, updated in items:
                key = f"{kind}:{c.get('id')}"
                seen.add(key)
                body = c.get("body") or ""
                author = (c.get("user") or {}).get("login")
                if key not in prev and not (author in trusted and (RECORD_LIKE_RE.search(body) or CRITICAL_LIKE_RE.search(body))):
                    continue
                digest = hashlib.sha256(body.encode()).hexdigest()
                snap[key] = {"pr": n, "h": digest, "author": author}
                if key in prev:
                    if prev[key]["h"] != digest:
                        self.flag("R7", f"R7:edited:{key}:{digest}",
                                  f"review record {key} on PR #{n} by {author!r} was edited since the last run")
                elif updated and created and updated != created:
                    self.flag("R7", f"R7:edited-before-snapshot:{key}:{digest}",
                              f"review record {key} on PR #{n} by {author!r} was already edited when first seen "
                              f"(created {created}, updated {updated})")
            for key, rec in prev.items():
                if rec["pr"] == n and key not in seen:
                    self.flag("R7", f"R7:deleted:{key}",
                              f"review record {key} on PR #{n} by {rec.get('author')!r} was deleted since the last run")
        return snap

    # ---- R4: forged checks
    def forged_checks(self, ok_ids: list[int]) -> list[int]:
        r = self.repo
        name = self.cfg["verdict_check_name"]
        ok = set(ok_ids)
        for p in self.gh.paged(f"repos/{r}/pulls?state=open", limit=5):
            head = (p.get("head") or {}).get("sha")
            if not head:
                continue
            q = urllib.parse.urlencode({"check_name": name, "filter": "all"})
            for cr in self.gh.paged(f"repos/{r}/commits/{head}/check-runs?{q}", key="check_runs", limit=5):
                cid = cr.get("id")
                if cr.get("status") != "completed" or cid in ok:
                    continue
                app = (cr.get("app") or {}).get("id")
                if app != int(self.cfg["actions_app_id"]):
                    self.flag("R4", f"R4:{cid}", f"{name} check run {cid} on PR #{p['number']} is from app {app!r}, not GitHub Actions")
                    continue
                try:
                    job = self.gh.get(f"repos/{r}/actions/jobs/{cid}")
                except NotFound:
                    self.flag("R4", f"R4:{cid}", f"{name} check run {cid} on PR #{p['number']} is not an Actions job (forged)")
                    continue
                if job.get("runner_name") is None or not job.get("steps"):
                    self.flag("R4", f"R4:{cid}", f"{name} check run {cid} on PR #{p['number']} was created through the API "
                                                 f"(runner_name={job.get('runner_name')!r}, steps={len(job.get('steps') or [])})")
                    continue
                ok.add(cid)
        return sorted(ok)[-MAX_FLAGGED:]

    # ---- R5: workflow files on branches
    def branch_workflows(self, prev: dict | None) -> dict:
        r = self.repo
        prev = prev or {}
        snap = {}
        for b in self.gh.paged(f"repos/{r}/branches", limit=10):
            name, tip = b.get("name"), (b.get("commit") or {}).get("sha")
            if name == self.default or not tip:
                continue
            if name in prev and prev[name] == tip:
                snap[name] = tip
                continue
            cmp = self.gh.get(f"repos/{r}/compare/{urllib.parse.quote(self.default)}...{tip}")
            files = cmp.get("files") or []
            touched = [f.get("filename") for f in files
                       if str(f.get("filename", "")).startswith(".github/workflows/")
                       or str(f.get("previous_filename") or "").startswith(".github/workflows/")]
            if touched:
                self.flag("R5", f"R5:{name}:{tip}", f"branch {name!r} at {tip[:12]} changes workflow files "
                                                    f"(its push workflows already ran): {', '.join(touched[:10])}")
            elif len(files) >= 300:
                self.flag("R5", f"R5:{name}:{tip}", f"branch {name!r} at {tip[:12]} changes 300+ files; workflow "
                                                    f"changes cannot be ruled out from the compare API")
            snap[name] = tip
        return snap


# --------------------------------------------------------------------------
# State (run-bound artifact) and findings
# --------------------------------------------------------------------------

def load_state(gh: GitHub, repo: str, cfg: dict, run_id: int, findings: list[dict]) -> dict | None:
    name = cfg["state_artifact"]
    default = cfg["default_branch"]
    arts = gh.paged(f"repos/{repo}/actions/artifacts?name={urllib.parse.quote(name)}", key="artifacts", limit=5)
    arts = [a for a in arts if a.get("name") == name and not a.get("expired")]
    for a in sorted(arts, key=lambda x: x.get("created_at") or "", reverse=True):
        wr = (a.get("workflow_run") or {}).get("id")
        if not wr or wr == run_id:
            continue
        run = gh.get(f"repos/{repo}/actions/runs/{wr}")
        why = audit_run_untrusted(run, repo, default, cfg["audit_workflow"])
        if why:
            findings.append(finding("R6", f"R6:state-untrusted:{a.get('id')}",
                                    f"artifact {name!r} {a.get('id')} was uploaded by run {wr}, not a trusted audit run ({why}); ignored"))
            continue
        z = gh.download(f"repos/{repo}/actions/artifacts/{a['id']}/zip", 20 * 1024 * 1024)
        try:
            with zipfile.ZipFile(io.BytesIO(z)) as zf:
                state = json.loads(zf.read("state.json").decode("utf-8"))
        except (KeyError, ValueError, zipfile.BadZipFile) as e:
            raise AuditError(f"state artifact {a['id']} unreadable: {e}") from e
        if state.get("version") != STATE_VERSION:
            raise AuditError(f"state artifact {a['id']} has version {state.get('version')!r}")
        return state
    try:
        runs = gh.get(f"repos/{repo}/actions/workflows/{cfg['audit_workflow'].rsplit('/', 1)[-1]}/runs"
                      f"?branch={urllib.parse.quote(default)}&status=success&per_page=20").get("workflow_runs") or []
    except NotFound:
        runs = []
    earlier = [x for x in runs if x.get("id") != run_id
               and audit_run_untrusted(x, repo, default, cfg["audit_workflow"]) is None]
    if earlier:
        findings.append(finding("R6", f"R6:state-missing:{earlier[0].get('id')}",
                                f"no trusted state artifact although audit run {earlier[0].get('id')} succeeded earlier: "
                                f"state deleted or expired; deletions and control changes before this run are unseen"))
    return None


def find_or_create_issue(gh: GitHub, repo: str, cfg: dict) -> int:
    title = cfg["findings_issue_title"]
    bot = "github-actions[bot]"
    issues = gh.paged(f"repos/{repo}/issues?state=all&creator={urllib.parse.quote(bot)}", limit=10)
    mine = sorted(i["number"] for i in issues if i.get("title") == title and "pull_request" not in i)
    if mine:
        return mine[0]
    return gh.post(f"repos/{repo}/issues", {"title": title, "body": (
        "Findings of the merge audit (`.github/workflows/audit.yml`, acardote/personal-assistant-ultra#581). "
        "Each `FLAG` is confirmed by the operator. Written only by the audit.")})["number"]


def render(findings: list[dict], ledger: list[str], notes: list[str], run_url: str) -> str:
    out = [f"## merge-audit run {run_url}", ""]
    out.append(f"### FLAGs ({len(findings)})")
    out += [f"- `FLAG` {f['rule']}: {f['summary']}" for f in findings] or ["(none)"]
    if ledger:
        out += ["", "### Audited default-branch commits and pushes"] + [f"- {x}" for x in ledger]
    if notes:
        out += ["", "### Notes"] + [f"- {x}" for x in notes]
    return "\n".join(out).replace("@", "@​")   # never mention anyone


def run_audit(gh: GitHub, repo: str, cfg: dict, run_id: int, vars_ctx: dict,
              now: datetime | None = None, sleep: Callable[[float], None] = time.sleep) -> tuple[dict, list[dict], "Auditor"]:
    meta = gh.get(f"repos/{repo}")
    if meta.get("default_branch") != cfg["default_branch"]:
        raise AuditError(f"default branch is {meta.get('default_branch')!r}, config says {cfg['default_branch']!r}")
    a = Auditor(gh, repo, cfg, now=now, sleep=sleep)
    state = load_state(gh, repo, cfg, run_id, a.findings)
    head = gh.get(f"repos/{repo}/branches/{urllib.parse.quote(cfg['default_branch'])}")["commit"]["sha"]
    prev = state or {}
    new_head = a.audit_commits(prev.get("head"), head)
    events_cursor = a.push_events(prev.get("events_cursor"), set())
    controls = a.controls(prev.get("controls"), vars_ctx)
    issue_cursor = a.label_events(prev.get("issue_events_cursor"))
    records = a.records(prev.get("records") if state else None)
    checks_ok = a.forged_checks(prev.get("checks_ok") or [])
    branches = a.branch_workflows(prev.get("branches"))
    flagged_before = set(prev.get("flagged") or [])
    new = [f for f in a.findings if f["key"] not in flagged_before]
    new_state = {"version": STATE_VERSION, "run_id": run_id, "audited_at": iso(a.now), "head": new_head,
                 "events_cursor": events_cursor, "issue_events_cursor": issue_cursor, "controls": controls,
                 "records": records, "checks_ok": checks_ok, "branches": branches,
                 "flagged": (list(prev.get("flagged") or []) + [f["key"] for f in new])[-MAX_FLAGGED:]}
    return new_state, new, a


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--state-out", required=True, help="where to write state.json for the artifact upload step")
    ap.add_argument("--dry-run", action="store_true", help="print findings; post nothing")
    args = ap.parse_args(argv)
    token = os.environ.get("GH_TOKEN", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not token or not run_id.isdigit():
        print("merge-audit: FAIL (fail closed): GH_TOKEN or GITHUB_RUN_ID not set")
        return 2
    try:
        with open(args.config, encoding="utf-8") as fh:
            cfg = json.load(fh)
        vars_ctx = json.loads(os.environ.get("VARS_JSON") or "{}")
        if not isinstance(vars_ctx, dict):
            raise AuditError("VARS_JSON is not an object")
        gh = GitHub(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        state, new, a = run_audit(gh, args.repo, cfg, int(run_id), vars_ctx)
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        text = render(new, a.ledger, a.notes, f"{server}/{args.repo}/actions/runs/{run_id}")
        for f in new:
            print(f"FLAG {f['rule']} {f['key']}: {f['summary']}")
        print(f"merge-audit: {len(new)} new FLAG(s), {len(a.findings)} total this run; head {state['head']}")
        if (new or a.ledger) and not args.dry_run:
            num = find_or_create_issue(gh, args.repo, cfg)
            gh.post(f"repos/{args.repo}/issues/{num}/comments", {"body": text[:60000]})
        os.makedirs(os.path.dirname(os.path.abspath(args.state_out)), exist_ok=True)
        with open(args.state_out, "w", encoding="utf-8") as fh:
            json.dump(state, fh, sort_keys=True)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(text + "\n")
    except Exception as e:  # noqa: BLE001 - anything uncomputable fails the run
        print(f"merge-audit: FAIL (fail closed): {type(e).__name__}: {e}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
