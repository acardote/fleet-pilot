#!/usr/bin/env python3
"""merge-audit: the E5 merge audit (acardote/personal-assistant-ultra#581).

Design: acardote/personal-assistant-ultra docs/design/merge-model.md section 4
(rules R1-R5, R7; R6 runs outside this repo, in the front door). This is
DETECTION, not prevention: it reports what already happened, as `FLAG`s.

Threat model. The operator's login is the repo admin AND the agents' login
(ADR-0005 A11). Anything in this repo that the admin can delete or edit
(comments, issues, artifacts, runs, settings) is under the control of the actor
being watched. Deletion cannot be prevented here, so the audit makes deletion
and rollback DETECTABLE and fails closed:

- State is a hash chain. Every run appends one chain entry (sequence number,
  previous entry's digest, its run id and run_number, the audited head, the
  digest of the audit code it ran, the digest of the state it saved, and its
  FLAGs). The state (a run-bound artifact) carries the last entries; the
  findings issue's BODY (the "anchor") carries them too, readable anonymously.
- A run loads state only from its predecessor: the newest successful trusted
  audit run. It fails closed (exit 2, run red, front door alerts "stale") when
  that run's artifact is gone, when audit runs between that run and this one
  were deleted (run_number gap), when the anchor names a newer successful run
  (rollback), or when the predecessor ran different audit code (an altered
  audit that was merged and reverted). Recovery is an explicit
  `workflow_dispatch` with input `rebaseline`, which is itself a FLAG and a
  chain discontinuity the front door alerts on.
- The front door (PAU tools/fleet_audit_check.py) reads the anchor every
  heartbeat, verifies the chain against its own copy (fork, regression, gap,
  rebaseline), checks every audit run since its last heartbeat against the
  pinned code and for run_number gaps, and turns each entry's FLAGs and the
  open conditions into inbox items. So a deleted findings comment no longer
  erases a FLAG: the FLAG reached Tier 0 through the chain.

Rules:
  R1  merge provenance. Every first-parent default-branch commit that is a PR
      merge by the bot merger (`merged_by`, from the PR endpoint) needs a
      `merge.yml` run (path, this repo, event `schedule` on the default branch
      or `pull_request_target`) whose log archive carries the Actions service's
      own `Job defined at: <repo>/.github/workflows/merge.yml@refs/heads/<default>`
      line in `<job>/system.txt` (no step can write that file, and run
      metadata cannot tell which base a pull_request_target run used: its
      `pull_requests[]` lists open PRs with that head, empty once they close),
      completed (any conclusion: merge.yml exits
      1 when ANOTHER candidate errored or was refused, after it already merged
      and logged this one; it prints MERGED only after GitHub confirmed the
      merge), and logged as whole lines, outside `##[group]Run` script echoes:
        VERDICT-RECOMPUTED pr=<n> head=<H> result=pass
        MERGED pr=<n> head=<H> run_id=<run id> workflow_ref=<repo>/<merge.yml>@refs/heads/<default>
      A merge by the operator login is a FLAG to confirm (separately worded
      for PRs not marked 7a); any other merger is a FLAG.
  R2  pushes. Every FIRST-PARENT commit between the last audited head and the
      default branch tip must have been created by GitHub (committer
      `web-flow`, signature verified) AND be a PR's merge commit (or an
      earlier commit of a rebase merge whose merge commit is later in the
      same range). Anything else is a direct push. A PR whose merge commit IS
      its head commit was "merged" by pushing the head (a laundered direct
      push). History that no longer contains the last audited head is a
      FLAG, and so is every PushEvent to the default branch whose head is not
      a PR merge commit (events API; it names the pusher).
  R3  control changes, compared with the previous snapshot: rulesets (summary
      and detail hash), rules for the default branch, the branch's protection
      summary, every workflow's state and updated_at, kill-switch labels, repo
      variables (hashed; only `public_vars` in clear), and every
      labeled/unlabeled event for a kill-switch label (with its actor).
      A missing ruleset, label or watched workflow, or a watched workflow not
      active, is an OPEN CONDITION, re-derived every run.
  R4  forged checks. A completed `review-verdict` check run on an open PR head
      that is not a GitHub Actions job of a trusted default-branch
      `verdict.yml` run (pull_request_target, base = default) is an open
      condition.
  R5  workflows run from outside the default branch. Every workflow run
      created since the last audit whose definition did not come from the
      default branch (head_branch not the default, or event pull_request) is
      a FLAG when its workflow file at the run's head_sha differs from the
      default branch's. Plus, as a second signal, every branch tip that
      changes `.github/workflows/`.
  R6  (in-repo part) state and anchor integrity, as above, and a gap of more
      than `max_gap_minutes` since the previous run.
  R7  review records. Trusted record-like issue comments, reviews and review
      comments on PRs are tracked (id -> body hash). Edited or deleted
      records are FLAGs; records are found through repo-wide `since` listings
      and re-verified one by one in rotation.

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
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

STATE_VERSION = 2
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
# Events whose run takes its workflow definition from the default branch.
DEFAULT_DEFINED_EVENTS = {"schedule", "pull_request_target", "issue_comment", "issues", "workflow_run",
                          "repository_dispatch", "label", "milestone", "discussion", "discussion_comment",
                          "pull_request_review", "pull_request_review_comment", "watch", "fork", "gollum",
                          "page_build", "public", "status", "check_run", "check_suite", "project", "project_card",
                          "project_column", "deployment", "deployment_status", "branch_protection_rule",
                          "registry_package"}
RETRY_STATUS = {500, 502, 503, 504}
CODE_PATHS = (".github/workflows/audit.yml", ".github/audit/audit.py", ".github/audit/config.json")
WITNESS_TITLE = "fleet-audit-chain"
ANCHOR_BEGIN = "<!-- fleet-audit-chain v1 -->"
ANCHOR_END = "<!-- /fleet-audit-chain -->"
ANCHOR_BUDGET = 50000          # chars of chain entries kept in the issue body (limit 65536)
COMMENT_CHUNK = 60000
GENESIS = "genesis"
ENTRY_FLAGS_CAP = 25
ENTRY_OPEN_CAP = 50
SUMMARY_CAP = 200
CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


class AuditError(Exception):
    """The audit cannot run; fail closed."""


class NotFound(AuditError):
    pass


class NoOp(Exception):
    """This run must not write state or the anchor (a re-run attempt, or a run
    older than the predecessor). Exit 0 without changing anything."""


class StateBroken(AuditError):
    """The previous state cannot be trusted (deleted, rolled back, or produced by
    other audit code). Fail closed until an explicit rebaseline dispatch."""


def clean(s: Any, cap: int = 0) -> str:
    """One line, no control characters (no log/markdown line injection)."""
    out = CTRL_RE.sub(" ", str(s))
    return out[:cap] if cap else out


def finding(rule: str, key: str, summary: str) -> dict:
    return {"rule": rule, "key": key, "summary": clean(summary)}


def canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def h(obj: Any) -> str:
    return hashlib.sha256(canon(obj).encode()).hexdigest()


def entry_digest(entry: dict) -> str:
    return h({k: v for k, v in entry.items() if k != "digest"})


# The audit's own integrity FLAGs, carried by kind in the witness so stripping
# them from the anchor is detectable (R6:gap is excluded: Tier 0 sees gaps itself).
WITNESS_R6 = ("anchor-mismatch", "anchor-forged", "anchor-behind", "anchor-unreadable", "rebaseline", "issue-moved",
              "runs-unverifiable", "runs-gap-suspect")


def witness_line(entry: dict) -> str:
    """Kept identical to PAU fleet_audit_check.WITNESS_RE (a vector is pinned on both sides)."""
    kinds = sorted({f["key"].split(":")[1] for f in entry.get("flags") or []
                    if f.get("rule") == "R6" and f["key"].split(":")[1] in WITNESS_R6})
    if entry.get("rebaseline") and "rebaseline" not in kinds:
        kinds = sorted(kinds + ["rebaseline"])
    return (f"fleet-audit-chain seq={entry['seq']} digest={entry['digest']} run_id={entry['run_id']} "
            f"flags_total={entry.get('flags_total') or 0} r6={','.join(kinds) or '-'}")


def state_digest(state: dict) -> str:
    return h({k: v for k, v in state.items() if k != "chain"})


def code_digest_of(blobs: dict) -> str:
    """Digest of the audit code a run executed. PAU's `fleet_audit_check.py pins`
    prints the same value (keep the two formulas identical; tests pin a vector)."""
    return hashlib.sha256("\n".join(f"{p} {blobs.get(p) or 'missing'}" for p in sorted(CODE_PATHS)).encode()).hexdigest()


def ts(s: str | None) -> datetime | None:
    if not s or not isinstance(s, str):
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# GitHub I/O
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def next_link(link: str | None) -> str | None:
    if not link:
        return None
    for part in link.split(","):
        seg = part.split(";")
        if len(seg) >= 2 and seg[1].strip() == 'rel="next"':
            return seg[0].strip()[1:-1]
    return None


class GitHub:
    """Small REST client. The token goes only to the API host; a redirect
    (log and artifact downloads) is followed WITHOUT the token. Rate limits
    (403/429 with Retry-After or X-RateLimit-Remaining: 0) wait up to
    `max_rate_wait` seconds, then fail closed."""

    def __init__(self, token: str, api: str = "https://api.github.com",
                 opener: Callable[..., Any] | None = None, attempts: int = 3,
                 sleep: Callable[[float], None] = time.sleep, max_rate_wait: int = 300,
                 clock: Callable[[], float] = time.time):
        self.token = token
        self.api = api.rstrip("/")
        self.opener = opener or urllib.request.build_opener(_NoRedirect).open
        self.attempts = attempts
        self.sleep = sleep
        self.max_rate_wait = max_rate_wait
        self.clock = clock
        self.count = 0
        self.remaining: str | None = None

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

    def _rate_wait(self, headers) -> float | None:
        if headers is None:
            return None
        ra = headers.get("Retry-After")
        if ra and str(ra).isdigit():
            return float(ra)
        if str(headers.get("X-RateLimit-Remaining")) == "0":
            reset = headers.get("X-RateLimit-Reset")
            if reset and str(reset).isdigit():
                return max(1.0, float(reset) - self.clock() + 1)
            return 60.0
        return None

    def _call(self, url: str, method: str = "GET", body: dict | None = None, auth: bool = True,
              raw: bool = False, max_bytes: int = 0):
        short = url.split("?")[0]
        last: BaseException | None = None
        attempt = 0
        while attempt < self.attempts:
            attempt += 1
            try:
                self.count += 1
                with self.opener(self._req(url, method, body, auth), timeout=60) as resp:
                    payload = resp.read(max_bytes + 1) if max_bytes else resp.read()
                    if max_bytes and len(payload) > max_bytes:
                        raise AuditError(f"{method} {short}: response over {max_bytes} bytes")
                    hdrs = getattr(resp, "headers", None) or {}
                    if auth:
                        self.remaining = hdrs.get("X-RateLimit-Remaining", self.remaining)
                    link = hdrs.get("Link")
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
                if e.code in (403, 429):
                    wait = self._rate_wait(e.headers)
                    if wait is None:
                        raise AuditError(f"{method} {short}: HTTP {e.code}") from e
                    if wait > self.max_rate_wait:
                        raise AuditError(f"{method} {short}: rate limited for {wait:.0f}s more (fail closed)") from e
                    self.sleep(wait)
                    continue
                if e.code not in RETRY_STATUS:
                    raise AuditError(f"{method} {short}: HTTP {e.code}") from e
            except AuditError:
                raise
            except Exception as e:  # noqa: BLE001 - transport errors retry, then fail closed
                last = e
            if attempt < self.attempts:
                self.sleep(2 ** (attempt - 1))
        raise AuditError(f"{method} {short} failed after {self.attempts} attempts: {type(last).__name__}: {last}")

    def get(self, path: str) -> Any:
        return self._call(f"{self.api}/{path}")[0]

    def post(self, path: str, body: dict) -> Any:
        return self._call(f"{self.api}/{path}", method="POST", body=body)[0]

    def patch(self, path: str, body: dict) -> Any:
        return self._call(f"{self.api}/{path}", method="PATCH", body=body)[0]

    def download(self, path: str, max_bytes: int) -> bytes:
        return self._call(f"{self.api}/{path}", raw=True, max_bytes=max_bytes)[0]

    def collect(self, path: str, key: str | None = None, max_pages: int = 10,
                stop: Callable[[dict], bool] | None = None) -> tuple[list, bool]:
        """Items page by page. Stops at the first item for which `stop` is true
        (that item is not returned). Returns (items, complete): complete is
        False when `max_pages` pages were read and more exist. Never raises for
        size, so a long list can never wedge the audit; callers FLAG an
        incomplete read."""
        sep = "&" if "?" in path else "?"
        url: str | None = f"{self.api}/{path}{sep}per_page=100"
        out: list = []
        pages = 0
        while url:
            data, link = self._call(url)
            items = data.get(key) if key and isinstance(data, dict) else data
            if not isinstance(items, list):
                raise AuditError(f"GET {path.split('?')[0]}: unexpected response shape")
            pages += 1
            for it in items:
                if stop is not None and stop(it):
                    return out, True
                out.append(it)
            url = next_link(link)
            if url and pages >= max_pages:
                return out, False
        return out, True

    def paged(self, path: str, key: str | None = None, limit: int = 20) -> list:
        """For lists that are small by construction (rules of one branch, the
        workflow files): more than `limit` pages fails closed."""
        items, complete = self.collect(path, key=key, max_pages=limit)
        if not complete:
            raise AuditError(f"GET {path.split('?')[0]}: more than {limit} pages")
        return items


# --------------------------------------------------------------------------
# Run trust, by API metadata only
# --------------------------------------------------------------------------

def pr_target_untrusted(run: dict, default: str) -> str | None:
    """Metadata pre-filter for a pull_request_target run. Metadata cannot prove
    which base (so which definition) a pull_request_target run used:
    `pull_requests[]` lists open PRs whose head matches, not the PR that
    triggered the run, and it is EMPTY once those PRs are closed (confirmed live:
    merge.yml run 45892436548). A sibling PR with the same head and another
    base would look identical. So the definition is proven from the run's log
    instead (`log_definition_ok`: the service-written `Job defined at:` line in
    `<job>/system.txt`). Here only a listed PR on another base is refused."""
    prs = run.get("pull_requests") or []
    if any((p.get("base") or {}).get("ref") != default for p in prs):
        return "pull_request_target on a PR not based on the default branch"
    return None


DEFINED_AT_RE = re.compile(r"^Job defined at: (\S+)$")


def log_definition_ok(zbytes: bytes, expected: str, max_unzipped: int) -> tuple[bool, str]:
    """The workflow definition a run executed, as the Actions service records it:
    `Job defined at: <repo>/<path>@<ref>` in each job's `system.txt`. That file
    is written by the service, not by any step (step logs are `N_<name>.txt`),
    so a workflow cannot forge it. Every job must name `expected`, and at least
    one must exist; anything else fails closed."""
    seen: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if sum(i.file_size for i in infos) > max_unzipped:
                return False, "log archive too large to read (fail closed)"
            for info in infos:
                if info.filename.rsplit("/", 1)[-1] != "system.txt":
                    continue
                for raw in z.read(info).decode("utf-8", "replace").splitlines():
                    m = LOG_LINE_RE.match(raw)
                    d = DEFINED_AT_RE.match(m.group(1).rstrip("\r")) if m else None
                    if d:
                        seen.append(d.group(1))
    except zipfile.BadZipFile:
        return False, "log archive unreadable"
    if not seen:
        return False, "no service-written 'Job defined at' line (definition unproven)"
    bad = sorted({x for x in seen if x != expected})
    if bad:
        return False, f"defined at {bad[0]!r}, not {expected!r}"
    return True, ""


def merge_run_untrusted(run: dict, repo: str, default: str, merge_path: str) -> str | None:
    """Metadata pre-filter (path, repository, default-branch events). It cannot
    prove the definition of a pull_request_target run; verify_bot_merge then
    requires the service-written definition line (`log_definition_ok`)."""
    if run.get("path") != merge_path:
        return f"path {run.get('path')!r}"
    if (run.get("repository") or {}).get("full_name") != repo:
        return "another repository"
    if (run.get("head_repository") or {}).get("full_name") != repo:
        return f"head repository {((run.get('head_repository') or {}).get('full_name'))!r} is not this repository (fork)"
    event = run.get("event")
    if event == "schedule":
        if run.get("head_branch") != default:
            return f"schedule on {run.get('head_branch')!r}"
        return None
    if event == "pull_request_target":
        return pr_target_untrusted(run, default)
    return f"event {event!r} on {run.get('head_branch')!r} (not schedule/pull_request_target from {default})"


def audit_run_untrusted(run: dict, repo: str, default: str, audit_path: str) -> str | None:
    """Metadata only. The code the run executed is checked separately
    (code digest at its head_sha), because a trusted path/event/branch says
    nothing about WHICH audit.yml/audit.py ran."""
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
    """Whole marker lines only, and never inside a `##[group]Run` block (the
    runner echoes the step's script there, expanded, even if the step later
    fails before merging)."""
    merged = verdict = False
    try:
        with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if sum(i.file_size for i in infos) > max_unzipped:
                return False, "log archive too large to read (fail closed)"
            for info in infos:
                in_echo = False
                for raw in z.read(info).decode("utf-8", "replace").splitlines():
                    m = LOG_LINE_RE.match(raw)
                    if not m:
                        continue
                    line = m.group(1).rstrip("\r")
                    if line.startswith("##[group]Run "):
                        in_echo = True
                        continue
                    if in_echo:
                        if line.startswith("##[endgroup]"):
                            in_echo = False
                        continue
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


def blobs_at(gh: GitHub, repo: str, ref: str, paths: tuple[str, ...] | None = None) -> dict[str, str]:
    """Blob SHAs at a commit. A truncated tree falls back to one contents call
    per wanted path (paths required then)."""
    tree = gh.get(f"repos/{repo}/git/trees/{urllib.parse.quote(ref, safe='')}?recursive=1")
    if not tree.get("truncated"):
        return {e["path"]: e["sha"] for e in tree.get("tree") or [] if e.get("type") == "blob"}
    if not paths:
        raise AuditError(f"tree of {ref[:12]} is truncated")
    out = {}
    for p in paths:
        try:
            out[p] = gh.get(f"repos/{repo}/contents/{urllib.parse.quote(p)}?ref={ref}")["sha"]
        except NotFound:
            pass
    return out


def code_digest(gh: GitHub, repo: str, sha: str) -> str:
    return code_digest_of(blobs_at(gh, repo, sha, CODE_PATHS))


# --------------------------------------------------------------------------
# The auditor
# --------------------------------------------------------------------------

class Auditor:
    def __init__(self, gh: GitHub, repo: str, cfg: dict, now: datetime | None = None,
                 sleep: Callable[[float], None] = time.sleep, deadline: float | None = None,
                 clock: Callable[[], float] = time.monotonic, seq: int = 0, hmac_key: str = ""):
        self.gh = gh
        self.repo = repo
        self.cfg = cfg
        self.default = cfg["default_branch"]
        self.now = now or datetime.now(timezone.utc)
        self.sleep = sleep
        self.clock = clock
        self.deadline = deadline
        self.seq = seq                      # this run's chain sequence number (unique event keys)
        self.hmac_key = hmac_key
        self.findings: list[dict] = []      # events: emitted once, when their source is first audited
        self.conditions: dict[str, dict] = {}   # open conditions: re-derived every run while they hold
        self.ledger: list[str] = []
        self.notes: list[str] = []
        self._slept = False
        self.backlogs: dict[str, dict] = {}
        self._defined: dict = {}         # run id -> (definition proven, why)
        self._on_main_cache: dict = {}
        self._siblings: dict = {}

    def flag(self, rule: str, key: str, summary: str) -> None:
        self.findings.append(finding(rule, key, summary))

    def condition(self, rule: str, key: str, summary: str) -> None:
        self.conditions[key] = finding(rule, key, summary)

    def _on_main(self, sha: str) -> bool:
        """The commit is on the default branch (ref type branch, not a tag or
        other ref that only shares the name)."""
        cache = self._on_main_cache
        if sha not in cache:
            try:
                st = self.gh.get(f"repos/{self.repo}/compare/{sha}...{urllib.parse.quote(self.default)}").get("status") \
                    if SHA_RE.match(sha) else None
            except NotFound:
                st = None
            cache[sha] = st in ("ahead", "identical")
        return cache[sha]

    SECTIONS = ("commits", "records", "checks", "runs", "branches")

    def begin(self, section: str) -> None:
        """Start a budgeted section. It may use its guaranteed share
        (`api_section_shares`) plus whatever the total budget has left after
        the shares of the sections still to come, so no section can starve a
        later one (verify5 V5-I1)."""
        total = getattr(self, "call_limit", None)
        shares = self.cfg.get("api_section_shares") or {}
        self.section = section
        self.section_start = self.gh.count
        if total is None:
            self.section_limit = None
            return
        later = self.SECTIONS[self.SECTIONS.index(section) + 1:]
        reserved = sum(int(shares.get(x, 0)) for x in later)
        self.section_limit = max(self.gh.count + int(shares.get(section, 0)), total - reserved)

    def sibling_base(self, branch: str | None) -> str | None:
        """Extra guard for a pull_request_target run (the definition proof is the
        main one): any PR, open or closed, from the same head branch whose base
        is not the default branch could have triggered it with that base's
        definition. An incomplete listing fails closed."""
        if not branch:
            return "no head branch"
        if branch not in self._siblings:
            owner = self.repo.split("/", 1)[0]
            q = urllib.parse.urlencode({"head": f"{owner}:{branch}", "state": "all"})
            prs, complete = self.gh.collect(f"repos/{self.repo}/pulls?{q}", max_pages=3)
            other = sorted({(p.get("base") or {}).get("ref") for p in prs} - {self.default})
            self._siblings[branch] = (f"a PR from head {branch!r} is based on {other[0]!r}, not {self.default}"
                                      if other else None) if complete else \
                f"more than 300 PRs from head {branch!r}: their bases could not all be read"
        return self._siblings[branch]

    def over_budget(self) -> bool:
        """This section's API budget (shared GITHUB_TOKEN quota) or the time budget is spent."""
        limit = getattr(self, "section_limit", None)
        if limit is None:
            limit = getattr(self, "call_limit", None)
        return self.out_of_time() or (limit is not None and self.gh.count >= limit)

    def backlog(self, section: str, rule: str, left: int, processed: int, detail: str) -> None:
        """A section that could not finish: an open condition, escalated to a
        FLAG (an event, so the front door raises a blocking item) when it
        persists for `backlog_flag_after` runs or when the section was starved
        to zero, naming what is waiting."""
        st = self.backlogs.setdefault(section, {"runs": 0})
        st["runs"] += 1
        self.condition(rule, f"{rule}:{section}-backlog", f"{left} item(s) of {section} not yet checked "
                                                         f"(budget or time); carried to the next run. {detail}")
        n = int(self.cfg["backlog_flag_after"])
        if processed == 0 or st["runs"] == n:
            why = "starved: nothing processed this run" if processed == 0 else f"backlog for {n} runs in a row"
            self.flag(rule, f"{rule}:{section}-backlog:{self.seq}", f"{section} check {why}; {left} waiting. {detail}")

    def out_of_time(self) -> bool:
        return self.deadline is not None and self.clock() >= self.deadline

    # ---- commits
    def range_commits(self, base: str | None, head: str) -> tuple[list[str], dict, bool]:
        """(first-parent chain base..head oldest first, commits by sha, reached base).
        Never raises for size: past `max_range_commits` the newest window is
        audited and the unaudited remainder is FLAGged."""
        cap = int(self.cfg["max_range_commits"])
        commits: dict[str, dict] = {}
        stop_at = base
        if base:
            try:
                first = self.gh.get(f"repos/{self.repo}/compare/{base}...{head}?per_page=100")
            except NotFound:
                self.flag("R2", f"R2:base-gone:{base}:{head}",
                          f"last audited head {base[:12]} no longer exists: history was rewritten (force push)")
                first = None
            if first is not None:
                status = first.get("status")
                if status in ("diverged", "behind"):
                    self.flag("R2", f"R2:rewrite:{base}:{head}",
                              f"default branch history no longer contains the last audited head {base[:12]} "
                              f"(compare status {status}): force push or ruleset bypass")
                if status in ("identical", "behind"):
                    return [], {}, True
                stop_at = ((first.get("merge_base_commit") or {}).get("sha")) or base
                total = int(first.get("total_commits") or 0)
                if total <= cap:
                    batch = list(first.get("commits") or [])
                    page = 2
                    while len(batch) < total:
                        more = self.gh.get(f"repos/{self.repo}/compare/{base}...{head}?per_page=100&page={page}")
                        got = more.get("commits") or []
                        if not got:
                            raise AuditError("compare pagination ended before total_commits")
                        batch.extend(got)
                        page += 1
                    commits = {c["sha"]: c for c in batch}
                else:
                    self.flag("R2", f"R2:range-too-large:{base}:{head}",
                              f"{total} commits since the last audited head {base[:12]}, over {cap}: only the newest "
                              f"first-parent window is audited; older commits in the range are UNAUDITED")
                    stop_at = None
            else:
                stop_at = None
        fallback = stop_at is None and bool(base)
        if not commits:
            listed, _ = self.gh.collect(f"repos/{self.repo}/commits?sha={head}", max_pages=max(1, cap // 100))
            commits = {c["sha"]: c for c in listed}
        chain: list[str] = []
        cur = head
        reached = False
        while cur in commits:
            if cur == stop_at:
                reached = True
                break
            chain.append(cur)
            parents = commits[cur].get("parents") or []
            if not parents:
                break
            cur = parents[0].get("sha")
        if cur == stop_at or fallback:
            reached = True      # (the fallback was FLAGged already)
        chain.reverse()
        return chain, commits, reached

    def pulls_for(self, sha: str, committed: str | None = None) -> list[dict]:
        """Association can lag a fresh merge by seconds: sleep ONCE per run, and
        only for a commit committed in the last 10 minutes."""
        try:
            pulls = self.gh.get(f"repos/{self.repo}/commits/{sha}/pulls") or []
        except NotFound:
            return []
        fresh = (ts(committed) or datetime.min.replace(tzinfo=timezone.utc)) > self.now - timedelta(minutes=10)
        if not pulls and fresh and not self._slept:
            self._slept = True
            self.sleep(15)
            pulls = self.gh.get(f"repos/{self.repo}/commits/{sha}/pulls") or []
        return pulls

    def audit_commits(self, last: str | None, head: str) -> str:
        """Audit last..head along the first-parent chain; returns the new audited
        head. Processes at most `max_commits_per_run` commits (and stops at the
        time budget), so a long range is audited over several runs instead of
        wedging; stops early at a merge whose run has not finished."""
        base = last or self.cfg.get("baseline_sha") or None
        if base == head:
            return head
        chain, commits, reached = self.range_commits(base, head)
        if not chain:
            return head
        if base and not reached:
            self.flag("R2", f"R2:first-parent-break:{base}:{head}",
                      f"the first-parent chain from {head[:12]} does not reach the last audited head {base[:12]}: "
                      f"a merge whose first parent is not the default branch (not a GitHub merge), or a truncated range")
        side = len(commits) - len(chain)
        if side > 0:
            self.ledger.append(f"{side} second-parent commit(s) arrived through merge commits (covered by their PRs)")
        cap = int(self.cfg["max_commits_per_run"])
        audited = base or ""
        for i, sha in enumerate(chain):
            if i >= cap or self.over_budget():
                self.notes.append(f"stopped after {i} of {len(chain)} commits (per-run budget); the next run continues "
                                  f"from {audited[:12]}")
                return audited
            c = commits[sha]
            committer = (c.get("committer") or {}).get("login")
            info = c.get("commit") or {}
            verified = (info.get("verification") or {}).get("verified") is True
            github_made = committer == self.cfg["github_committer"] and verified
            pulls = self.pulls_for(sha, (info.get("committer") or {}).get("date"))
            merged = next((p for p in pulls if p.get("merged_at") and p.get("merge_commit_sha") == sha), None)
            if merged is None:
                later = set(chain[i + 1:])
                carrier = next((p for p in pulls if p.get("merged_at") and p.get("merge_commit_sha") in later), None)
                if carrier is not None and github_made:
                    self.ledger.append(f"{sha[:12]} rebase-merged commit of PR #{carrier['number']} (merged later in this range)")
                else:
                    author = ((c.get("author") or {}).get("login")) or ((info.get("author") or {}).get("name"))
                    self.flag("R2", f"R2:direct:{sha}",
                              f"{sha[:12]} is on {self.default} but is not a PR merge made by GitHub: direct push "
                              f"(author {author!r}, committer {committer!r}, signature verified {verified}; pusher, "
                              f"when known, in the PushEvent FLAGs)")
                    self.ledger.append(f"{sha[:12]} DIRECT PUSH")
                audited = sha
                continue
            pr = self.gh.get(f"repos/{self.repo}/pulls/{merged['number']}")
            by = (pr.get("merged_by") or {}).get("login")
            n = pr["number"]
            if not github_made:
                self.flag("R2", f"R2:not-github-merge:{sha}",
                          f"{sha[:12]} is PR #{n}'s merge commit but GitHub did not create it (committer "
                          f"{committer!r}, signature verified {verified}): pushed to {self.default}, and the push "
                          f"marked the PR merged")
            if (pr.get("head") or {}).get("sha") == sha:
                self.flag("R2", f"R2:laundered:{sha}",
                          f"{sha[:12]} is PR #{n}'s own head commit, so the PR was 'merged' by pushing its head to "
                          f"{self.default} (merged_by {by!r}): a direct push shown as a merge")
            if by == self.cfg["bot_merger"]:
                verdict = self.verify_bot_merge(pr, sha)
                if verdict == "pending":
                    self.notes.append(f"{sha[:12]} PR #{n}: merging run still in progress; re-checked next run")
                    return audited
                self.ledger.append(f"{sha[:12]} PR #{n} merged by {by}: {verdict}")
            elif by in self.cfg["operator_logins"]:
                title = clean(pr.get("title") or "")
                labels = {(lb.get("name") or "") for lb in pr.get("labels") or []}
                pat = re.compile(self.cfg["operator_7a_pattern"])
                marked = bool(pat.search(title)) or any(pat.fullmatch(x) for x in labels)
                if marked:
                    self.flag("R1", f"R1:operator:{sha}",
                              f"{sha[:12]} PR #{n} (marked 7a) merged by {by} (operator login: the operator, a v1 agent "
                              f"session or the front door, A11). Expected for 7a PRs; confirm")
                else:
                    self.flag("R1", f"R1:operator-unmarked:{sha}",
                              f"{sha[:12]} PR #{n} (NOT marked 7a) merged by {by}: an ordinary PR should be merged by "
                              f"merge.yml; confirm who merged it and why")
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
        q = urllib.parse.urlencode({"created": f"{iso(lo)}..{iso(hi)}"})
        try:
            runs, complete = self.gh.collect(f"repos/{self.repo}/actions/workflows/{mpath.rsplit('/', 1)[-1]}/runs?{q}",
                                             key="workflow_runs", max_pages=5)
        except NotFound:
            runs, complete = [], True
        seen: list[str] = [] if complete else ["more than 500 merge.yml runs in the window; not all read"]
        pending = False
        max_pending = timedelta(minutes=int(self.cfg["max_pending_minutes"]))
        for run in sorted(runs, key=lambda r: r.get("created_at") or "", reverse=True):
            rid = run.get("id")
            why = merge_run_untrusted(run, self.repo, self.default, mpath)
            if not why and run.get("event") == "pull_request_target":
                why = self.sibling_base(run.get("head_branch"))
            if why:
                seen.append(f"run {rid} untrusted: {why}")
                continue
            created = ts(run.get("created_at"))
            if created is not None and created > merged_at:
                continue
            if run.get("event") == "schedule" and not self._on_main(run.get("head_sha") or ""):
                seen.append(f"run {rid}: schedule run whose commit is not on {self.default} (a ref named like it)")
                continue
            if run.get("status") != "completed":
                if created is not None and self.now - created <= max_pending:
                    pending = True
                else:
                    seen.append(f"run {rid}: still {run.get('status')!r} after {self.cfg['max_pending_minutes']} min")
                continue
            # Any conclusion counts (fleet-pilot#3: the run fails when another
            # candidate errored or was refused, after merging and logging this
            # one); the trust is the run's metadata plus its own log lines.
            try:
                z = self.gh.download(f"repos/{self.repo}/actions/runs/{rid}/logs", int(self.cfg["max_log_bytes"]))
            except NotFound:
                seen.append(f"run {rid}: logs unavailable")
                continue
            dok, dwhy = log_definition_ok(z, expected_ref, 4 * int(self.cfg["max_log_bytes"]))
            if not dok:
                seen.append(f"run {rid}: {dwhy}")
                continue
            # A MERGED line from a run proven to run main's merge.yml counts for the
            # PR it names, whichever PR or schedule triggered the run.
            ok, why = log_proves_merge(z, n, head, int(rid), expected_ref, 4 * int(self.cfg["max_log_bytes"]))
            if ok:
                return f"verified by run {rid}"
            seen.append(f"run {rid}: {why}")
        if pending:
            return "pending"
        detail = "; ".join(seen[:8]) or "no merge.yml run in the window"
        self.flag("R1", f"R1:provenance:{sha}",
                  f"{sha[:12]} PR #{n} merged by {self.cfg['bot_merger']} at head {head[:12]} with no completed "
                  f"default-branch merge.yml run that logged its inline recomputation and the merge ({detail})")
        return "FLAG (no provenance)"

    # ---- R2: push events (its value is the pusher's login; the commit audit
    # above is the complete record of what landed)
    def push_events(self, cursor: int | None, seen: list[int]) -> tuple[int | None, list[int]]:
        floor = min(seen) if seen else cursor
        events, complete = self.gh.collect(f"repos/{self.repo}/events", max_pages=3,
                                           stop=(lambda e: floor is not None and str(e.get("id", "")).isdigit()
                                                 and int(e["id"]) < floor))
        events = [e for e in events if str(e.get("id", "")).isdigit()]
        ids = [int(e["id"]) for e in events]
        newest = max(ids + ([cursor] if cursor is not None else [])) if (ids or cursor is not None) else None
        new_seen = sorted(ids)[-300:]
        if cursor is None:
            self.notes.append("first run: push-event cursor set, earlier pushes covered by the commit audit")
            return newest, new_seen
        if len(events) >= 300 and min(ids) > cursor:
            self.flag("R2", f"R2:events-gap:{self.seq}", f"more than 300 repo events since the last run "
                                                          f"(after event {cursor}): pushes in the gap unread "
                                                          f"(the commit audit still covers what landed)")
        known = set(seen)
        for e in sorted(events, key=lambda x: int(x["id"])):
            eid = int(e["id"])
            if eid in known or (not seen and eid <= cursor) or e.get("type") != "PushEvent":
                continue
            p = e.get("payload") or {}
            if p.get("ref") != f"refs/heads/{self.default}":
                continue
            actor = (e.get("actor") or {}).get("login")
            head = p.get("head") or ""
            ok = False
            if SHA_RE.match(head):
                ok = any(x.get("merged_at") and x.get("merge_commit_sha") == head
                         for x in self.pulls_for(head, e.get("created_at")))
            if not ok:
                self.flag("R2", f"R2:push:{eid}",
                          f"push to {self.default} by {actor!r} at {e.get('created_at')}: head {head[:12]} "
                          f"(before {str(p.get('before', ''))[:12]}) is not a PR merge commit")
            else:
                self.ledger.append(f"push {eid} by {actor}: PR merge {head[:12]}")
        return newest, new_seen

    # ---- R3: controls
    def _vars(self, vars_ctx: dict) -> dict:
        public = set(self.cfg.get("public_vars") or [])
        out = {}
        for k, v in sorted(vars_ctx.items()):
            if k in public:
                out[k] = v
            else:
                mac = hashlib.sha256((self.hmac_key + "\0" + str(v)).encode()).hexdigest()[:16]
                out[k] = f"hash:{mac}"
        return out

    def controls(self, prev: dict | None, vars_ctx: dict) -> dict:
        r, d = self.repo, self.default
        rulesets = {}
        for x in self.gh.paged(f"repos/{r}/rulesets?includes_parents=true", limit=3):
            rid = str(x["id"])
            summary = {k: x.get(k) for k in ("name", "enforcement", "updated_at", "target", "source_type")}
            try:
                detail = self.gh.get(f"repos/{r}/rulesets/{x['id']}")
                summary["detail"] = h({k: v for k, v in (detail or {}).items() if k not in ("_links", "node_id")})
            except NotFound:
                summary["detail"] = None
            rulesets[rid] = summary
        rules = self.gh.paged(f"repos/{r}/rules/branches/{urllib.parse.quote(d)}", limit=5)
        branch = self.gh.get(f"repos/{r}/branches/{urllib.parse.quote(d)}")
        wf_list = self.gh.paged(f"repos/{r}/actions/workflows", key="workflows", limit=5)
        wfs = {w.get("path"): {"state": w.get("state"), "updated_at": w.get("updated_at")} for w in wf_list}
        labels = {}
        for name in self.cfg["kill_switch_labels"]:
            try:
                lab = self.gh.get(f"repos/{r}/labels/{urllib.parse.quote(name, safe='')}")
                labels[name] = {k: lab.get(k) for k in ("id", "name", "color")}
            except NotFound:
                labels[name] = None
        snap = {"rulesets": rulesets, "rules": h(rules),
                "protection": {"protected": branch.get("protected"), "protection": h(branch.get("protection"))},
                "workflows": wfs, "labels": labels, "vars": self._vars(vars_ctx)}
        exp = self.cfg.get("expected_ruleset")
        if exp and not any(v["name"] == exp and v["enforcement"] == "active" for v in rulesets.values()):
            now_sets = ", ".join("{}={}".format(v["name"], v["enforcement"]) for v in rulesets.values()) or "none"
            self.condition("R3", "R3:ruleset-missing", f"no active ruleset named {exp!r} on this repo (rulesets now: {now_sets})")
        for name, lab in labels.items():
            if lab is None:
                self.condition("R3", f"R3:label-missing:{name}", f"kill-switch label {name!r} does not exist")
        for wf in self.cfg["watched_workflows"]:
            if wf not in wfs:
                self.condition("R3", f"R3:workflow-missing:{wf}", f"watched workflow {wf} does not exist on this repo")
            elif wfs[wf]["state"] != "active":
                self.condition("R3", f"R3:workflow-state:{wf}", f"{wf} state is {wfs[wf]['state']!r}, not active")
        if prev:
            for part, label in (("rulesets", "rulesets"), ("rules", "rules applying to the default branch"),
                                ("protection", "branch protection summary"), ("workflows", "workflow set/state"),
                                ("labels", "kill-switch labels"), ("vars", "repo variables")):
                old, new = prev.get(part), snap[part]
                if old != new:
                    self.flag("R3", f"R3:{part}:{self.seq}",
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
        """issues/events is the repo's whole history, newest first: read only
        down to the cursor (bounded), never the whole list."""
        if cursor is None:
            first, _ = self.gh.collect(f"repos/{self.repo}/issues/events", max_pages=1)
            ids = [e["id"] for e in first if isinstance(e.get("id"), int)]
            return max(ids) if ids else 0
        events, complete = self.gh.collect(
            f"repos/{self.repo}/issues/events", max_pages=int(self.cfg["max_issue_event_pages"]),
            stop=lambda e: isinstance(e.get("id"), int) and e["id"] <= cursor)
        if not complete:
            self.flag("R3", f"R3:issue-events-gap:{self.seq}",
                      f"more than {100 * int(self.cfg['max_issue_event_pages'])} issue events since the last run "
                      f"(after event {cursor}): kill-switch label changes in the gap unread")
        ids = [e["id"] for e in events if isinstance(e.get("id"), int)]
        watched = set(self.cfg["kill_switch_labels"])
        for e in events:
            if not isinstance(e.get("id"), int):
                continue
            if e.get("event") in ("labeled", "unlabeled") and (e.get("label") or {}).get("name") in watched:
                num = (e.get("issue") or {}).get("number")
                self.flag("R3", f"R3:label-event:{e['id']}",
                          f"{(e.get('actor') or {}).get('login')!r} {e['event']} {(e.get('label') or {}).get('name')!r} "
                          f"on #{num} at {e.get('created_at')}")
        return max(ids + [cursor])

    # ---- R7: review records
    def _record_like(self, author: str | None, body: str) -> bool:
        return author in set(self.cfg["trusted_record_authors"]) and bool(RECORD_LIKE_RE.search(body) or CRITICAL_LIKE_RE.search(body))

    def records(self, prev: dict | None, cursor: dict | None, prev_backlog: dict | None = None) -> tuple[dict, dict]:
        """Returns (records, cursor). New and edited comments come from repo-wide
        `since` listings (bounded, resumable through the cursor); reviews from
        the PRs updated since the cursor; every tracked record is also
        re-fetched one by one in rotation (`record_verify_per_run`), which is
        what catches deletions, since listings never show a deleted item."""
        r = self.repo
        self.backlogs["records"] = dict(prev_backlog or {"runs": 0})
        prev = dict(prev or {})
        horizon = self.now - timedelta(days=int(self.cfg["record_scope_days"]))
        first = cursor is None
        cursor = dict(cursor or {})
        since0 = iso(horizon)
        snap: dict[str, dict] = {k: v for k, v in prev.items() if (ts(v.get("at")) or self.now) >= horizon}
        pages = int(self.cfg["max_record_pages"])

        def observe(key: str, n: int, body: str, author: str | None, created: str | None, updated: str | None) -> None:
            digest = hashlib.sha256(body.encode()).hexdigest()
            old = snap.get(key)
            if old is None:
                if not self._record_like(author, body):
                    return
                snap[key] = {"pr": n, "h": digest, "author": author, "at": created, "v": iso(self.now)}
                if updated and created and updated != created:
                    self.flag("R7", f"R7:edited-before-snapshot:{key}:{self.seq}",
                              f"review record {key} on PR #{n} by {author!r} was already edited when first seen "
                              f"(created {created}, updated {updated})")
                return
            old["v"] = iso(self.now)
            if old["h"] != digest:
                self.flag("R7", f"R7:edited:{key}:{self.seq}",
                          f"review record {key} on PR #{n} by {old.get('author')!r} was edited since the last run")
                old["h"] = digest

        def pr_num(url: str | None) -> int | None:
            m = re.search(r"/(?:pulls|issues)/([0-9]+)$", url or "")
            return int(m.group(1)) if m else None

        # issue comments on PRs (repo-wide, oldest update first, resumable)
        for kind, path, url_key in (("ic", "issues/comments", "issue_url"), ("rc", "pulls/comments", "pull_request_url")):
            since = cursor.get(kind) or since0
            q = urllib.parse.urlencode({"since": since, "sort": "updated", "direction": "asc"})
            items, complete = self.gh.collect(f"repos/{r}/{path}?{q}", max_pages=pages)
            for c in items:
                if kind == "ic" and "/pull/" not in (c.get("html_url") or ""):
                    continue
                n = pr_num(c.get(url_key))
                if n is None:
                    continue
                observe(f"{kind}:{c.get('id')}", n, c.get("body") or "", (c.get("user") or {}).get("login"),
                        c.get("created_at"), c.get("updated_at"))
            if items:
                cursor[kind] = max(c.get("updated_at") or since for c in items)
            if not complete:
                self.notes.append(f"R7 {path}: more than {pages} pages since {since}; the rest is read next run")
        # reviews: PRs updated since the cursor (sorted by update, newest first; stop at the cursor)
        since_pr = ts(cursor.get("prs") or since0) or horizon
        prs, complete = self.gh.collect(f"repos/{r}/pulls?state=all&sort=updated&direction=desc", max_pages=pages,
                                        stop=lambda p: (ts(p.get("updated_at")) or self.now) < since_pr - timedelta(minutes=5))
        if not complete:
            self.flag("R7", f"R7:reviews-truncated:{self.seq}",
                      f"more than {pages * 100} PRs updated since {iso(since_pr)}: new reviews on the older ones were "
                      f"not read (tracked records are still re-verified in rotation)")
        # Oldest update first, so a budget stop leaves the cursor at the last PR read.
        stopped = False
        cap = int(self.cfg["records_review_reads_per_run"])
        for i, p in enumerate(sorted(prs, key=lambda x: x.get("updated_at") or "")):
            if i >= cap or self.over_budget():      # a cap of its own: cheap PR edits cannot buy reads
                stopped = True
                break
            n = p["number"]
            for c in self.gh.collect(f"repos/{r}/pulls/{n}/reviews", max_pages=pages)[0]:
                if c.get("state") == "PENDING":
                    continue
                observe(f"rv:{n}:{c.get('id')}", n, c.get("body") or "", (c.get("user") or {}).get("login"),
                        c.get("submitted_at"), None)
            if p.get("updated_at"):
                cursor["prs"] = max(p["updated_at"], cursor.get("prs") or "")
        if stopped:
            done = sum(1 for p in prs if (p.get("updated_at") or "") <= (cursor.get("prs") or ""))
            self.backlog("records", "R7", len(prs) - done, done, "Reviews of recently updated PRs, oldest update first.")
        else:
            self.backlogs["records"] = {"runs": 0}
        if not prs and first and not stopped:
            cursor["prs"] = iso(self.now)
        # rotation: re-fetch the least recently verified tracked records
        k = int(self.cfg["record_verify_per_run"])
        for key in sorted((x for x in snap if x in prev), key=lambda x: snap[x].get("v") or "")[:k]:
            if self.over_budget():
                break           # the rest stay least-recently-verified and come first next run
            rec = snap[key]
            if rec.get("v") == iso(self.now):
                continue
            kind, _, rest = key.partition(":")
            if kind == "ic":
                path = f"repos/{r}/issues/comments/{rest}"
            elif kind == "rc":
                path = f"repos/{r}/pulls/comments/{rest}"
            else:
                n, _, rid = rest.partition(":")
                path = f"repos/{r}/pulls/{n}/reviews/{rid}"
            try:
                c = self.gh.get(path)
            except NotFound:
                self.flag("R7", f"R7:deleted:{key}",
                          f"review record {key} on PR #{rec['pr']} by {rec.get('author')!r} was deleted since it was last verified")
                del snap[key]
                continue
            observe(key, rec["pr"], c.get("body") or "", (c.get("user") or {}).get("login"),
                    c.get("created_at") or c.get("submitted_at"), c.get("updated_at"))
        return snap, cursor

    # ---- R4: forged checks (open conditions)
    def forged_checks(self, ok_ids: list[int], bad: dict, seen: dict | None = None,
                      prev_backlog: dict | None = None) -> tuple[list[int], dict, dict]:
        """R4 with a bounded number of check-run reads per run: open PRs whose
        head is new or changed come first, then the least recently checked.
        A PR not read this run keeps its known forged-check conditions (same
        head) and is read on a later run. Returns (ok ids, bad, seen)."""
        r = self.repo
        name = self.cfg["verdict_check_name"]
        vpath = self.cfg["verdict_workflow"]
        ok = set(ok_ids)
        seen = dict(seen or {})
        new_bad: dict[str, dict] = {}
        prs, complete = self.gh.collect(f"repos/{r}/pulls?state=open", max_pages=5)
        if not complete:
            self.condition("R4", "R4:scan-truncated", "more than 500 open PRs: forged checks on the rest unread")
        q = urllib.parse.urlencode({"check_name": name, "filter": "all"})
        heads = {str(p["number"]): (p.get("head") or {}).get("sha") for p in prs}

        # Never-read PRs and the least recently read ones take turns, so neither
        # a flood of new PRs nor a backlog of old ones starves the other.
        fresh = [p for p in prs if str(p["number"]) not in seen]
        old = sorted((p for p in prs if str(p["number"]) in seen), key=lambda p: seen[str(p["number"])].get("at") or "")
        mixed = [x for pair in zip(old, fresh) for x in pair] + old[len(fresh):] + fresh[len(old):]
        cap = int(self.cfg["checks_prs_per_run"])
        read = 0
        backlog = 0
        for p in mixed:
            n, head = str(p["number"]), heads[str(p["number"])]
            if not head:
                continue
            if read >= cap or self.over_budget():
                backlog += 1
                for cid, b in (bad or {}).items():      # keep what is known for this head
                    if isinstance(b, dict) and b.get("pr") == n and b.get("head") == head:
                        new_bad[cid] = b
                        self.condition("R4", f"R4:{cid}", f"{name} check run {cid} on PR #{n} {b.get('why')}")
                continue
            read += 1
            for cr in self.gh.collect(f"repos/{r}/commits/{head}/check-runs?{q}", key="check_runs", max_pages=3)[0]:
                cid = cr.get("id")
                okkey = f"{cid}:{cr.get('conclusion')}"     # a later conclusion change is re-checked
                if cr.get("status") != "completed" or okkey in ok:
                    continue
                known = (bad or {}).get(str(cid))
                why = (known.get("why") if isinstance(known, dict) else known) or self._check_untrusted(cr, vpath, p)
                if why:
                    new_bad[str(cid)] = {"why": why, "pr": n, "head": head}
                    self.condition("R4", f"R4:{cid}", f"{name} check run {cid} on PR #{n} {why}")
                else:
                    ok.add(okkey)
            seen[n] = {"head": head, "at": iso(self.now)}
        self.backlogs["checks"] = dict(prev_backlog or {"runs": 0})
        if backlog:
            self.backlog("checks", "R4", backlog, read, f"Per-run limit {cap} PRs; least recently read go first.")
        else:
            self.backlogs["checks"] = {"runs": 0}
        seen = {k: v for k, v in seen.items() if k in heads}
        return sorted(str(x) for x in ok)[-2000:], new_bad, seen

    def _check_untrusted(self, cr: dict, vpath: str, pr: dict | None = None) -> str | None:
        """A review-verdict check run is trusted only as a job of a verdict.yml
        run whose definition the Actions service records as the default
        branch's (`log_definition_ok`), with the check run's conclusion equal to
        the job's. A check run created through the API becomes a runnerless
        job of the run that created it (live: forgery 140152689638 is a job of
        a ci.yml run), so the path check and the definition proof are what
        stop it; do not reorder or drop them. A runnerless job is accepted only
        when it was cancelled or skipped (verdict.yml's concurrency group,
        #594) and the check run says the same: it can never pass a merge."""
        r = self.repo
        app = (cr.get("app") or {}).get("id")
        if app != int(self.cfg["actions_app_id"]):
            return f"is from app {app!r}, not GitHub Actions"
        try:
            job = self.gh.get(f"repos/{r}/actions/jobs/{cr.get('id')}")
        except NotFound:
            return "is not an Actions job (forged)"
        if cr.get("conclusion") != job.get("conclusion"):
            return (f"says {cr.get('conclusion')!r} but its job concluded {job.get('conclusion')!r} "
                    f"(the check run was rewritten)")
        try:
            run = self.gh.get(f"repos/{r}/actions/runs/{job.get('run_id')}")
        except NotFound:
            return f"belongs to run {job.get('run_id')}, which does not exist"
        if run.get("path") != vpath:
            return f"is a job of {run.get('path')!r}, not {vpath} (a same-named job in another workflow, or created through the API)"
        if (run.get("repository") or {}).get("full_name") != r:
            return "is a job of a run in another repository"
        if (run.get("head_repository") or {}).get("full_name") != r:
            return "is a job of a run whose head repository is not this repository (fork)"
        if run.get("event") != "pull_request_target":
            return f"is a job of a {vpath} run on event {run.get('event')!r} (definition not from the default branch)"
        no_runner = not job.get("runner_name") or not job.get("steps")
        if no_runner:
            if job.get("conclusion") in ("cancelled", "skipped"):
                return None
            return (f"was created through the API (runner_name={job.get('runner_name')!r}, "
                    f"steps={len(job.get('steps') or [])}, conclusion {job.get('conclusion')!r})")
        why = pr_target_untrusted(run, self.default) or self.sibling_base(run.get("head_branch"))
        if why:
            return f"is a job of an untrusted {vpath} run ({why})"
        cache = self._defined
        rid = run.get("id")
        if rid not in cache:
            try:
                z = self.gh.download(f"repos/{r}/actions/runs/{rid}/logs", int(self.cfg["max_log_bytes"]))
                cache[rid] = log_definition_ok(z, f"{r}/{vpath}@refs/heads/{self.default}", 4 * int(self.cfg["max_log_bytes"]))
            except NotFound:
                cache[rid] = (False, "its run's logs are unavailable (definition unproven)")
        dok, dwhy = cache[rid]
        return None if dok else f"is a job of a {vpath} run whose definition is not proven to be the default branch's ({dwhy})"

    # ---- R5: workflows run from outside the default branch
    def foreign_runs(self, cursor: dict | None, prev_backlog: dict | None = None) -> dict:
        """R5 over workflow runs since the cursor, oldest first. A run is flagged
        when the workflow file it ran (the blob at its head_sha) is neither
        main's blob at the merge base of that commit (the branch did not touch
        the file, so the definition is one main had) nor main's current blob. A
        file the branch added or changed is flagged; a stale branch that merely
        predates a later change on main is not. Bounded by the per-run API
        budget and deadline: what is not processed stays behind the cursor for
        the next run, with one backlog condition."""
        r = self.repo
        cursor = dict(cursor or {})
        since = cursor.get("at") or iso(self.now - timedelta(minutes=30))
        last_id = int(cursor.get("id") or 0)
        q = urllib.parse.urlencode({"created": f">={since}"})
        runs, complete = self.gh.collect(f"repos/{r}/actions/runs?{q}", key="workflow_runs",
                                         max_pages=int(self.cfg["max_run_pages"]))
        if not complete:
            self.flag("R5", f"R5:runs-overflow:{self.seq}",
                      f"more than {100 * int(self.cfg['max_run_pages'])} workflow runs created since {since}: the older "
                      f"ones in that window were not checked (a run flood)")
        default_blobs: dict | None = None
        trees: dict[str, dict] = {}
        bases: dict[str, str | None] = {}

        def tree_of(sha: str) -> dict:
            if sha not in trees:
                try:
                    trees[sha] = blobs_at(self.gh, r, sha) if SHA_RE.match(sha) else {}
                except NotFound:
                    trees[sha] = {}
            return trees[sha]

        def base_of(sha: str) -> str | None:
            if sha not in bases:
                try:
                    cmp = self.gh.get(f"repos/{r}/compare/{urllib.parse.quote(self.default)}...{sha}") \
                        if SHA_RE.match(sha) else {}
                    bases[sha] = (cmp.get("merge_base_commit") or {}).get("sha")
                except NotFound:
                    bases[sha] = None
            return bases[sha]

        new = sorted((x for x in runs if int(x.get("id") or 0) > last_id), key=lambda x: int(x["id"]))
        self.backlogs["runs"] = dict(prev_backlog or {"runs": 0})
        # Runs left unchecked last time that are no longer listed were deleted
        # before they could be checked: the listing is the evidence.
        listed = {int(x.get("id") or 0) for x in runs}
        for p in cursor.get("pending") or []:
            if complete and int(p.get("id") or 0) not in listed:
                self.flag("R5", f"R5:run-vanished:{p.get('id')}",
                          f"workflow run {p.get('id')} ({p.get('path')}, ref {p.get('branch')!r}, actor {p.get('actor')!r}) "
                          f"was listed but unchecked last run and is gone now (deleted before R5 could check it)")
        done_id, stopped_at = last_id, None
        processed = 0
        for run in new:
            if self.over_budget():
                stopped_at = run
                break
            path = run.get("path") or ""
            done_id = int(run["id"])
            processed += 1
            if not path.startswith(".github/workflows/"):
                continue        # dynamic workflows (Pages, Dependabot): GitHub-defined
            path = path.split("@", 1)[0]
            event = run.get("event")
            if event in DEFAULT_DEFINED_EVENTS:
                continue
            sha = run.get("head_sha") or ""
            if run.get("head_branch") == self.default and event != "pull_request":
                # A tag (or other ref) named like the default branch reports the
                # same head_branch: the commit must be on the default branch.
                if self._on_main(sha):
                    continue
                self.flag("R5", f"R5:run:{run.get('id')}",
                          f"workflow run {run.get('id')} ({path}, event {event!r}) reports ref {self.default!r} but its "
                          f"commit {sha[:12]} is not on the default branch (a tag or other ref named "
                          f"{self.default!r}): it ran a definition the default branch does not hold")
                continue
            ran = tree_of(sha).get(path)
            if default_blobs is None:
                default_blobs = blobs_at(self.gh, r, self.default)
            if ran is not None and ran == default_blobs.get(path):
                continue
            base = base_of(sha)
            at_base = tree_of(base).get(path) if base else None
            retired = set(self.cfg.get("retired_workflow_blobs") or [])
            # Only main's version at THIS commit's merge base, and only while main
            # still has the file and that version is not retired (verify5 V5-M1).
            if ran is not None and ran == at_base and path in default_blobs and ran not in retired:
                continue        # unchanged on the branch: main's definition at the branch point
            self.flag("R5", f"R5:run:{run.get('id')}",
                      f"workflow run {run.get('id')} ({path}, event {event!r}, ref {clean(run.get('head_branch'))!r}, "
                      f"actor {(run.get('actor') or {}).get('login')!r}) ran a definition the branch changed or added "
                      f"({'absent on the default branch at the branch point' if at_base is None else 'differs from the default branch at the branch point'})")
        if stopped_at is not None:
            waiting = [x for x in new if int(x["id"]) > done_id]
            cursor["pending"] = [{"id": x.get("id"), "path": clean(x.get("path"), 120), "branch": clean(x.get("head_branch"), 120),
                                  "actor": (x.get("actor") or {}).get("login")} for x in waiting[:50]]
            oldest = waiting[0]
            age = self.now - (ts(oldest.get("created_at")) or self.now)
            if age > timedelta(minutes=int(self.cfg["backlog_age_flag_minutes"])):
                # Evidence that survives a later deletion of that run.
                self.flag("R5", f"R5:run-unchecked:{oldest.get('id')}",
                          f"workflow run {oldest.get('id')} ({clean(oldest.get('path'), 120)}, ref "
                          f"{clean(oldest.get('head_branch'), 80)!r}, actor {(oldest.get('actor') or {}).get('login')!r}, "
                          f"created {oldest.get('created_at')}) is still unchecked after {int(age.total_seconds() // 60)} "
                          f"min (R5 backlog); {len(waiting)} run(s) waiting")
            self.backlog("runs", "R5", len(waiting), processed,
                         f"Oldest waiting: run {oldest.get('id')} ({clean(oldest.get('path'), 120)}, ref "
                         f"{clean(oldest.get('head_branch'), 80)!r}, actor {(oldest.get('actor') or {}).get('login')!r}, "
                         f"created {oldest.get('created_at')})")
            cursor["id"] = done_id
            start = ts(stopped_at.get("created_at")) or self.now
            cursor["at"] = iso(start - timedelta(minutes=1))
            return cursor
        self.backlogs["runs"] = {"runs": 0}
        cursor["pending"] = []
        if runs:
            cursor["id"] = max([last_id] + [int(x.get("id") or 0) for x in runs])
            cursor["at"] = iso(self.now - timedelta(minutes=10))
        else:
            cursor.setdefault("at", since)
        return cursor

    def branch_workflows(self, prev: dict | None) -> dict:
        r = self.repo
        prev = prev or {}
        snap = {}
        branches, complete = self.gh.collect(f"repos/{r}/branches", max_pages=int(self.cfg["max_branch_pages"]))
        if not complete:
            self.condition("R5", "R5:branches-truncated",
                           f"more than {100 * int(self.cfg['max_branch_pages'])} branches: tips past that were not checked")
        for b in branches:
            name, tip = b.get("name"), (b.get("commit") or {}).get("sha")
            if name == self.default or not tip:
                continue
            if name in prev and prev[name] == tip:
                snap[name] = tip
                continue
            if self.over_budget():
                self.condition("R5", "R5:branches-backlog", "branch tips not all checked (per-run API budget or time "
                                                             "limit); the rest are checked next run")
                break       # not recorded: re-checked next run (runs-based R5 above is the primary check)
            cmp = self.gh.get(f"repos/{r}/compare/{urllib.parse.quote(self.default)}...{tip}")
            files = cmp.get("files") or []
            touched = [f.get("filename") for f in files
                       if str(f.get("filename", "")).startswith(".github/workflows/")
                       or str(f.get("previous_filename") or "").startswith(".github/workflows/")]
            if touched:
                self.flag("R5", f"R5:{name}:{tip}", f"branch {clean(name)!r} at {tip[:12]} changes workflow files "
                                                    f"(its push workflows already ran): {clean(', '.join(touched[:10]))}")
            elif len(files) >= 300:
                self.flag("R5", f"R5:{name}:{tip}", f"branch {clean(name)!r} at {tip[:12]} changes 300+ files; workflow "
                                                    f"changes cannot be ruled out from the compare API")
            snap[name] = tip
        return snap


# --------------------------------------------------------------------------
# State (run-bound artifact), the chain, and the anchor (findings issue body)
# --------------------------------------------------------------------------

class RunEnv:
    def __init__(self, run_id: int, run_number: int | None = None, workflow_sha: str = "", actor: str = "",
                 event: str = "", rebaseline: str = "", reason: str = "", server: str = "https://github.com",
                 run_attempt: int = 1):
        self.run_id = run_id
        self.run_attempt = run_attempt
        self.run_number = run_number
        self.workflow_sha = workflow_sha
        self.actor = actor
        self.event = event
        self.rebaseline = rebaseline if event == "workflow_dispatch" and rebaseline in ("continue", "fresh") else ""
        self.reason = clean(reason, 300)
        self.server = server


def parse_anchor(body: str | None) -> dict | None:
    if not body or ANCHOR_BEGIN not in body:
        return None
    seg = body.split(ANCHOR_BEGIN, 1)[1].split(ANCHOR_END, 1)[0]
    m = re.search(r"```json\n(.*?)\n```", seg, re.S)
    if not m:
        return None
    try:
        doc = json.loads(m.group(1))
    except ValueError:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        return None
    return doc


def render_anchor(repo: str, entries: list[dict], status: str = "ok", reason: str = "") -> str:
    keep: list[dict] = []
    size = 0
    for e in reversed(entries):
        s = len(canon(e))
        if keep and size + s > ANCHOR_BUDGET:
            break
        keep.append(e)
        size += s
    keep.reverse()
    doc = {"v": 1, "repo": repo, "status": status, "reason": clean(reason, 500), "entries": keep}
    return ("Findings of the merge audit (`.github/workflows/audit.yml`, acardote/personal-assistant-ultra#581). "
            "Each `FLAG` is confirmed by the operator. Written only by the audit.\n\n"
            "The block below is the audit's hash chain (newest entries last). The front door verifies it on every "
            "heartbeat; editing it is detected.\n\n"
            f"{ANCHOR_BEGIN}\n```json\n{canon(doc)}\n```\n{ANCHOR_END}\n")


def find_issue(gh: GitHub, repo: str, cfg: dict) -> tuple[int | None, str | None]:
    """The findings issue: the EARLIEST issue github-actions[bot] created with
    the configured title (a later decoy with the same title is ignored)."""
    title = cfg["findings_issue_title"]
    found: list[dict] = []

    def match(i: dict) -> bool:
        if (i.get("title") == title and "pull_request" not in i
                and (i.get("user") or {}).get("login") == "github-actions[bot]"):
            found.append(i)
            return True
        return False

    # Oldest first, so the issue the first audit run created stays on page 1
    # (no reliance on the `creator` filter accepting a bot login).
    for direction in ("asc", "desc"):     # desc: an issue re-created after the repo's 300th item
        q = urllib.parse.urlencode({"state": "all", "sort": "created", "direction": direction})
        gh.collect(f"repos/{repo}/issues?{q}", max_pages=3, stop=match)
        if found:
            break
    if found:
        return found[0]["number"], found[0].get("body") or ""
    return None, None


def trusted_audit_runs(gh: GitHub, repo: str, cfg: dict, env: RunEnv) -> list[dict]:
    default = cfg["default_branch"]
    wf = cfg["audit_workflow"].rsplit("/", 1)[-1]
    q = urllib.parse.urlencode({"branch": default, "status": "success"})
    try:
        runs, _ = gh.collect(f"repos/{repo}/actions/workflows/{wf}/runs?{q}", key="workflow_runs", max_pages=1)
    except NotFound:
        runs = []
    out = [x for x in runs if x.get("id") != env.run_id
           and audit_run_untrusted(x, repo, default, cfg["audit_workflow"]) is None]
    return sorted(out, key=lambda x: (x.get("run_number") or 0, x.get("id") or 0), reverse=True)


def audit_run_numbers(gh: GitHub, repo: str, cfg: dict, since: str | None) -> tuple[set, bool]:
    """run_numbers of every audit.yml run (any branch, status or conclusion)
    created since `since`: the `created>=` listing, plus the plain newest-first
    list as a second view for listing lag."""
    wf = cfg["audit_workflow"].rsplit("/", 1)[-1]
    q = urllib.parse.urlencode({"created": f">={since}"})
    runs, complete = gh.collect(f"repos/{repo}/actions/workflows/{wf}/runs?{q}", key="workflow_runs", max_pages=10)
    plain, _ = gh.collect(f"repos/{repo}/actions/workflows/{wf}/runs", key="workflow_runs", max_pages=2)
    return {x.get("run_number") for x in runs + plain if isinstance(x.get("run_number"), int)}, complete


def read_state_artifact(gh: GitHub, repo: str, cfg: dict, run: dict) -> dict | None:
    arts = (gh.get(f"repos/{repo}/actions/runs/{run['id']}/artifacts?per_page=100") or {}).get("artifacts") or []
    art = next((a for a in arts if a.get("name") == cfg["state_artifact"] and not a.get("expired")), None)
    if art is None:
        return None
    z = gh.download(f"repos/{repo}/actions/artifacts/{art['id']}/zip", 20 * 1024 * 1024)
    try:
        with zipfile.ZipFile(io.BytesIO(z)) as zf:
            state = json.loads(zf.read("state.json").decode("utf-8"))
    except (KeyError, ValueError, zipfile.BadZipFile) as e:
        raise StateBroken(f"state artifact {art['id']} of run {run['id']} unreadable: {e}") from e
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        raise StateBroken(f"state artifact {art['id']} has version {state.get('version') if isinstance(state, dict) else '?'!r}")
    return state


def verify_state(state: dict, run: dict) -> None:
    if state.get("run_id") != run.get("id"):
        raise StateBroken(f"state names run {state.get('run_id')}, but it is run {run.get('id')}'s artifact")
    chain = state.get("chain") or []
    if not chain:
        raise StateBroken(f"state of run {run.get('id')} has no chain")
    headE = chain[-1]
    if entry_digest(headE) != headE.get("digest"):
        raise StateBroken(f"state of run {run.get('id')}: chain head digest does not verify")
    if headE.get("state") != state_digest(state):
        raise StateBroken(f"state of run {run.get('id')}: content does not match its chain entry")
    for a, b in zip(chain, chain[1:]):
        if b.get("prev") != a.get("digest") and not b.get("rebaseline"):
            raise StateBroken(f"state of run {run.get('id')}: chain broken between seq {a.get('seq')} and {b.get('seq')}")


def load_state(gh: GitHub, repo: str, cfg: dict, env: RunEnv, anchor: dict | None, a: Auditor) -> dict | None:
    """The predecessor's state, or None on the very first run. Raises
    StateBroken (fail closed) on deletion, rollback or foreign audit code."""
    runs = trusted_audit_runs(gh, repo, cfg, env)
    entries = (anchor or {}).get("entries") or []
    if not runs:
        if entries:
            raise StateBroken(f"no successful trusted audit run exists, but the anchor holds a chain up to seq "
                              f"{entries[-1].get('seq')}: audit runs were deleted")
        return None
    pred = runs[0]
    if env.run_number and pred.get("run_number") and int(pred["run_number"]) >= int(env.run_number):
        raise AuditError(f"this is run #{env.run_number}, older than the newest successful audit run "
                         f"#{pred['run_number']} (a re-run of an old failed run): refused, so it can never become a "
                         f"successful run that the next run mistakes for its predecessor")
    # run_number continuity: a deleted audit run leaves a permanent gap.
    # Cancelled, skipped, queued and in-progress runs are listed, so they never
    # leave one. The `created>=` listing can lag, so a number missing from it
    # is re-checked against the plain runs list; a number missing from both is
    # a SUSPECT (FLAG) and fails closed only if it is still missing on the next
    # run at least 5 minutes later (see the gap_suspects check below).
    a.gap_suspects = None
    if env.run_number and pred.get("run_number"):
        nums, complete = audit_run_numbers(gh, repo, cfg, pred.get("created_at"))
        if complete:
            missing = [n for n in range(int(pred["run_number"]) + 1, int(env.run_number)) if n not in nums]
            if missing:
                a.gap_suspects = {"numbers": missing[:50], "since": pred.get("created_at"), "first_seen": iso(a.now)}
                a.flag("R6", f"R6:runs-gap-suspect:{env.run_id}",
                       f"audit run number(s) {missing[:10]} between the state's run #{pred['run_number']} and this run "
                       f"#{env.run_number} are not listed: deleted runs, or listing lag; this run fails closed if they "
                       f"are still missing on the next run")
        else:
            a.flag("R6", f"R6:runs-unverifiable:{env.run_id}",
                   f"more than 1000 audit.yml runs since run {pred['id']}: run-number continuity not verified")
    state = read_state_artifact(gh, repo, cfg, pred)
    if state is None:
        raise StateBroken(f"audit run {pred['id']} (#{pred.get('run_number')}) succeeded but its state artifact is gone: "
                          f"state deleted (or expired after a long outage)")
    verify_state(state, pred)
    sus = state.get("gap_suspects")
    if sus and sus.get("numbers"):
        nums, complete = audit_run_numbers(gh, repo, cfg, sus.get("since"))
        still = [n for n in sus["numbers"] if n not in nums]
        first = ts(sus.get("first_seen")) or a.now
        if not complete:
            still = list(sus["numbers"])        # cannot be confirmed present: treat as missing (verify5 V5-M2)
        if still and a.now - first >= timedelta(minutes=5):
            raise StateBroken(f"audit run number(s) {still[:10]} are still missing {int((a.now - first).total_seconds() // 60)} "
                              f"min after they were first noticed: audit runs were deleted (newer state may have been removed)")
        if still:
            carry = {"numbers": still, "since": sus.get("since"), "first_seen": sus.get("first_seen")}
            a.gap_suspects = carry if not a.gap_suspects else {
                "numbers": sorted(set(still) | set(a.gap_suspects["numbers"]))[:50],
                "since": min(sus.get("since") or "", a.gap_suspects["since"] or "") or sus.get("since"),
                "first_seen": sus.get("first_seen")}
        else:
            a.notes.append(f"run numbers {sus['numbers'][:10]} suspected last run are listed now (listing lag)")
    # the code the predecessor ran must be this run's code (or one it accepts)
    if env.workflow_sha:
        cur = code_digest(gh, repo, env.workflow_sha)
        prev_code = cur if pred.get("head_sha") == env.workflow_sha else code_digest(gh, repo, pred.get("head_sha") or "")
        if prev_code != cur and prev_code not in (cfg.get("accepted_previous_code") or []):
            raise StateBroken(f"state run {pred['id']} ran audit code {prev_code[:12]} at {str(pred.get('head_sha'))[:12]}, "
                              f"this run runs {cur[:12]}: state from other audit code is not trusted (after a legitimate "
                              f"7a audit change, list the old digest in config accepted_previous_code, or dispatch "
                              f"rebaseline=continue)")
    # the anchor must not be ahead of the state (rollback), nor disagree with it
    seq = state["chain"][-1]["seq"]
    mine = {e.get("seq"): e.get("digest") for e in state["chain"]}
    for e in entries:
        s = e.get("seq")
        if not isinstance(s, int):
            continue
        if s > seq:
            rid = e.get("run_id")
            if rid == env.run_id:
                continue        # this run's own earlier attempt (re-run)
            try:
                run = gh.get(f"repos/{repo}/actions/runs/{rid}")
            except NotFound:
                raise StateBroken(f"the anchor's seq {s} names audit run {rid}, which no longer exists: newer state "
                                  f"was deleted (rollback to run {pred['id']}, seq {seq})")
            if audit_run_untrusted(run, repo, cfg["default_branch"], cfg["audit_workflow"]) is not None:
                a.flag("R6", f"R6:anchor-forged:{s}:{rid}",
                       f"the anchor's seq {s} names run {rid}, which is not a trusted audit run: forged entry, overwritten")
            elif run.get("conclusion") == "success":
                raise StateBroken(f"the anchor's seq {s} comes from successful audit run {rid}, newer than the loaded state "
                                  f"(run {pred['id']}, seq {seq}): rollback")
            elif run.get("status") != "completed":
                raise StateBroken(f"the anchor's seq {s} comes from audit run {rid}, still {run.get('status')!r}")
            else:
                a.notes.append(f"anchor seq {s} from run {rid} ({run.get('conclusion')}) was never committed; overwritten")
        elif s in mine and mine[s] != e.get("digest"):
            a.flag("R6", f"R6:anchor-mismatch:{s}:{env.run_id}",
                   f"the anchor's entry seq {s} differs from the state's (anchor edited); rewritten from the state")
    if entries and max((e.get("seq") or 0) for e in entries) < seq:
        a.flag("R6", f"R6:anchor-behind:{env.run_id}",
               f"the anchor ends before the state's seq {seq} (anchor edited back or a write lost); rewritten")
    gap = timedelta(minutes=int(cfg["max_gap_minutes"]))
    prev_at = ts(state.get("audited_at"))
    if prev_at and a.now - prev_at > gap:
        a.flag("R6", f"R6:gap:{env.run_id}",
               f"{int((a.now - prev_at).total_seconds() // 60)} minutes since the previous audit run (limit "
               f"{cfg['max_gap_minutes']}): the audit was stopped, disabled or starved; changes made and undone in the "
               f"gap are unseen")
    return state


def newest_readable_state(gh: GitHub, repo: str, cfg: dict, env: RunEnv) -> tuple[dict | None, dict | None, list[str]]:
    """For rebaseline=continue: the newest state that verifies against its own
    chain entry AND was written by this run's audit code (or code listed in
    accepted_previous_code). Returns (state, run, skipped reasons). A state
    forged by altered audit code is never adopted."""
    skipped: list[str] = []
    cur = code_digest(gh, repo, env.workflow_sha) if env.workflow_sha else None
    for run in trusted_audit_runs(gh, repo, cfg, env)[:30]:
        try:
            st = read_state_artifact(gh, repo, cfg, run)
            if st is None:
                skipped.append(f"run {run['id']}: no state artifact")
                continue
            verify_state(st, run)
        except StateBroken as e:
            skipped.append(f"run {run['id']}: {e}")
            continue
        if cur is not None:
            code = cur if run.get("head_sha") == env.workflow_sha else code_digest(gh, repo, run.get("head_sha") or "")
            if code != cur and code not in (cfg.get("accepted_previous_code") or []):
                skipped.append(f"run {run['id']}: ran audit code {code[:12]}, not this code {cur[:12]}")
                continue
        return st, run, skipped
    return None, None, skipped


def flag_line(f: dict) -> str:
    """One posted FLAG line. Kept identical to PAU fleet_audit_check (it rebuilds
    flags_digest from the posted lines when an entry's FLAG list is capped)."""
    return f"- `FLAG` {f['rule']} `{f['key']}`: {f['summary']}".replace("@", "@\u200b")


def flags_digest(flags: list[dict]) -> str:
    return hashlib.sha256("\n".join(flag_line(f) for f in flags).encode()).hexdigest()


def chunks(text: str, size: int = COMMENT_CHUNK) -> list[str]:
    """Split at line boundaries; every FLAG is posted, nothing is truncated."""
    out, cur = [], ""
    for line in text.split("\n"):
        line = line[:size - 1]
        if len(cur) + len(line) + 1 > size:
            out.append(cur)
            cur = ""
        cur += line + "\n"
    if cur.strip():
        out.append(cur)
    return out


def render_header(run_url: str, seq: int, part: int | None = None, parts: int | None = None) -> str:
    tail = f", part {part}/{parts}" if part else ""
    return f"## merge-audit run {run_url} (chain seq {seq}{tail})"


def render_body(events: list[dict], new_conditions: list[dict], open_conditions: list[dict], ledger: list[str],
                notes: list[str]) -> str:
    def nm(x: str) -> str:
        return x.replace("@", "@\u200b")   # never mention anyone
    out = [f"### FLAGs ({len(events) + len(new_conditions)} new)"]
    out += [flag_line(f) for f in events + new_conditions] or ["(none)"]
    if open_conditions:
        out += ["", f"### Open conditions ({len(open_conditions)}, re-checked every run)"]
        out += [nm(f"- {f['rule']}: {f['summary']}") for f in open_conditions]
    if ledger:
        out += ["", "### Audited default-branch commits and pushes"] + [nm(f"- {clean(x)}") for x in ledger]
    if notes:
        out += ["", "### Notes"] + [nm(f"- {clean(x)}") for x in notes]
    return "\n".join(out)


def render(events: list[dict], new_conditions: list[dict], open_conditions: list[dict], ledger: list[str],
           notes: list[str], run_url: str, seq: int) -> str:
    return render_header(run_url, seq) + "\n\n" + render_body(events, new_conditions, open_conditions, ledger, notes)


def make_entry(seq: int, prev: str, env: RunEnv, head: str, code: str, sdigest: str, events: list[dict],
               conditions: list[dict], audited_at: str, rebaseline: dict | None) -> dict:
    def slim(f):
        return {"rule": f["rule"], "key": f["key"][:200], "summary": f["summary"][:SUMMARY_CAP]}
    e = {"seq": seq, "prev": prev, "run_id": env.run_id, "run_number": env.run_number, "audited_at": audited_at,
         "head": head, "code": code, "state": sdigest, "flags": [slim(f) for f in events[:ENTRY_FLAGS_CAP]],
         "flags_total": len(events), "flags_digest": flags_digest(events),
         "open": [slim(f) for f in conditions[:ENTRY_OPEN_CAP]],
         "open_total": len(conditions), "rebaseline": rebaseline}
    e["digest"] = entry_digest(e)
    return e


def rerun_guard(gh: GitHub, repo: str, cfg: dict, env: RunEnv) -> None:
    """A re-run attempt. If an earlier attempt of this run SUCCEEDED, it already
    wrote the chain entry, the witness and the state: write nothing (NoOp), so
    the entry the front door may have seen is never rewritten. That needs the
    earlier attempt's state artifact to still be listed for this run (not
    verified live); if it is not, fail this attempt rather than leave a
    successful run without state (a failed run is never a predecessor, so the
    next run continues normally; the front door may report a fork at this
    run's seq, loudly). If no earlier attempt succeeded (the usual "Re-run
    failed jobs"), or that cannot be read, run the audit normally."""
    prior = None
    for k in range(1, env.run_attempt):
        try:
            att = gh.get(f"repos/{repo}/actions/runs/{env.run_id}/attempts/{k}")
        except AuditError:
            continue
        if att.get("conclusion") == "success":
            prior = k
    if prior is None:
        return
    try:
        arts = (gh.get(f"repos/{repo}/actions/runs/{env.run_id}/artifacts?per_page=100") or {}).get("artifacts") or []
    except AuditError:
        arts = []
    if any(x.get("name") == cfg["state_artifact"] and not x.get("expired") for x in arts):
        raise NoOp(f"attempt {env.run_attempt} of run {env.run_id}: attempt {prior} already succeeded and wrote the chain "
                   f"entry, the witness and the state; nothing written")
    raise AuditError(f"attempt {env.run_attempt} of run {env.run_id}: attempt {prior} succeeded but its state artifact is "
                     f"not listed after the re-run; failing this attempt so the run is not taken as a predecessor without "
                     f"state (the next run continues from the previous run's state)")


def run_audit(gh: GitHub, repo: str, cfg: dict, env: RunEnv, vars_ctx: dict, now: datetime | None = None,
              sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
              hmac_key: str = "") -> tuple[dict, dict, "Auditor", int | None]:
    """Returns (state, plan, auditor, issue_number). The caller posts the plan
    (comments + anchor) and writes the state file. Raises StateBroken / AuditError."""
    if env.run_attempt > 1:
        rerun_guard(gh, repo, cfg, env)
    meta = gh.get(f"repos/{repo}")
    if meta.get("default_branch") != cfg["default_branch"]:
        raise AuditError(f"default branch is {meta.get('default_branch')!r}, config says {cfg['default_branch']!r}")
    deadline = clock() + int(cfg["time_budget_seconds"])
    a = Auditor(gh, repo, cfg, now=now, sleep=sleep, deadline=deadline, clock=clock, hmac_key=hmac_key)
    a.call_limit = gh.count + int(cfg["api_budget_per_run"])
    issue, body = find_issue(gh, repo, cfg)
    anchor = parse_anchor(body)
    if issue is not None and anchor is None and body and ANCHOR_BEGIN in body:
        a.flag("R6", f"R6:anchor-unreadable:{env.run_id}", "the findings issue body's chain block is unreadable (edited); rewritten")
    rebaseline = None
    try:
        state = load_state(gh, repo, cfg, env, anchor, a)
        problem = ""
    except StateBroken as e:
        if not env.rebaseline:
            e.issue, e.anchor = issue, anchor   # type: ignore[attr-defined]
            raise
        state, problem = None, str(e)
    if env.rebaseline:
        adopted = None
        skipped: list[str] = []
        if env.rebaseline == "continue" and state is None:
            state, run, skipped = newest_readable_state(gh, repo, cfg, env)
            adopted = run.get("id") if run else None
        elif state is not None:
            adopted = state.get("run_id")
        rebaseline = {"mode": env.rebaseline, "actor": env.actor, "reason": env.reason, "problem": clean(problem, 300),
                      "adopted_run": adopted, "skipped": [clean(x, 160) for x in skipped[:10]]}
        a.flag("R6", f"R6:rebaseline:{env.run_id}",
               f"re-baselined ({env.rebaseline}) by {env.actor!r}, reason {env.reason!r}; adopted the state of run "
               f"{rebaseline['adopted_run']}; skipped: {'; '.join(rebaseline['skipped']) or 'none'}; state problem: {problem or 'none'}"
               f"{'' if state else '; no previous state used: commits since the baseline are re-audited, and changes before this run are unseen'}")
    prev = state or {}
    if state and state.get("issue") and issue is not None and state["issue"] != issue:
        a.flag("R6", f"R6:issue-moved:{env.run_id}",
               f"the findings issue was #{state['issue']} and is now #{issue} (deleted or replaced)")
    a_entries = (anchor or {}).get("entries") or []
    if state and not rebaseline:
        seq = state["chain"][-1]["seq"] + 1
        prev_digest = state["chain"][-1]["digest"]
        base_chain = list(state["chain"])
    else:
        top = max([0] + [e.get("seq") or 0 for e in a_entries] + [((state or {}).get("chain") or [{}])[-1].get("seq") or 0])
        seq = top + 1
        if state and state.get("chain"):
            # Chain from the state we actually adopted (verified), not from an
            # anchor the admin may have edited; the front door can then walk on
            # through the rebaseline entry to what it saw before.
            prev_digest = state["chain"][-1]["digest"]
        else:
            prev_digest = (a_entries[-1].get("digest") if a_entries else None) or GENESIS
        if rebaseline is not None:
            head_e = ((state or {}).get("chain") or [{}])[-1]
            rebaseline["prev_seq"] = head_e.get("seq")
            rebaseline["prev_flags_total"] = head_e.get("flags_total")
        base_chain = list((state or {}).get("chain") or []) if rebaseline and rebaseline["mode"] == "continue" else []
    a.seq = seq
    head = gh.get(f"repos/{repo}/branches/{urllib.parse.quote(cfg['default_branch'])}")["commit"]["sha"]
    bl = prev.get("backlogs") or {}
    a.begin("commits")
    new_head = a.audit_commits(prev.get("head"), head)
    events_cursor, events_seen = a.push_events(prev.get("events_cursor"), prev.get("events_seen") or [])
    controls = a.controls(prev.get("controls"), vars_ctx)
    issue_cursor = a.label_events(prev.get("issue_events_cursor"))
    a.begin("records")
    records, records_cursor = a.records(prev.get("records") if state else None, prev.get("records_cursor") if state else None,
                                        bl.get("records"))
    a.begin("checks")
    checks_ok, checks_bad, checks_seen = a.forged_checks(prev.get("checks_ok") or [], prev.get("checks_bad") or {},
                                                         prev.get("checks_seen") or {}, bl.get("checks"))
    a.begin("runs")
    runs_cursor = a.foreign_runs(prev.get("runs_cursor"), bl.get("runs"))
    a.begin("branches")
    branches = a.branch_workflows(prev.get("branches"))
    code = code_digest(gh, repo, env.workflow_sha) if env.workflow_sha else ""
    conditions = [a.conditions[k] for k in sorted(a.conditions)]
    was_open = set(prev.get("open") or [])
    new_conditions = [c for c in conditions if c["key"] not in was_open]
    audited_at = iso(a.now)
    new_state = {"version": STATE_VERSION, "run_id": env.run_id, "run_number": env.run_number, "seq": seq,
                 "audited_at": audited_at, "head": new_head, "events_cursor": events_cursor, "events_seen": events_seen,
                 "issue_events_cursor": issue_cursor, "controls": controls, "records": records,
                 "records_cursor": records_cursor, "checks_ok": checks_ok, "checks_bad": checks_bad, "checks_seen": checks_seen,
                 "runs_cursor": runs_cursor, "branches": branches, "issue": issue,
                 "open": [c["key"] for c in conditions], "gap_suspects": getattr(a, "gap_suspects", None),
                 "backlogs": a.backlogs}
    ordered = sorted(a.findings, key=lambda f: f["rule"] != "R6")   # integrity FLAGs first (never capped away)
    entry = make_entry(seq, prev_digest, env, new_head, code, state_digest(new_state), ordered + new_conditions,
                       conditions, audited_at, rebaseline)
    new_state["chain"] = (base_chain + [entry])[-int(cfg["chain_keep"]):]
    plan = {"events": ordered, "new_conditions": new_conditions, "conditions": conditions, "entry": entry}
    return new_state, plan, a, issue


def publish(gh: GitHub, repo: str, cfg: dict, env: RunEnv, state: dict, plan: dict, a: Auditor,
            issue: int | None, dry_run: bool) -> tuple[int | None, str]:
    """Posts the findings comments (split, never truncated) and rewrites the
    anchor. Returns (issue number, rendered text)."""
    run_url = f"{env.server}/{repo}/actions/runs/{env.run_id}"
    text = render(plan["events"], plan["new_conditions"], plan["conditions"], a.ledger, a.notes, run_url, state["seq"])
    if dry_run:
        return issue, text
    if issue is None:
        issue = gh.post(f"repos/{repo}/issues", {"title": cfg["findings_issue_title"],
                                                 "body": render_anchor(repo, state["chain"])})["number"]
        state["issue"] = issue
        # the issue number is part of the state: re-seal the chain head
        entry = dict(state["chain"][-1])
        entry["state"] = state_digest(state)
        entry["digest"] = entry_digest(entry)
        state["chain"][-1] = entry
    if plan["events"] or plan["new_conditions"] or a.ledger:
        # Every part carries the run and seq, so the front door can rebuild the
        # full FLAG list of a capped entry and check it against flags_digest.
        body = render_body(plan["events"], plan["new_conditions"], plan["conditions"], a.ledger, a.notes)
        parts = chunks(body, COMMENT_CHUNK - 300)
        for i, part in enumerate(parts, start=1):
            gh.post(f"repos/{repo}/issues/{issue}/comments",
                    {"body": render_header(run_url, state["seq"], i, len(parts)) + "\n\n" + part})
    gh.patch(f"repos/{repo}/issues/{issue}", {"body": render_anchor(repo, state["chain"])})
    return issue, text


def mark_broken(gh: GitHub, repo: str, issue: int | None, anchor: dict | None, reason: str) -> None:
    """Fail closed, but say why where the front door can read it (the anchor's
    status), without touching the chain."""
    if issue is None:
        return
    entries = (anchor or {}).get("entries") or []
    gh.patch(f"repos/{repo}/issues/{issue}", {"body": render_anchor(repo, entries, status="broken", reason=reason)})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--state-out", required=True, help="where to write state.json for the artifact upload step")
    ap.add_argument("--dry-run", action="store_true", help="print findings; post nothing")
    args = ap.parse_args(argv)
    # Nothing this script prints may act as a workflow command (names and
    # summaries come from repo content): stop command processing for the log.
    stop_token = secrets.token_hex(16)
    print(f"::stop-commands::{stop_token}", flush=True)
    token = os.environ.get("GH_TOKEN", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not token or not run_id.isdigit():
        print("merge-audit: FAIL (fail closed): GH_TOKEN or GITHUB_RUN_ID not set")
        return 2
    rn = os.environ.get("GITHUB_RUN_NUMBER", "")
    env = RunEnv(int(run_id), int(rn) if rn.isdigit() else None, os.environ.get("GITHUB_WORKFLOW_SHA", ""),
                 os.environ.get("GITHUB_ACTOR", ""), os.environ.get("GITHUB_EVENT_NAME", ""),
                 os.environ.get("REBASELINE", ""), os.environ.get("REBASELINE_REASON", ""),
                 os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
                 int(os.environ.get("GITHUB_RUN_ATTEMPT", "1") or 1))
    gh = None
    try:
        with open(args.config, encoding="utf-8") as fh:
            cfg = json.load(fh)
        vars_ctx = json.loads(os.environ.get("VARS_JSON") or "{}")
        if not isinstance(vars_ctx, dict):
            raise AuditError("VARS_JSON is not an object")
        gh = GitHub(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        state, plan, a, issue = run_audit(gh, args.repo, cfg, env, vars_ctx, hmac_key=os.environ.get("AUDIT_HMAC_KEY", ""))
        issue, text = publish(gh, args.repo, cfg, env, state, plan, a, issue, args.dry_run)
        new = plan["events"] + plan["new_conditions"]
        for f in new:
            print(f"FLAG {f['rule']} {clean(f['key'])}: {f['summary']}")
        print(f"merge-audit: seq {state['seq']}, {len(new)} new FLAG(s), {len(plan['conditions'])} open condition(s); "
              f"head {state['head']}; {gh.count} API calls, rate remaining {gh.remaining}")
        os.makedirs(os.path.dirname(os.path.abspath(args.state_out)), exist_ok=True)
        with open(args.state_out, "w", encoding="utf-8") as fh:
            json.dump(state, fh, sort_keys=True)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(text + "\n")
        print(f"::{stop_token}::", flush=True)
        # The WITNESS: an annotation is bound to this run and readable
        # anonymously; the admin can remove it only by deleting the run (a
        # run_number hole). The front door requires the anchor to hold exactly
        # this entry, so an anchor rewritten to strip FLAGs is detected.
        head = state["chain"][-1]
        print(f"::notice title={WITNESS_TITLE}::{witness_line(head)}", flush=True)
        for f in sorted(new, key=lambda f: f["rule"] != "R6")[:9]:    # 10 warnings per step; integrity FLAGs first; FLAGs readable on the run page and by the front door
            print(f"::warning title=FLAG {f['rule']}::{f['summary'].replace('::', ': :')[:300]}")
    except NoOp as e:
        print(f"merge-audit: {e}")
        out = os.environ.get("GITHUB_OUTPUT")
        if out:
            with open(out, "a", encoding="utf-8") as fh:
                fh.write("noop=true\n")
        return 0
    except StateBroken as e:
        print(f"merge-audit: FAIL (fail closed): state broken: {e}")
        try:
            cand, run, skipped = newest_readable_state(gh, args.repo, cfg, env) if gh is not None else (None, None, [])
            would = (f"run {run['id']} (#{run.get('run_number')}, seq {cand['chain'][-1]['seq']}, head "
                     f"{str(cand.get('head'))[:12]})") if cand else "nothing (fresh)"
            print(f"merge-audit: for the record, rebaseline=continue would adopt {would}; it would skip: "
                  f"{'; '.join(skipped) or 'none'}")
        except Exception as e3:  # noqa: BLE001
            print(f"merge-audit: could not compute the rebaseline candidate: {type(e3).__name__}: {e3}")
        print("merge-audit: this may be tampering. Do NOT rebaseline by reflex: find out why the state is broken "
              "(deleted runs or artifacts, altered audit code, an edited findings issue) and confirm the cause first. "
              "Only then dispatch audit.yml with a rebaseline mode and a reason; fresh is the conservative choice "
              "when the cause is unclear. The front door alerts on any rebaseline.")
        try:
            if gh is not None and not args.dry_run:
                mark_broken(gh, args.repo, getattr(e, "issue", None), getattr(e, "anchor", None), str(e))
        except Exception as e2:  # noqa: BLE001
            print(f"merge-audit: could not mark the anchor broken: {type(e2).__name__}: {e2}")
        return 2
    except Exception as e:  # noqa: BLE001 - anything uncomputable fails the run
        print(f"merge-audit: FAIL (fail closed): {type(e).__name__}: {e}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
