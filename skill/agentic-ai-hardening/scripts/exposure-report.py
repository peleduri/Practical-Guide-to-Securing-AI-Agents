#!/usr/bin/env python3
"""Personalized agentic-stack exposure report — EXAMPLE, stdlib-only.

Joins the local agentic-tool inventory (inventory-agents.sh --json) against live
advisory sources, through the curated watchlist (agentic-watchlist.json), and
renders an honest exposure report (Markdown + JSON).

M1 pipeline (keep in sync with the design doc's diagram):

     inventory-agents.sh          agentic-watchlist.json (vendored, lint-enforced)
       (presence + install          name/aliases . osv package coords .
        channel, --json)            per-channel metadata source . guide mapping
            |                                   |
            v                                   v
          +-----------------------------------------+      OSV.dev  (floor)
          |            exposure-report.py           |<-- querybatch{package,version}
          |  1 read versions from pkg METADATA      |     (server-side range match)
          |    (brew/npm/pip/plist; never exec      |      CISA KEV (jackpot)
          |    targets; --probe-binaries opt-in)    |<-- single JSON fetch
          |  2 query OSV with version -> confirmed  |      pulse latest.json
          |    no version -> "version unknown"      |<-- (enrichment, schema-
          |    (KEV/pulse hits -> possible)         |      validated, best-effort)
          |    KEV alone never confirms             |
          |  3 merge GHSA<->CVE aliases (1 finding) |
          |  4 sanitize feed strings -> MD + JSON   |   each source: live -> cache
          +-----------------------------------------+    (<7d, ~/.cache) -> banner
            |            |                               hard timeouts + size caps
            v            v                               on every request
     exposure-report.md  exposure-report.json

Honest result taxonomy (never "clean"):
  matched (confirmed / possible) . version unknown . not covered .
  no matching advisories in covered sources
"Actively exploited" wording is reserved for KEV-corroborated findings, and a
KEV name-match alone never yields `confirmed` (KEV carries no version data).

Security posture:
  - READ-ONLY by default: versions come from package metadata (brew Cellar dirs,
    npm/pip metadata, app plists). Target binaries are executed ONLY under the
    explicit --probe-binaries flag. Feeds are untrusted DATA, never instructions.
  - Every network request carries a hard timeout and a response-size cap.
  - All feed-derived strings are sanitized before rendering.

Exit codes: 0 = report rendered . 2 = rendered degraded (>=1 source skipped) .
3 = no report possible (all sources unavailable, no cache).

Replay / determinism: --osv/--kev/--feed/--inventory/--now isolate every input;
output ordering is sorted, dates derive from --now, so fixture runs are
byte-stable in CI. --offline uses cache/replay files only (no sockets).
"""

import argparse
import concurrent.futures
import glob
import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

SCHEMA_VERSION = 1
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
PULSE_URL = "https://peleduri.github.io/zero-day-pulse/latest.json"

REQUEST_TIMEOUT = 10          # hard per-request timeout, seconds
SMALL_CAP = 2 * 1024 * 1024   # response-size cap for OSV calls (bytes)
LARGE_CAP = 30 * 1024 * 1024  # response-size cap for KEV / pulse feeds (bytes)
DETAIL_FETCH_MAX = 50         # pagination/count cap on per-vuln detail GETs
PROBE_TIMEOUT = 5             # per-command cap for --probe-binaries, seconds
SOFT_BUDGET = 45              # stop submitting new network work past this, seconds
POOL_SIZE = 6
CACHE_TTL = timedelta(days=7)
MAX_FIELD = 300               # sanitized feed-string length cap

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
# A version we are willing to believe. Versions are NOT trusted input: they come
# from a cloned repo's package.json, an app plist, or a directory name — all
# third-party-writable. Anything outside this shape becomes "version unknown".
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,63}$")
# A vuln id we are willing to put in a URL path or a report heading.
VULN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


# --------------------------------------------------------------------------- util

def cache_dir():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "agentic-ai-hardening", "feeds")


def sanitize(text, cap=MAX_FIELD):
    """Feed strings are untrusted: strip control/format chars, neutralize
    Markdown structure, cap length. Schema validation is not output safety.

    Order matters. Backslash is escaped FIRST: escaping `[` to `\\[` without
    doubling a pre-existing backslash turns feed text `\\[x\\](http://evil)`
    into `\\\\[x\\\\](...)`, which renders as a live link — the escape becomes
    the injection. Unicode Cc/Cf/Co/Cs and the line/paragraph separators go too,
    not just C0: a bidi override (U+202E) or zero-width char can visually
    reorder or hide text in a report whose whole value is that a human trusts
    what it says."""
    if not isinstance(text, str):
        text = str(text)
    text = "".join(ch for ch in text
                   if unicodedata.category(ch) not in ("Cc", "Cf", "Co", "Cs")
                   and ch not in (" ", " "))
    text = text.replace("\\", "\\\\")          # must precede the specials
    for ch in "|`*_[]<>#!":
        text = text.replace(ch, "\\" + ch)
    if len(text) > cap:
        text = text[:cap] + "…"
    return text


def safe_url(url):
    """Only plain http(s) URLs are rendered as links, and never ones that can
    break out of Markdown link syntax.

    `[title](URL)` means a URL containing `)`, `(`, `[` or `]` can inject a
    second attacker-controlled link or an image into the report, so those four
    characters are percent-encoded rather than passed through (real advisory
    URLs survive encoding)."""
    if not isinstance(url, str) or len(url) > 500:
        return ""
    if not re.match(r"^https?://[\w\-.~:/?#\[\]@!$&'()*+,;=%]+$", url):
        return ""
    # Reject userinfo: `https://api.osv.dev@evil.example/x` reads as osv.dev to
    # a human clicking an advisory link in a security report.
    try:
        netloc = urllib.parse.urlsplit(url).netloc
    except ValueError:
        return ""
    if "@" in netloc or not netloc:
        return ""
    for ch, enc in (("(", "%28"), (")", "%29"), ("[", "%5B"), ("]", "%5D")):
        url = url.replace(ch, enc)
    return url


def version_key(text):
    """Sort key that orders versions numerically, not lexicographically.

    Lexicographic sorting puts "0.9.2" after "0.10.0", so a brew Cellar or
    site-packages holding both (brew keeps old versions until `brew cleanup`)
    would report the OLDER install — and an old version is exactly what makes a
    patched machine render as confirmed/actively-exploited. That is the
    credibility failure this project exists to avoid."""
    parts = re.split(r"[._\-+]", str(text))
    return [(0, int(p)) if p.isdigit() else (1, p) for p in parts if p != ""]


def _read_capped(resp, cap):
    """Read a response body under BOTH a size cap and a wall-clock deadline.

    urlopen's `timeout` bounds each socket operation, not the whole transfer:
    a server dripping one byte every few seconds never trips it, so a 30MB cap
    alone would let one slow feed consume the entire run budget. Read in chunks
    and abort on either bound."""
    deadline = time.monotonic() + REQUEST_TIMEOUT
    chunks, total = [], 0
    while total <= cap:
        if time.monotonic() > deadline:
            raise TimeoutError("response body exceeded %ds read deadline"
                               % REQUEST_TIMEOUT)
        chunk = resp.read(min(65536, cap + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > cap:
        raise ValueError("response exceeds size cap")
    return b"".join(chunks)


def http_get_json(url, cap):
    req = urllib.request.Request(url, headers={"User-Agent": "exposure-report/1"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        data = _read_capped(resp, cap)
    return json.loads(data)


def http_post_json(url, payload, cap):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"User-Agent": "exposure-report/1",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        data = _read_capped(resp, cap)
    return json.loads(data)


class SourceState:
    """Tracks per-source outcome for the coverage footer + exit code."""

    def __init__(self):
        self.status = {}   # source -> "live" | "cache" | "replay" | "skipped"
        self.notes = {}

    def set(self, source, status, note=""):
        self.status[source] = status
        if note:
            self.notes[source] = note

    def skipped(self):
        return sorted(s for s, st in self.status.items() if st == "skipped")

    def usable(self):
        return [s for s, st in self.status.items() if st != "skipped"]


def load_with_cache(name, fetch, replay_file, offline, cap, now, state):
    """Source loading ladder: replay file -> live (unless --offline) -> cache
    (<7d) -> skipped. Live successes refresh the cache (never inside the
    vendored skill dir; user cache dir only).

    `now` is the RENDER clock (settable via --now for byte-stable fixtures).
    Cache freshness deliberately uses the WALL clock instead: how old a cached
    feed is, is a real-time property, and reading it off an injected past date
    would make an 8-day-old cache look fresh."""
    del now  # render clock only; cache TTL is wall-clock (see docstring)
    if replay_file:
        try:
            with open(replay_file, "rb") as fh:
                data = json.loads(fh.read(cap + 1))
            state.set(name, "replay")
            return data
        except (OSError, ValueError) as exc:
            state.set(name, "skipped", "replay file unreadable: %s" % exc)
            return None
    cpath = os.path.join(cache_dir(), name + ".json")
    if not offline:
        try:
            data = fetch()
            _cache_write(cpath, data)
            state.set(name, "live")
            return data
        except (urllib.error.URLError, ValueError, OSError, TimeoutError,
                RecursionError) as exc:
            live_err = str(exc)
    else:
        live_err = "offline mode"
    data, why = _cache_read(cpath, cap)
    if data is not None:
        # A cached feed is stale-by-definition data, and this run could not
        # reach the live source: say so rather than presenting it as current.
        state.set(name, "cache", "%s; using cached copy" % live_err)
        return data
    state.set(name, "skipped", "%s; %s" % (live_err, why))
    return None


def _cache_ok(path):
    """A cache entry is only usable if it is a real, user-owned, non-symlink
    file. The cache lives under $XDG_CACHE_HOME, which can be a shared or
    world-writable base, and this tool's own threat model assumes an attacker
    may already run as the user — so a planted symlink or a foreign-owned file
    is treated as no cache at all."""
    try:
        st = os.lstat(path)
    except OSError:
        return False, "no cache"
    if not os.path.isfile(path) or os.path.islink(path):
        return False, "cache path is not a regular file"
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        return False, "cache not owned by this user"
    return True, ""


def _cache_write(cpath, data):
    """Write atomically into a 0700 dir, never through a symlink. A plain
    open(path, "w") on a planted symlink truncates and overwrites the target —
    an arbitrary-file-overwrite primitive handed to a security scanner."""
    try:
        d = os.path.dirname(cpath)
        os.makedirs(d, mode=0o700, exist_ok=True)
        if os.path.islink(cpath):
            os.unlink(cpath)          # refuse to write through a symlink
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, cpath)    # atomic: no torn cache for a parallel run
        except BaseException:
            os.unlink(tmp)
            raise
    except (OSError, ValueError, TypeError):
        pass                          # cache write failure never fails the run


def _cache_read(cpath, cap):
    ok, why = _cache_ok(cpath)
    if not ok:
        return None, why
    try:
        st = os.stat(cpath)
        age = datetime.now() - datetime.fromtimestamp(st.st_mtime)
        # A future mtime means a forward-dated (planted) file, not a fresh one.
        if age < timedelta(0) or age > CACHE_TTL:
            return None, "cache stale or forward-dated"
        with open(cpath, "rb") as fh:
            return json.loads(fh.read(cap + 1)), ""
    except (OSError, ValueError, RecursionError):
        return None, "cache unreadable"


# ---------------------------------------------------------------- version discovery

def _expand(pattern):
    return sorted(glob.glob(os.path.expanduser(pattern)))


def version_from_brew_cellar(src):
    for p in src.get("paths", []):
        for cellar in _expand(p):
            try:
                versions = [d for d in os.listdir(cellar)
                            if not d.startswith(".")]
            except OSError:
                continue
            if versions:
                # Newest by version order, NOT lexicographic (see version_key).
                return max(versions, key=version_key), cellar
    return None, None


def version_from_plist(src):
    for p in src.get("paths", []):
        for plist in _expand(p):
            try:
                with open(plist, "rb") as fh:
                    info = plistlib.load(fh)
                v = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
                if v:
                    return str(v), plist
            except (OSError, plistlib.InvalidFileException, ValueError):
                continue
    return None, None


def _version_from_package_json(roots, package):
    """Read a version from a package.json.

    When a package NAME is given (npm layout), only `<root>/<package>/
    package.json` counts. Falling back to `<root>/package.json` there would
    attribute an unrelated package's version to this product and send it to
    OSV — a wrong version is a wrong finding. The bare-root read is the clone
    layout, used only when no package name is supplied."""
    for root in roots:
        for base in _expand(root):
            if package:
                pj = os.path.join(base, *package.split("/"), "package.json")
            else:
                pj = os.path.join(base, "package.json")
            if not os.path.isfile(pj):
                continue
            try:
                with open(pj, encoding="utf-8") as fh:
                    v = json.load(fh).get("version")
                if v:
                    return str(v), pj
            except (OSError, ValueError):
                continue
    return None, None


def version_from_npm_global(src):
    return _version_from_package_json(src.get("roots", []), src.get("package", ""))


def version_from_clone_package_json(src):
    return _version_from_package_json(src.get("roots", []), "")


def version_from_pip_dist_info(src):
    pkg = src.get("package", "").replace("-", "_")
    for root in src.get("roots", []):
        for base in _expand(root):
            found = []
            for d in glob.glob(os.path.join(base, "%s-*.dist-info" % pkg)):
                m = re.match(r"%s-(.+)\.dist-info$" % re.escape(pkg),
                             os.path.basename(d))
                if m:
                    found.append((m.group(1), d))
            if found:
                # Newest by version order, not lexicographic (see version_key).
                return max(found, key=lambda pair: version_key(pair[0]))
    return None, None


def version_from_probe(src, probing_enabled):
    """Executes the TARGET binary — only ever under the explicit opt-in flag."""
    if not probing_enabled:
        return None, None
    cmd = src.get("command", [])
    if not (isinstance(cmd, list) and cmd and all(isinstance(c, str) for c in cmd)):
        return None, None  # watchlist command must be a fixed argv list
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=PROBE_TIMEOUT, check=False)
        m = re.search(src.get("version_pattern", r"(\d+\.\d+\.\d+)"),
                      (out.stdout or "") + (out.stderr or ""))
        if m and m.groups():
            return m.group(1), "probe:%s" % cmd[0]
    except (OSError, subprocess.SubprocessError, re.error, IndexError):
        # A malformed watchlist version_pattern must not crash the scan with a
        # traceback (that would exit outside the documented 0/2/3 contract).
        pass
    return None, None


VERSION_HANDLERS = {
    "brew_cellar": version_from_brew_cellar,
    "macos_app_plist": version_from_plist,
    "npm_global_package_json": version_from_npm_global,
    "clone_package_json": version_from_clone_package_json,
    "pip_dist_info": version_from_pip_dist_info,
}


def discover_product(product, spec, inventory_products, probing):
    """Presence + version for one product. Presence = inventory hit OR any
    version-source hit. Discovery failure never crashes and never drops a
    product silently — worst case is 'present, version unknown'."""
    present = product in inventory_products
    version, evidence = None, None
    for src in spec.get("version_sources", []):
        stype = src.get("type")
        if stype == "probe_binary":
            version, evidence = version_from_probe(src, probing)
        else:
            handler = VERSION_HANDLERS.get(stype)
            if handler is None:
                continue
            try:
                version, evidence = handler(src)
            except Exception:            # noqa: BLE001 — never crash the scan
                version, evidence = None, None
        if version:
            version = str(version).strip().lstrip("v")
            # Validate before the value reaches an OSV query or the report: a
            # package.json in a cloned repo can put anything in "version".
            if not VERSION_RE.match(version):
                version, evidence = None, None
                present = True   # the product IS here; its version is unusable
                continue
            present = True
            break
    return {"product": product, "present": present,
            "version": version, "evidence": evidence}


# ------------------------------------------------------------------------- sources

def query_osv(installed, watchlist, replay, offline, now, state, deadline):
    """querybatch with {package, version} — OSV evaluates affected ranges
    server-side; a returned vuln for our exact installed version IS the
    confirmed signal. Products without a version are NOT enumerated (listing
    every historical advisory as 'possible' would be FUD)."""
    queries, owners = [], []
    for item in installed:
        spec = watchlist["products"][item["product"]]
        if not item["present"] or not item["version"]:
            continue
        for q in spec.get("osv_queries", []):
            queries.append({"package": {"name": q["name"],
                                        "ecosystem": q["ecosystem"]},
                            "version": item["version"]})
            owners.append(item["product"])
    if not queries:
        # Nothing to ask OSV about is not a degraded run — distinct from "skipped".
        state.set("osv", "n/a", "no versioned OSV-covered products present")
        return {}

    if replay:
        batch = load_with_cache("osv", None, replay, offline, SMALL_CAP, now, state)
    elif offline:
        state.set("osv", "skipped", "offline mode (OSV batch is per-version; not cached)")
        return {}
    else:
        try:
            batch = http_post_json(OSV_BATCH_URL, {"queries": queries}, SMALL_CAP)
            state.set("osv", "live")
        except (urllib.error.URLError, ValueError, OSError, TimeoutError) as exc:
            state.set("osv", "skipped", str(exc))
            return {}
    if not isinstance(batch, dict):
        state.set("osv", "skipped", "unexpected batch response shape")
        return {}

    hits = {}  # vuln id -> {product, detail}
    results = batch.get("results")
    if not isinstance(results, list) or len(results) != len(queries):
        # Product attribution rides on array POSITION. A short (or long) results
        # array means zip() silently drops the tail — a product would render
        # "no matching advisories" having never been evaluated. Refuse to guess.
        state.set("osv", "skipped",
                  "result count %s does not match %d queries"
                  % (len(results) if isinstance(results, list) else "n/a",
                     len(queries)))
        return {}
    for owner, result in zip(owners, results):
        vulns = (result or {}).get("vulns") if isinstance(result, dict) else None
        for v in vulns if isinstance(vulns, list) else []:
            vid = v.get("id") if isinstance(v, dict) else None
            # The id goes into a URL path and a report heading: only accept a
            # conservative shape (blocks '../', query/fragment re-targeting,
            # and control characters from a hostile feed).
            if isinstance(vid, str) and VULN_ID_RE.match(vid):
                # Every owner, not just the first: the same CVE returned for two
                # queried products affects BOTH, and setdefault would drop the
                # second, leaving a vulnerable product reading clean.
                entry = hits.setdefault(vid, {"products": [], "detail": None})
                if owner not in entry["products"]:
                    entry["products"].append(owner)

    ids = sorted(hits)[:DETAIL_FETCH_MAX]
    if len(hits) > DETAIL_FETCH_MAX:
        state.notes["osv"] = "detail fetches capped at %d of %d hits" % (
            DETAIL_FETCH_MAX, len(hits))
    if replay:
        details = (batch.get("details") or {}) if isinstance(batch, dict) else {}
        for vid in ids:
            hits[vid]["detail"] = details.get(vid)
        return hits

    def fetch_detail(vid):
        # Re-check inside the worker: a future queued before the deadline can
        # still start after it. submit() is non-blocking, so gating only the
        # submit loop would never bound anything.
        if time.monotonic() > deadline:
            raise TimeoutError("past soft budget")
        # quote() as well as the VULN_ID_RE gate above: defense in depth on a
        # feed-supplied value that becomes a URL path segment.
        return vid, http_get_json(
            OSV_VULN_URL.format(urllib.parse.quote(vid, safe="")), SMALL_CAP)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=POOL_SIZE)
    try:
        futures = [pool.submit(fetch_detail, vid) for vid in ids]
        done, not_done = concurrent.futures.wait(
            futures, timeout=max(0.0, deadline - time.monotonic()))
        if not_done:
            state.notes["osv"] = "soft budget reached; %d detail(s) unfetched" % (
                len(not_done))
        for fut in done:
            try:
                vid, detail = fut.result()
                hits[vid]["detail"] = detail
            except (urllib.error.URLError, ValueError, OSError, TimeoutError):
                continue  # partial detail is a banner, not a crash
    finally:
        # Don't block on stragglers: drop queued work and let in-flight
        # requests die to their own per-request timeout.
        pool.shutdown(wait=False, cancel_futures=True)
    return hits


def load_kev(replay, offline, now, state, deadline=None):
    # Past the run budget, don't start another network fetch — fall to
    # cache/skipped so the total stays bounded (KEV+pulse are serial after OSV).
    if deadline is not None and not replay and time.monotonic() > deadline:
        offline = True
    data = load_with_cache(
        "kev", lambda: http_get_json(KEV_URL, LARGE_CAP),
        replay, offline, LARGE_CAP, now, state)
    if data is None:
        return []
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        state.set("kev", "skipped", "unexpected KEV schema")
        return []
    # Item-level guard too: a list of strings would otherwise blow up on
    # v.get(...) downstream and take the whole report with it.
    entries = [v for v in vulns if isinstance(v, dict)]
    if vulns and not entries:
        state.set("kev", "skipped", "unexpected KEV schema: no object entries")
        return []
    return entries


def load_pulse(replay, offline, now, state, deadline=None):
    """Pulse latest.json is another repo's internal artifact until the M2 feed
    contract: schema-guard the exact shape we consume; any mismatch is
    source-down (banner), never a crash."""
    if deadline is not None and not replay and time.monotonic() > deadline:
        offline = True  # same budget guard as KEV
    data = load_with_cache(
        "pulse", lambda: http_get_json(PULSE_URL, LARGE_CAP),
        replay, offline, LARGE_CAP, now, state)
    if data is None:
        return []
    # The feed's own key is `findings`; `items` is accepted as a fallback so a
    # future rename doesn't silently disable enrichment. (This guard originally
    # only knew `items`, so enrichment never once worked against the live feed
    # while every fixture-based test passed — verified by a live run.)
    items = None
    if isinstance(data, dict):
        for key in ("findings", "items"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
    elif isinstance(data, list):
        items = data
    if not isinstance(items, list):
        state.set("pulse", "skipped",
                  "schema mismatch: no findings/items list")
        return []
    out = []
    for item in items:
        if not isinstance(item, dict):
            state.set("pulse", "skipped", "schema mismatch: non-object item")
            return []
        # Scan only the fields that carry CVE ids — re-serializing the whole
        # (up to 30MB) feed with json.dumps just to regex it is wasted work.
        # `cve_ids` is the live feed's own field; the rest are fallbacks.
        haystack = " ".join(
            str(item.get(k, "")) for k in
            ("cve_ids", "cve", "cves", "title", "summary", "description",
             "url", "link"))
        cves = set(CVE_RE.findall(haystack))
        if cves:
            out.append({"cves": sorted(cves),
                        "title": item.get("title", ""),
                        "url": item.get("link", item.get("url", ""))})
    return out


# ------------------------------------------------------------------------ matching

def canonical_id(osv_detail, fallback):
    """Canonical vuln identity: prefer a CVE alias so OSV(GHSA)/KEV/pulse
    findings merge into ONE finding instead of several with contradictory
    confidence. Precedence: CVE > GHSA/other id.

    Every consumed field is type-guarded: feeds are untrusted, and a
    schema-violating response must degrade a source, never crash the scan."""
    if isinstance(osv_detail, dict):
        aliases = osv_detail.get("aliases")
        if isinstance(aliases, list):
            for alias in sorted(a for a in aliases if isinstance(a, str)):
                if alias.startswith("CVE-") and VULN_ID_RE.match(alias):
                    return alias
        vid = osv_detail.get("id")
        if isinstance(vid, str) and vid.startswith("CVE-") \
                and VULN_ID_RE.match(vid):
            return vid
    return fallback


def kev_haystacks(kev_vulns):
    """Lowercased (entry, vendor+product) pairs, built ONCE per run. The KEV
    catalog is ~1300 entries and matching runs per product, so rebuilding these
    strings inside the per-product loop is pure rework."""
    return [(v, ("%s %s" % (v.get("vendorProject", ""),
                            v.get("product", ""))).lower())
            for v in kev_vulns]


def kev_name_matches(haystacks, aliases):
    """Name/alias match against KEV vendorProject+product. KEV has no version
    data, so these can only ever seed `possible` on their own."""
    lowered = [a.lower() for a in aliases]
    return [v for v, hay in haystacks if any(a in hay for a in lowered)]


def build_findings(installed, watchlist, osv_hits, kev_vulns, pulse_items):
    findings = {}  # canonical id -> finding

    def get(cid, product):
        """One finding per canonical vuln id, but carrying EVERY affected
        product. Keying on the id alone and keeping only the first product made
        a second equally-matched product render as "no matching advisories" —
        a vulnerable product reading clean."""
        f = findings.setdefault(cid, {
            "id": cid, "products": [], "sources": [],
            "confidence": "possible", "actively_exploited": False,
            "summary": "", "kev_date": "", "urls": [], "pulse": None})
        if product not in f["products"]:
            f["products"].append(product)
        return f

    for vid, hit in sorted(osv_hits.items()):
        detail = hit["detail"]
        cid = canonical_id(detail, vid)
        f = None
        for owner in hit.get("products", []):
            f = get(cid, owner)   # same finding object, one entry per product
        if f is None:
            continue
        if "osv" not in f["sources"]:
            f["sources"].append("osv")
        f["confidence"] = "confirmed"  # OSV matched the exact installed version
        if isinstance(detail, dict):
            # Type-guard every field: a feed returning `references` as a list of
            # strings, or `details` as an object, must not raise.
            for key in ("summary", "details"):
                val = detail.get(key)
                if isinstance(val, str) and val:
                    f["summary"] = val[:200]
                    break
            refs = detail.get("references")
            if isinstance(refs, list):
                for ref in refs[:3]:
                    if not isinstance(ref, dict):
                        continue
                    u = safe_url(ref.get("url", ""))
                    if u:
                        f["urls"].append(u)

    kev_by_cve = {v.get("cveID"): v for v in kev_vulns if v.get("cveID")}
    haystacks = kev_haystacks(kev_vulns)
    for item in installed:
        if not item["present"]:
            continue
        spec = watchlist["products"][item["product"]]
        for v in kev_name_matches(haystacks, spec.get("aliases", [])):
            cid = v.get("cveID", "")
            if not cid:
                continue
            f = get(cid, item["product"])
            if "kev" not in f["sources"]:
                f["sources"].append("kev")
            f["kev_date"] = v.get("dateAdded", "")
            if not f["summary"]:
                f["summary"] = v.get("shortDescription", "")
            # Deliberately does NOT set actively_exploited. Alias matching is
            # unanchored substring matching against KEV's vendor+product text,
            # so a KEV entry naming a DIFFERENT product could otherwise flip
            # this product's OSV finding to "ACTIVELY EXPLOITED". Only the
            # canonical-CVE loop below may set that flag.

    for f in findings.values():
        if f["id"] in kev_by_cve and "osv" in f["sources"]:
            # Mirror the name-match branch exactly: a finding that renders
            # "ACTIVELY EXPLOITED (CISA KEV)" must also list kev in Sources and
            # carry its dateAdded, or the report contradicts itself.
            v = kev_by_cve[f["id"]]
            if "kev" not in f["sources"]:
                f["sources"].append("kev")
            if not f["kev_date"]:
                f["kev_date"] = v.get("dateAdded", "")
            if not f["summary"]:
                f["summary"] = v.get("shortDescription", "")
            f["actively_exploited"] = True
        for item in pulse_items:
            if f["id"] in item["cves"]:
                f["pulse"] = {"title": item["title"], "url": safe_url(item["url"])}
                if "pulse" not in f["sources"]:
                    f["sources"].append("pulse")
    return sorted(findings.values(),
                  key=lambda f: (f["confidence"] != "confirmed",
                                 not f["actively_exploited"], f["id"]))


# ----------------------------------------------------------------------- rendering

def product_state(item, spec, findings, osv_ran):
    # A finding lists EVERY product it affects, so a CVE hitting two watched
    # products marks both "matched" — checking only a single owner product
    # made the second one render as if nothing matched it.
    if any(item["product"] in f["products"] for f in findings):
        return "matched"
    if not item["version"]:
        return "version unknown"
    if not spec.get("osv_queries"):
        return "not covered"
    if not osv_ran:
        return "not evaluated (source unavailable)"
    return "no matching advisories in covered sources"


def render_markdown(now, installed, watchlist, findings, state, probing):
    lines = []
    add = lines.append
    add("# Agentic stack exposure report")
    add("")
    add("Generated %s by exposure-report.py (schema v%d). Read-only scan%s." % (
        now.strftime("%Y-%m-%d"), SCHEMA_VERSION,
        "; binary probing ENABLED" if probing else "; no target binaries executed"))
    add("")
    confirmed = [f for f in findings if f["confidence"] == "confirmed"]
    add("## Summary")
    add("")
    add("- Products present: %d of %d watched" %
        (sum(1 for i in installed if i["present"]), len(installed)))
    add("- Findings: %d confirmed, %d possible" %
        (len(confirmed), len(findings) - len(confirmed)))
    add("- Actively exploited (KEV-corroborated): %d" %
        sum(1 for f in findings if f["actively_exploited"]))
    add("")
    if findings:
        add("## Findings")
        add("")
        for f in findings:
            specs = [watchlist["products"][p] for p in f["products"]
                     if p in watchlist["products"]]
            names = ", ".join(s["name"] for s in specs) or "unknown product"
            flag = "⚠ ACTIVELY EXPLOITED (CISA KEV%s)" % (
                ", added %s" % sanitize(f["kev_date"]) if f["kev_date"] else "") \
                if f["actively_exploited"] else f["confidence"].upper()
            add("### %s — %s — %s" % (sanitize(f["id"]), names, flag))
            add("")
            if f["summary"]:
                add("%s" % sanitize(f["summary"]))
                add("")
            add("- Sources: %s" % ", ".join(sorted(f["sources"])))
            for u in f["urls"][:3]:
                add("- Advisory: <%s>" % u)
            if f["pulse"] and f["pulse"]["url"]:
                add("- Pulse enrichment: [%s](%s)" %
                    (sanitize(f["pulse"]["title"]), f["pulse"]["url"]))
            # One hardening pointer per affected product — a CVE hitting two
            # products has two mitigations to name, not one.
            for spec in specs:
                g = spec.get("guide", {})
                if g.get("part"):
                    add("- Hardening (%s): `%s`%s" % (
                        spec["name"], g["part"],
                        " · control template `%s`" % g["template"]
                        if g.get("template") else ""))
            add("")
    add("## Products")
    add("")
    add("| Product | Present | Version | State |")
    add("|---------|---------|---------|-------|")
    osv_ran = state.status.get("osv") in ("live", "cache", "replay")
    for item in installed:
        spec = watchlist["products"][item["product"]]
        add("| %s | %s | %s | %s |" % (
            spec["name"], "yes" if item["present"] else "no",
            sanitize(item["version"]) if item["version"] else "unknown",
            product_state(item, spec, findings, osv_ran) if item["present"] else "—"))
    add("")
    add("## Coverage (what this scan can and cannot see)")
    add("")
    for src in ("osv", "kev", "pulse"):
        st = state.status.get(src, "skipped")
        note = state.notes.get(src, "")
        add("- %s: %s%s" % (src.upper(), st, " — %s" % sanitize(note) if note else ""))
    limited = sorted(watchlist["products"][i["product"]]["name"]
                     for i in installed
                     if i["present"] and not
                     watchlist["products"][i["product"]].get("osv_queries"))
    if limited:
        add("- Limited coverage (no OSV data; KEV+pulse name-matching only): %s"
            % ", ".join(limited))
    add("- Not visible to this scan: transitive dependencies, bundled runtimes "
        "(Electron/Chromium), install channels not in the watchlist, and "
        "products outside it. Absence of findings is **not** absence of risk.")
    add("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--watchlist", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "agentic-watchlist.json"))
    ap.add_argument("--inventory", help="inventory-agents.sh --json output (JSONL)")
    ap.add_argument("--osv", help="replay file for the OSV batch (+details)")
    ap.add_argument("--kev", help="replay file for the CISA KEV catalog")
    ap.add_argument("--feed", help="replay file for pulse latest.json")
    ap.add_argument("--now", help="ISO date for deterministic output (fixtures/CI)")
    ap.add_argument("--offline", action="store_true",
                    help="cache/replay only; never opens a socket")
    ap.add_argument("--probe-binaries", action="store_true",
                    help="allow executing target binaries for version discovery "
                         "(OFF by default: a compromised target must not run "
                         "inside the scanner)")
    ap.add_argument("--out", default=os.environ.get(
        "AGENT_ASSESSMENT_OUT", os.path.join(os.getcwd(), ".agent-assessment")))
    args = ap.parse_args(argv)

    now = datetime.fromisoformat(args.now) if args.now else datetime.now()
    deadline = time.monotonic() + SOFT_BUDGET
    state = SourceState()

    try:
        with open(args.watchlist, encoding="utf-8") as fh:
            watchlist = json.load(fh)
        products = watchlist["products"]
        assert isinstance(products, dict) and products
    except (OSError, ValueError, KeyError, AssertionError) as exc:
        print("exposure-report: cannot load watchlist (%s): %s" %
              (args.watchlist, exc), file=sys.stderr)
        return 3

    inventory_products = set()
    if args.inventory:
        try:
            with open(args.inventory, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        print("exposure-report: malformed inventory line skipped",
                              file=sys.stderr)
                        continue
                    pid = rec.get("product") or ""
                    if pid in products:
                        inventory_products.add(pid)
        except OSError as exc:
            print("exposure-report: cannot read inventory: %s" % exc,
                  file=sys.stderr)
            return 3

    installed = [discover_product(p, spec, inventory_products,
                                  args.probe_binaries)
                 for p, spec in sorted(products.items())]

    osv_hits = query_osv(installed, watchlist, args.osv, args.offline,
                         now, state, deadline)
    kev_vulns = load_kev(args.kev, args.offline, now, state, deadline)
    pulse_items = load_pulse(args.feed, args.offline, now, state, deadline)

    if not state.usable():
        print("exposure-report: no advisory source reachable and no usable "
              "cache — cannot produce a report (try --offline with fixtures, "
              "or check the network).", file=sys.stderr)
        return 3

    findings = build_findings(installed, watchlist, osv_hits, kev_vulns,
                              pulse_items)

    os.makedirs(args.out, exist_ok=True)
    md = render_markdown(now, installed, watchlist, findings, state,
                         args.probe_binaries)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated": now.strftime("%Y-%m-%d"),
        "probing": bool(args.probe_binaries),
        "products": [{**i, "state": product_state(
            i, products[i["product"]], findings,
            state.status.get("osv") in ("live", "cache", "replay"))
            if i["present"] else "absent"} for i in installed],
        "findings": findings,
        "sources": {"status": state.status, "notes": state.notes},
    }
    md_path = os.path.join(args.out, "exposure-report.md")
    json_path = os.path.join(args.out, "exposure-report.json")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")

    skipped = state.skipped()
    print("exposure-report: %s (findings: %d%s)" % (
        md_path, len(findings),
        "; DEGRADED — skipped: %s" % ", ".join(skipped) if skipped else ""),
        file=sys.stderr)
    return 2 if skipped else 0


if __name__ == "__main__":
    sys.exit(main())
