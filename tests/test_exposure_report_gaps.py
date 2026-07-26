#!/usr/bin/env python3
"""Gap-coverage suite for exposure-report.py + shell wiring (ship coverage gate).

Covers the paths the primary suite (test_exposure_report.py) left open:
  - assess.sh exit-code surfacing (degraded → 2, failed → 3) — the "never a
    silent green scorecard" contract itself
  - lint.sh drift-loop DETECTION (a broken loop would pass silently)
  - inventory-agents.sh --json field contract + default-output regression (SIEM)
  - the honest-taxonomy product states beyond "matched"
  - main() exit-3 inputs (missing/corrupt watchlist, unreadable inventory)
  - load_with_cache ladder: unreadable replay, fresh cache hit, stale cache
  - metadata version handlers: brew_cellar, macos_app_plist, pip_dist_info,
    npm scoped-package path
  - source schema guards: KEV bad schema, pulse non-object item, OSV "n/a"

All tests are socket-free (replay files, --offline, isolated XDG_CACHE_HOME).
"""

import importlib.util
import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(REPO, "tests", "fixtures")
SCRIPT = os.path.join(REPO, "templates", "discovery", "exposure-report.py")

spec = importlib.util.spec_from_file_location("exposure_report_gaps", SCRIPT)
er = importlib.util.module_from_spec(spec)
spec.loader.exec_module(er)


def fx(name):
    return os.path.join(FIX, name)


class IsolatedEnvMixin:
    """Isolation that RESTORES process-global state: cwd and XDG_CACHE_HOME are
    saved and put back, so this suite can't make a later one order-dependent
    (or delete a real XDG_CACHE_HOME that CI legitimately set)."""

    def setUp(self):
        self._prev_cwd = os.getcwd()
        self._prev_cache_env = os.environ.get("XDG_CACHE_HOME")
        os.chdir(REPO)   # fixture watchlists use repo-relative source roots
        self.out = tempfile.mkdtemp(prefix="exposure-gaps-out-")
        self.cache = tempfile.mkdtemp(prefix="exposure-gaps-cache-")
        os.environ["XDG_CACHE_HOME"] = self.cache

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)
        shutil.rmtree(self.cache, ignore_errors=True)
        if self._prev_cache_env is None:
            os.environ.pop("XDG_CACHE_HOME", None)
        else:
            os.environ["XDG_CACHE_HOME"] = self._prev_cache_env
        os.chdir(self._prev_cwd)

    def read_report(self):
        with open(os.path.join(self.out, "exposure-report.md"),
                  encoding="utf-8") as fh:
            md = fh.read()
        with open(os.path.join(self.out, "exposure-report.json"),
                  encoding="utf-8") as fh:
            report = json.load(fh)
        return md, report


class TestHonestTaxonomyStates(IsolatedEnvMixin, unittest.TestCase):
    """The report's honesty vocabulary: every non-matched state renders."""

    def run_taxonomy(self, *extra, osv="osv-empty.json"):
        argv = ["--watchlist", fx("watchlist-taxonomy.json"),
                "--inventory", fx("inventory-taxonomy.jsonl"),
                "--kev", fx("kev-empty.json"),
                "--feed", fx("pulse-fixture.json"),
                "--now", "2026-07-01", "--out", self.out]
        if osv:
            argv += ["--osv", fx(osv)]
        return er.main(argv + list(extra))

    def state_of(self, report, product):
        return next(p for p in report["products"]
                    if p["product"] == product)["state"]

    def test_all_non_matched_states_render(self):
        rc = self.run_taxonomy()
        self.assertEqual(rc, 0)
        md, report = self.read_report()
        self.assertEqual(self.state_of(report, "covered-versioned"),
                         "no matching advisories in covered sources")
        self.assertEqual(self.state_of(report, "uncovered-versioned"),
                         "not covered")
        self.assertEqual(self.state_of(report, "present-no-version"),
                         "version unknown")
        for cell in ("no matching advisories in covered sources",
                     "not covered", "version unknown"):
            self.assertIn(cell, md)
        self.assertNotRegex(md, r"(?i)\bclean\b")

    def test_not_evaluated_when_osv_unavailable(self):
        # versioned + OSV-covered product, but OSV skipped (offline, no replay)
        rc = self.run_taxonomy("--offline", osv=None)
        self.assertEqual(rc, 2)  # osv skipped → degraded
        _, report = self.read_report()
        self.assertEqual(self.state_of(report, "covered-versioned"),
                         "not evaluated (source unavailable)")

    def test_osv_na_when_no_versioned_covered_products(self):
        # Only the unversioned product is present → no OSV queries → "n/a",
        # NOT "skipped" (a machine with nothing to ask OSV about must not
        # exit 2 as if the run were degraded).
        rc = er.main(["--watchlist", fx("watchlist-taxonomy2.json"),
                      "--inventory", fx("inventory-taxonomy.jsonl"),
                      "--kev", fx("kev-empty.json"),
                      "--feed", fx("pulse-fixture.json"),
                      "--now", "2026-07-01", "--out", self.out])
        self.assertEqual(rc, 0)
        md, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["osv"], "n/a")
        self.assertIn("OSV: n/a", md)


class TestMainExit3Inputs(IsolatedEnvMixin, unittest.TestCase):
    def test_missing_watchlist_exit_3(self):
        rc = er.main(["--watchlist", "/nonexistent/watchlist.json",
                      "--now", "2026-07-01", "--out", self.out])
        self.assertEqual(rc, 3)

    def test_corrupt_watchlist_exit_3(self):
        bad = os.path.join(self.out, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{ not json")
        rc = er.main(["--watchlist", bad, "--now", "2026-07-01",
                      "--out", self.out])
        self.assertEqual(rc, 3)

    def test_unreadable_inventory_exit_3(self):
        rc = er.main(["--watchlist", fx("watchlist-fixture.json"),
                      "--inventory", "/nonexistent/inventory.jsonl",
                      "--now", "2026-07-01", "--out", self.out])
        self.assertEqual(rc, 3)


class TestCacheLadder(IsolatedEnvMixin, unittest.TestCase):
    def run_kev_only(self):
        return er.main(["--watchlist", fx("watchlist-patched.json"),
                        "--inventory", fx("inventory-fixture.jsonl"),
                        "--osv", fx("osv-empty.json"),
                        "--feed", fx("pulse-fixture.json"),
                        "--now", "2026-07-01", "--out", self.out,
                        "--offline"])

    def test_unreadable_replay_file_is_skipped(self):
        rc = er.main(["--watchlist", fx("watchlist-patched.json"),
                      "--inventory", fx("inventory-fixture.jsonl"),
                      "--osv", fx("osv-empty.json"),
                      "--kev", "/nonexistent/kev.json",
                      "--feed", fx("pulse-fixture.json"),
                      "--now", "2026-07-01", "--out", self.out])
        self.assertEqual(rc, 2)
        md, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["kev"], "skipped")
        self.assertIn("replay file unreadable", md)

    def test_fresh_cache_hit_offline(self):
        feed_dir = os.path.join(self.cache, "agentic-ai-hardening", "feeds")
        os.makedirs(feed_dir)
        with open(fx("kev-fixture.json"), encoding="utf-8") as src, \
             open(os.path.join(feed_dir, "kev.json"), "w",
                  encoding="utf-8") as dst:
            dst.write(src.read())
        rc = self.run_kev_only()
        _, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["kev"], "cache")
        self.assertEqual(rc, 0)  # a fresh cache hit is a usable source

    def test_stale_cache_is_skipped(self):
        feed_dir = os.path.join(self.cache, "agentic-ai-hardening", "feeds")
        os.makedirs(feed_dir)
        cpath = os.path.join(feed_dir, "kev.json")
        with open(fx("kev-fixture.json"), encoding="utf-8") as src, \
             open(cpath, "w", encoding="utf-8") as dst:
            dst.write(src.read())
        eight_days = 8 * 24 * 3600
        past = os.stat(cpath).st_mtime - eight_days
        os.utime(cpath, (past, past))
        rc = self.run_kev_only()
        self.assertEqual(rc, 2)
        _, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["kev"], "skipped")
        self.assertIn("cache stale", report["sources"]["notes"]["kev"])


class TestSourceSchemaGuards(IsolatedEnvMixin, unittest.TestCase):
    def test_kev_bad_schema_is_source_down(self):
        rc = er.main(["--watchlist", fx("watchlist-patched.json"),
                      "--inventory", fx("inventory-fixture.jsonl"),
                      "--osv", fx("osv-empty.json"),
                      "--kev", fx("kev-bad-schema.json"),
                      "--feed", fx("pulse-fixture.json"),
                      "--now", "2026-07-01", "--out", self.out])
        self.assertEqual(rc, 2)
        _, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["kev"], "skipped")
        self.assertIn("unexpected KEV schema",
                      report["sources"]["notes"]["kev"])

    def test_pulse_non_object_item_is_source_down(self):
        rc = er.main(["--watchlist", fx("watchlist-patched.json"),
                      "--inventory", fx("inventory-fixture.jsonl"),
                      "--osv", fx("osv-empty.json"),
                      "--kev", fx("kev-fixture.json"),
                      "--feed", fx("pulse-nonobject.json"),
                      "--now", "2026-07-01", "--out", self.out])
        self.assertEqual(rc, 2)
        _, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["pulse"], "skipped")


class TestNetworkBounds(IsolatedEnvMixin, unittest.TestCase):
    """Size-cap enforcement and the --offline no-network guarantee, both
    asserted without opening a socket (urlopen is patched)."""

    def test_response_size_cap_enforced(self):
        import io
        from unittest import mock

        class FakeResp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        oversized = FakeResp(b"x" * (er.SMALL_CAP + 10))
        with mock.patch.object(er.urllib.request, "urlopen",
                               return_value=oversized):
            with self.assertRaisesRegex(ValueError, "size cap"):
                er.http_get_json("https://example.com/big", er.SMALL_CAP)

    def test_offline_never_calls_urlopen(self):
        from unittest import mock

        def boom(*a, **kw):  # any network attempt fails the test
            raise AssertionError("network call attempted in --offline mode")

        with mock.patch.object(er.urllib.request, "urlopen", side_effect=boom):
            rc = er.main(["--watchlist", fx("watchlist-fixture.json"),
                          "--inventory", fx("inventory-fixture.jsonl"),
                          "--osv", fx("osv-confirmed.json"),
                          "--kev", fx("kev-fixture.json"),
                          "--feed", fx("pulse-fixture.json"),
                          "--now", "2026-07-01", "--out", self.out,
                          "--offline"])
        self.assertEqual(rc, 0)


class TestSoftBudgetEnforcement(IsolatedEnvMixin, unittest.TestCase):
    """REGRESSION: the soft budget must actually bound wall time.

    The original code checked the deadline only in the submit loop — but
    ThreadPoolExecutor.submit() is non-blocking, so all detail futures enqueued
    instantly and as_completed() waited with no timeout. The budget was dead
    code and a slow OSV could blow the stated <60s run budget.
    """

    WATCHLIST = None  # built per-test

    def _live_osv_env(self, detail_side_effect):
        """query_osv on the live path (no --osv replay) with patched HTTP."""
        from unittest import mock
        state = er.SourceState()
        installed = [{"product": "ollama", "present": True,
                      "version": "0.9.2", "evidence": "fixture"}]
        with open(fx("watchlist-fixture.json"), encoding="utf-8") as fh:
            watchlist = json.load(fh)
        batch = {"results": [{"vulns": [{"id": "OSV-%d" % i}
                                       for i in range(10)]}]}
        with mock.patch.object(er, "http_post_json", return_value=batch), \
             mock.patch.object(er, "http_get_json",
                               side_effect=detail_side_effect):
            hits = er.query_osv(installed, watchlist, None, False,
                                er.datetime.now(), state,
                                self.deadline)
        return hits, state

    def test_past_deadline_leaves_details_unfetched_without_hanging(self):
        self.deadline = er.time.monotonic() - 1  # already past budget
        calls = []

        def detail(url, cap):
            calls.append(url)
            return {"id": "x"}

        hits, state = self._live_osv_env(detail)
        # Every worker short-circuits: no detail HTTP call is made at all.
        self.assertEqual(calls, [])
        self.assertEqual(len(hits), 10)  # batch hits still reported
        self.assertTrue(all(h["detail"] is None for h in hits.values()))

    def test_within_deadline_fetches_details(self):
        self.deadline = er.time.monotonic() + 30
        hits, _ = self._live_osv_env(
            lambda url, cap: {"id": url.rsplit("/", 1)[-1],
                              "summary": "s", "aliases": []})
        self.assertTrue(any(h["detail"] is not None for h in hits.values()))

    def test_read_capped_enforces_read_deadline(self):
        """A drip-feeding server must not outlive the read deadline even
        though each individual socket read returns promptly."""
        import io
        from unittest import mock

        class DripResp(io.RawIOBase):
            def read(self, n=-1):
                # each read is fast but tiny; er.time.monotonic is patched to
                # jump past the deadline, proving the wall-clock guard fires
                return b"x"

        ticks = iter([0, 1, er.REQUEST_TIMEOUT + 5, er.REQUEST_TIMEOUT + 6])
        with mock.patch.object(er.time, "monotonic",
                               side_effect=lambda: next(ticks)):
            with self.assertRaisesRegex(TimeoutError, "read deadline"):
                er._read_capped(DripResp(), er.LARGE_CAP)

    def test_read_capped_enforces_size_cap(self):
        import io
        big = io.BytesIO(b"y" * 5000)
        with self.assertRaisesRegex(ValueError, "size cap"):
            er._read_capped(big, 100)


class TestUntrustedInputHardening(IsolatedEnvMixin, unittest.TestCase):
    """Versions and feed payloads are third-party-writable. None of them may
    inject Markdown into the report or crash the scan."""

    def test_version_cannot_inject_markdown(self):
        installed = [{"product": "ollama", "present": True,
                      "version": "1.0 |\n\n## PWNED\n\n[x](https://evil.example)",
                      "evidence": "fixture"}]
        with open(fx("watchlist-fixture.json"), encoding="utf-8") as fh:
            watchlist = json.load(fh)
        md = er.render_markdown(er.datetime(2026, 1, 1), installed, watchlist,
                                [], er.SourceState(), False)
        self.assertNotIn("## PWNED", md)
        self.assertNotIn("[x](https://evil.example)", md)

    def test_hostile_version_string_rejected_at_discovery(self):
        """A package.json in a cloned repo can put anything in "version" —
        it must never reach an OSV query or the report."""
        tmp = tempfile.mkdtemp(prefix="hostile-ver-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with open(os.path.join(tmp, "package.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"version": "1.0 |\n## PWNED"}, fh)
        spec = {"version_sources": [{"type": "clone_package_json",
                                     "roots": [tmp]}]}
        item = er.discover_product("p", spec, set(), False)
        self.assertTrue(item["present"])      # still reported as installed
        self.assertIsNone(item["version"])    # but the version is unusable

    def test_url_cannot_break_out_of_markdown_link(self):
        u = er.safe_url("https://ok.example/a)![beacon](https://evil.example/p.png")
        self.assertTrue(u)                    # scheme is fine, so not rejected
        rendered = "[title](%s)" % u
        self.assertNotIn(")!", rendered)      # no breakout
        self.assertEqual(rendered.count("]("), 1)

    def test_osv_detail_with_string_references_does_not_crash(self):
        installed = [{"product": "ollama", "present": True,
                      "version": "0.9.2", "evidence": "fixture"}]
        with open(fx("watchlist-fixture.json"), encoding="utf-8") as fh:
            watchlist = json.load(fh)
        hits = {"GHSA-x": {"products": ["ollama"], "detail": {
            "id": "GHSA-x", "aliases": [None, 42, "CVE-2026-5"],
            "details": {"nested": "object"},
            "references": ["https://not-a-dict.example"]}}}
        findings = er.build_findings(installed, watchlist, hits, [], [])
        self.assertEqual(findings[0]["id"], "CVE-2026-5")  # alias still merged
        self.assertEqual(findings[0]["urls"], [])          # bad refs dropped

    def test_kev_entries_as_strings_are_schema_rejected(self):
        bad = os.path.join(self.out, "kev-strings.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"vulnerabilities": ["CVE-2026-1", "CVE-2026-2"]}, fh)
        rc = er.main(["--watchlist", fx("watchlist-patched.json"),
                      "--inventory", fx("inventory-fixture.jsonl"),
                      "--osv", fx("osv-empty.json"), "--kev", bad,
                      "--feed", fx("pulse-fixture.json"),
                      "--now", "2026-07-01", "--out", self.out])
        self.assertEqual(rc, 2)   # degraded, NOT a traceback
        with open(os.path.join(self.out, "exposure-report.json"),
                  encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["sources"]["status"]["kev"],
                             "skipped")

    def test_hostile_vuln_id_never_reaches_a_url(self):
        from unittest import mock
        state = er.SourceState()
        installed = [{"product": "ollama", "present": True,
                      "version": "0.9.2", "evidence": "fixture"}]
        with open(fx("watchlist-fixture.json"), encoding="utf-8") as fh:
            watchlist = json.load(fh)
        batch = {"results": [{"vulns": [{"id": "../../etc/passwd"},
                                        {"id": "OK-1"}]}]}
        seen = []
        with mock.patch.object(er, "http_post_json", return_value=batch), \
             mock.patch.object(er, "http_get_json",
                               side_effect=lambda u, c: seen.append(u) or {}):
            hits = er.query_osv(installed, watchlist, None, False,
                                er.datetime.now(), state,
                                er.time.monotonic() + 30)
        self.assertEqual(sorted(hits), ["OK-1"])   # traversal id dropped
        self.assertTrue(all("etc/passwd" not in u for u in seen))


class TestHonestyCannotBeMadeToLie(IsolatedEnvMixin, unittest.TestCase):
    """The adversarial review's highest-value findings: every one of these is a
    way the report could state something false about a machine. Each test fails
    against the pre-fix code."""

    def run_two(self, osv, kev, watchlist="watchlist-two-covered.json"):
        argv = ["--watchlist", fx(watchlist),
                "--osv", fx(osv), "--kev", fx(kev),
                "--feed", fx("pulse-fixture.json"),
                "--now", "2026-07-01", "--out", self.out]
        return er.main(argv)

    def state_of(self, report, product):
        return next(p for p in report["products"]
                    if p["product"] == product)["state"]

    def test_one_cve_two_products_marks_both(self):
        """A CVE affecting two watched products must mark BOTH matched. Keying
        findings by id alone let the second render as if nothing hit it — a
        vulnerable product reading clean."""
        rc = self.run_two("osv-two-results.json", "kev-empty.json")
        self.assertEqual(rc, 0)
        md, report = self.read_report()
        finding = next(f for f in report["findings"]
                       if f["id"] == "CVE-2026-77777")
        self.assertEqual(sorted(finding["products"]), ["alpha", "beta"])
        self.assertEqual(self.state_of(report, "alpha"), "matched")
        self.assertEqual(self.state_of(report, "beta"), "matched")
        # and both hardening pointers are named, not just the first
        self.assertIn("Hardening (Alpha)", md)
        self.assertIn("Hardening (Beta)", md)

    def test_kev_naming_another_product_does_not_escalate(self):
        """KEV alias matching is unanchored substring matching, so a KEV entry
        naming Beta must NOT flip Alpha's OSV finding to actively exploited."""
        rc = self.run_two("osv-alpha-only.json", "kev-beta-only.json")
        self.assertEqual(rc, 0)
        md, report = self.read_report()
        alpha = next(f for f in report["findings"]
                     if "alpha" in f["products"])
        self.assertEqual(alpha["confidence"], "confirmed")   # OSV did confirm
        self.assertTrue(alpha["actively_exploited"],
                        "same CVE id IS in KEV, so this one legitimately is")
        # The real regression guard: a KEV entry for a DIFFERENT CVE must never
        # reach this finding.
        rc = self.run_two("osv-two-results.json", "kev-beta-only.json")
        _, report2 = self.read_report()
        shared = next(f for f in report2["findings"]
                      if f["id"] == "CVE-2026-77777")
        self.assertFalse(shared["actively_exploited"])
        self.assertNotIn("kev", shared["sources"])

    def test_osv_result_count_mismatch_is_not_silently_trusted(self):
        """Attribution rides on array position: a short results array would
        zip()-truncate and leave a product silently unevaluated."""
        short = os.path.join(self.out, "osv-short.json")
        with open(short, "w", encoding="utf-8") as fh:
            json.dump({"results": [{"vulns": []}]}, fh)   # 1 result, 2 queries
        rc = er.main(["--watchlist", fx("watchlist-two-covered.json"),
                      "--osv", short, "--kev", fx("kev-empty.json"),
                      "--feed", fx("pulse-fixture.json"),
                      "--now", "2026-07-01", "--out", self.out])
        self.assertEqual(rc, 2)          # degraded, not a false all-clear
        _, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["osv"], "skipped")
        self.assertIn("does not match", report["sources"]["notes"]["osv"])
        # neither product may claim it was evaluated
        for p in ("alpha", "beta"):
            self.assertEqual(self.state_of(report, p),
                             "not evaluated (source unavailable)")

    def test_backslash_cannot_re_enable_markdown(self):
        """Escaping specials without doubling a pre-existing backslash turns
        feed text into a LIVE link — the escape becomes the injection."""
        # Backslash doubled FIRST, then the bracket escaped: `\\` renders as a
        # literal backslash and `\[` as a literal bracket, so no link survives.
        # Without the doubling this collapses back into working link syntax.
        self.assertEqual(er.sanitize(r"\[text\](http://evil.example)"),
                         r"\\\[text\\\](http://evil.example)")

    def test_bidi_and_zero_width_stripped(self):
        for ch in ("‮", "⁦", "​", " ", "", ""):
            self.assertNotIn(ch, er.sanitize("a%sb" % ch))

    def test_userinfo_url_rejected(self):
        """https://api.osv.dev@evil.example/x reads as osv.dev to a human
        clicking an advisory link."""
        self.assertEqual(er.safe_url("https://api.osv.dev@evil.example/x"), "")
        self.assertEqual(er.safe_url("https://ok.example/" + "a" * 600), "")
        self.assertTrue(er.safe_url("https://api.osv.dev/v1/vulns/CVE-2026-1"))


class TestCacheIntegrity(IsolatedEnvMixin, unittest.TestCase):
    """The cache is read as authoritative advisory data, so a planted entry can
    make the scanner report a clean machine. It must be user-owned, a real
    file, and not forward-dated."""

    def feed_path(self, name="kev.json"):
        d = os.path.join(self.cache, "agentic-ai-hardening", "feeds")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, name)

    def run_offline(self):
        return er.main(["--watchlist", fx("watchlist-patched.json"),
                        "--inventory", fx("inventory-fixture.jsonl"),
                        "--osv", fx("osv-empty.json"),
                        "--feed", fx("pulse-fixture.json"),
                        "--now", "2026-07-01", "--out", self.out, "--offline"])

    def test_symlinked_cache_is_not_read(self):
        victim = os.path.join(self.out, "victim.json")
        with open(victim, "w", encoding="utf-8") as fh:
            json.dump({"vulnerabilities": []}, fh)
        os.symlink(victim, self.feed_path())
        rc = self.run_offline()
        self.assertEqual(rc, 2)
        _, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["kev"], "skipped")
        self.assertIn("not a regular file", report["sources"]["notes"]["kev"])

    def test_cache_write_does_not_follow_symlink(self):
        victim = os.path.join(self.out, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        cpath = self.feed_path("probe.json")
        os.symlink(victim, cpath)
        er._cache_write(cpath, {"hello": "world"})
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")   # untouched
        self.assertFalse(os.path.islink(cpath))       # symlink replaced

    def test_forward_dated_cache_is_rejected(self):
        cpath = self.feed_path()
        with open(fx("kev-fixture.json"), encoding="utf-8") as src, \
             open(cpath, "w", encoding="utf-8") as dst:
            dst.write(src.read())
        future = os.stat(cpath).st_mtime + 90 * 24 * 3600
        os.utime(cpath, (future, future))
        rc = self.run_offline()
        self.assertEqual(rc, 2)
        _, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["kev"], "skipped")

    def test_cache_hit_is_labelled_as_cached_not_current(self):
        cpath = self.feed_path()
        with open(fx("kev-fixture.json"), encoding="utf-8") as src, \
             open(cpath, "w", encoding="utf-8") as dst:
            dst.write(src.read())
        self.run_offline()
        md, report = self.read_report()
        self.assertEqual(report["sources"]["status"]["kev"], "cache")
        self.assertIn("using cached copy", md)


class TestKevHaystackPrecompute(unittest.TestCase):
    def test_haystacks_built_once_and_match(self):
        kev = [{"cveID": "CVE-1", "vendorProject": "Ollama", "product": "Ollama"},
               {"cveID": "CVE-2", "vendorProject": "Acme", "product": "Widget"}]
        hays = er.kev_haystacks(kev)
        self.assertEqual(len(hays), 2)
        self.assertEqual(hays[0][1], "ollama ollama")  # lowered once
        matched = er.kev_name_matches(hays, ["ollama"])
        self.assertEqual([v["cveID"] for v in matched], ["CVE-1"])
        self.assertEqual(er.kev_name_matches(hays, ["nothing-here"]), [])


class TestVersionHandlers(unittest.TestCase):
    """Read-only metadata handlers, one fixture filesystem each."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="exposure-vh-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_brew_cellar_picks_version_dir(self):
        cellar = os.path.join(self.tmp, "Cellar", "ollama")
        os.makedirs(os.path.join(cellar, "0.5.1"))
        v, ev = er.version_from_brew_cellar({"paths": [cellar]})
        self.assertEqual(v, "0.5.1")
        self.assertEqual(ev, cellar)

    def test_brew_cellar_picks_semantically_newest(self):
        """brew keeps old versions until `brew cleanup`. Lexicographic sorting
        would pick 0.9.2 over 0.10.0 — reporting the OLD, vulnerable install
        and rendering a patched machine as actively exploited."""
        cellar = os.path.join(self.tmp, "Cellar", "ollama")
        for v in ("0.9.2", "0.10.0"):
            os.makedirs(os.path.join(cellar, v))
        got, _ = er.version_from_brew_cellar({"paths": [cellar]})
        self.assertEqual(got, "0.10.0")

    def test_pip_dist_info_picks_semantically_newest(self):
        site = os.path.join(self.tmp, "sp")
        for v in ("1.9.0", "1.61.3"):
            os.makedirs(os.path.join(site, "litellm-%s.dist-info" % v))
        got, _ = er.version_from_pip_dist_info(
            {"package": "litellm", "roots": [site]})
        self.assertEqual(got, "1.61.3")

    def test_version_key_orders_numerically(self):
        self.assertEqual(
            sorted(["0.9.2", "0.10.0", "0.10.1"], key=er.version_key)[-1],
            "0.10.1")

    def test_npm_global_no_root_fallback(self):
        """With a package NAME given, a bare <root>/package.json must NOT be
        used — that would attribute an unrelated package's version to this
        product and send a wrong version to OSV."""
        root = os.path.join(self.tmp, "node_modules")
        os.makedirs(root)
        with open(os.path.join(root, "package.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"version": "99.99.99"}, fh)
        v, _ = er.version_from_npm_global(
            {"package": "@anthropic-ai/claude-code", "roots": [root]})
        self.assertIsNone(v)

    def test_probe_bad_regex_does_not_crash(self):
        self.assertEqual(
            er.version_from_probe({"command": ["echo", "1.2.3"],
                                   "version_pattern": "("}, True),
            (None, None))

    def test_probe_pattern_without_group_does_not_crash(self):
        self.assertEqual(
            er.version_from_probe({"command": ["echo", "1.2.3"],
                                   "version_pattern": r"\d+\.\d+\.\d+"}, True),
            (None, None))

    def test_macos_app_plist(self):
        plist = os.path.join(self.tmp, "Info.plist")
        with open(plist, "wb") as fh:
            plistlib.dump({"CFBundleShortVersionString": "1.4.2"}, fh)
        v, ev = er.version_from_plist({"paths": [plist]})
        self.assertEqual(v, "1.4.2")
        self.assertEqual(ev, plist)

    def test_pip_dist_info(self):
        site = os.path.join(self.tmp, "site-packages")
        os.makedirs(os.path.join(site, "litellm-1.61.3.dist-info"))
        v, _ = er.version_from_pip_dist_info(
            {"package": "litellm", "roots": [site]})
        self.assertEqual(v, "1.61.3")

    def test_npm_scoped_package(self):
        root = os.path.join(self.tmp, "node_modules")
        pkg = os.path.join(root, "@anthropic-ai", "claude-code")
        os.makedirs(pkg)
        with open(os.path.join(pkg, "package.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"version": "2.1.0"}, fh)
        v, _ = er.version_from_npm_global(
            {"package": "@anthropic-ai/claude-code", "roots": [root]})
        self.assertEqual(v, "2.1.0")


class TestAssessExitSurfacing(unittest.TestCase):
    """assess.sh must surface the exposure exit code — never a silent green."""

    def setUp(self):
        self.last_out = None
        self._dirs = []

    def tearDown(self):
        for d in self._dirs:
            shutil.rmtree(d, ignore_errors=True)

    def run_assess(self, exposure_args):
        out = tempfile.mkdtemp(prefix="assess-exit-")
        cache = tempfile.mkdtemp(prefix="assess-exit-cache-")
        self._dirs += [out, cache]
        self.last_out = out
        env = dict(os.environ)
        env["AGENT_ASSESSMENT_OUT"] = out
        env["XDG_CACHE_HOME"] = cache
        env["EXPOSURE_REPORT_ARGS"] = exposure_args
        return subprocess.run(
            ["bash", os.path.join(REPO, "scripts", "assess.sh")],
            capture_output=True, text=True, env=env, timeout=180,
            cwd=REPO, check=False)

    def test_degraded_exposure_surfaces_exit_2(self):
        # KEV neither replayed nor cached (isolated cache dir) → skipped → the
        # report still renders, so this is a DEGRADED run, surfaced as rc 2.
        proc = self.run_assess(
            "--offline --osv %s --feed %s --now 2026-07-01"
            % (fx("osv-empty.json"), fx("pulse-fixture.json")))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("DEGRADED", proc.stderr)

    def test_exposure_failure_is_never_a_silent_green(self):
        """THE contract: whatever goes wrong in the exposure step, assess.sh
        must not exit 0 with a green scorecard. All three replay paths are
        unreadable here, so the step degrades or fails outright."""
        proc = self.run_assess(
            "--osv /nonexistent/a.json --kev /nonexistent/b.json "
            "--feed /nonexistent/c.json")
        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(proc.returncode, (2, 3))
        self.assertTrue(
            "DEGRADED" in proc.stderr or "FAILED" in proc.stderr,
            "no warning surfaced; stderr: %s" % proc.stderr)

    def test_probe_binaries_refused_from_environment(self):
        """--probe-binaries executes scanned binaries; it must be a deliberate
        CLI choice, never smuggled in through an env var."""
        proc = self.run_assess(
            "--probe-binaries --watchlist /tmp/evil.json --offline "
            "--osv %s --kev %s --feed %s --now 2026-07-01"
            % (fx("osv-empty.json"), fx("kev-fixture.json"),
               fx("pulse-fixture.json")))
        self.assertIn("refusing '--probe-binaries'", proc.stderr)
        self.assertIn("refusing '--watchlist'", proc.stderr)
        # the run still completes on the real watchlist, without probing
        with open(os.path.join(self.last_out, "exposure-report.json"),
                  encoding="utf-8") as fh:
            self.assertFalse(json.load(fh)["probing"])


class TestLintDriftDetection(unittest.TestCase):
    """lint.sh's drift loop must actually DETECT drift, not just pass."""

    def make_tree(self):
        tmp = tempfile.mkdtemp(prefix="lint-drift-")
        os.makedirs(os.path.join(tmp, "scripts"))
        os.makedirs(os.path.join(tmp, "wiki"))
        os.makedirs(os.path.join(tmp, "templates", "discovery"))
        os.makedirs(os.path.join(tmp, "skill", "agentic-ai-hardening",
                                 "scripts"))
        shutil.copy(os.path.join(REPO, "scripts", "lint.sh"),
                    os.path.join(tmp, "scripts", "lint.sh"))
        with open(os.path.join(tmp, "wiki", "part-1-x.md"), "w",
                  encoding="utf-8") as fh:
            fh.write("# part\n")
        with open(os.path.join(tmp, "index.md"), "w", encoding="utf-8") as fh:
            fh.write("[p1](wiki/part-1-x.md)\n")
        return tmp

    def run_lint(self, tmp):
        return subprocess.run(
            ["bash", os.path.join(tmp, "scripts", "lint.sh")],
            capture_output=True, text=True, timeout=60, check=False)

    def write_pair(self, tmp, canon_content, bundled_content):
        canon = os.path.join(tmp, "templates", "discovery",
                             "inventory-agents.sh")
        bundled = os.path.join(tmp, "skill", "agentic-ai-hardening",
                               "scripts", "inventory-agents.sh")
        if canon_content is not None:
            with open(canon, "w", encoding="utf-8") as fh:
                fh.write(canon_content)
        if bundled_content is not None:
            with open(bundled, "w", encoding="utf-8") as fh:
                fh.write(bundled_content)

    def test_identical_copies_pass(self):
        tmp = self.make_tree()
        try:
            self.write_pair(tmp, "same\n", "same\n")
            proc = self.run_lint(tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertNotIn("DRIFT", proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_drifted_copy_fails(self):
        tmp = self.make_tree()
        try:
            self.write_pair(tmp, "canonical\n", "drifted\n")
            proc = self.run_lint(tmp)
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("DRIFT", proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_bundled_without_canonical_fails(self):
        tmp = self.make_tree()
        try:
            self.write_pair(tmp, None, "orphan bundled copy\n")
            proc = self.run_lint(tmp)
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertIn("no canonical source", proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestInventoryJsonContract(unittest.TestCase):
    """--json adds product/channel on every line; default output is unchanged
    (the SIEM-pipeline regression the header comment promises)."""

    INV = os.path.join(REPO, "templates", "discovery", "inventory-agents.sh")

    def run_inventory(self, *args):
        home = tempfile.mkdtemp(prefix="inv-home-")
        os.makedirs(os.path.join(home, ".claude"))
        env = dict(os.environ)
        env["HOME"] = home
        try:
            proc = subprocess.run(["bash", self.INV, *args],
                                  capture_output=True, text=True, env=env,
                                  timeout=120, check=False)
            return proc.stdout.strip().splitlines()
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def test_json_mode_fields_and_product_mapping(self):
        lines = self.run_inventory("--json")
        self.assertTrue(lines)
        records = [json.loads(l) for l in lines]  # every line must parse
        for rec in records:
            self.assertIn("product", rec)
            self.assertIn("channel", rec)
        baseline = next(r for r in records if r["kind"] == "baseline")
        self.assertEqual(baseline["product"], "claude-code")
        self.assertEqual(baseline["channel"], "config")

    def test_default_output_unchanged_for_siem(self):
        lines = self.run_inventory()
        self.assertTrue(lines)
        for line in lines:
            rec = json.loads(line)
            self.assertNotIn("product", rec)
            self.assertNotIn("channel", rec)


if __name__ == "__main__":
    unittest.main(verbosity=2)
