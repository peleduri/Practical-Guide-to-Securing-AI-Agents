# Repository schema — LLM Wiki

This repository is an **LLM Wiki** (per Andrej Karpathy's pattern): a compounding, cross-referenced set of markdown pages that a human or an LLM can read, extend, and maintain. It is the practical companion to a multi-part security guide on defending agentic AI.

## Layout

- `index.md` — the catalog. Every page gets one link and a one-line summary, grouped by category. Update it whenever a page is added, renamed, or removed.
- `log.md` — append-only history. One entry per change: `## [YYYY-MM-DD] <operation> | <title>`.
- `wiki/` — the pages. Each page is a self-contained markdown file with YAML frontmatter (`title`, `summary`, `part`, `updated`).
- `README.md` — the human entry point.
- `start-here.md` — the on-ramp: reader tracks (security engineer / platform-DevEx / CISO), the first five controls in order, and a crawl/walk/run maturity model.
- `glossary.md` — one-line definitions of the terms used across the parts, each pointing to the part that defines it. Definitions live here; `index.md`'s "Key concepts" is only a compact concept→part pointer.
- `scripts/lint.sh` — the wiki's test suite: fails on a broken relative link or an orphan part. CI runs it on every PR via `.github/workflows/lint.yml`.
- `templates/` — copy-ready controls (config baselines, the PreToolUse hook, Sigma+SPL detections, identity/workflow examples), each mapped to its part. Examples to adapt, not drop-in.
- `skill/` — the guide packaged as a portable Agent Skill (`skill/agentic-ai-hardening/SKILL.md`) that runs on Claude Code / Codex CLI / Cursor: discover → assess → report → opt-in harden. **Executed-script policy:** everything the skill *executes* is bundled inside it as a verbatim copy of a canonical `templates/` original, and `scripts/lint.sh` + CI enforce the copies stay byte-identical — so the skill never fetches-and-runs remote code. The bundled set: `inventory-agents.sh` (discovery), `exposure-report.py` (advisory matching), `agentic-watchlist.json` (data whose probe commands can run under `--probe-binaries`, so it is policed like code), and `scorecard.sh` (rendering; canonical at `templates/assessment/`). The *controls* the skill writes are fetched from their canonical raw URLs, preview-then-write. Front-door prerequisites, stated honestly: `jq` (hard-required by `assess.sh` and `scorecard.sh`) and `python3` (exposure matching; skipped with a loud note when absent). When a control or the maturity model changes, keep the skill's Control Catalog and checklist in sync.

## Conventions

- **Links:** pages cross-reference with GitHub-native relative markdown links, e.g. `[Part 2](part-2-endpoint-hardening-and-policy-playbook.md)`. This is the GitHub-friendly form of Karpathy's `[[wikilink]]` — it renders for humans on GitHub and parses cleanly for LLMs.
- **Frontmatter:** every page starts with `title`, `summary`, `part` (when applicable), and `updated` (ISO date).
- **Vendor names** appear as concrete examples, not endorsements. Product controls change fast — verify against the linked vendor docs before relying on a specific setting.
- **Sources** are cited inline as plain URLs at the foot of a page.

## Workflows

- **Ingest** (add a source or finding): read the source, write or update the relevant page in `wiki/`, add or refresh its line in `index.md`, and append a `log.md` entry.
- **Query:** search the pages, answer with citations to page + section. A good synthesized answer can be filed back as a new page.
- **Lint:** run `scripts/lint.sh` (CI runs it on every PR) to catch orphans (a page not listed in `index.md`) and broken relative links; still review by hand for contradictions across pages and stale claims (a control the vendor has since changed).

## Scope note

Vendor and product specifics (Claude Code, Claude Cowork, Codex, Cursor, Coder, GPU-first neoclouds, sandbox-native providers) are named as concrete examples. Nothing here is organization-specific; it is a general playbook.

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore
- Author a backlog-ready spec/issue → invoke /spec
