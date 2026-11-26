# Changelog & Iteration Roadmap

## [1.1.3] - 2026-11-18 (Full Red-Team Adversarial Audit Remediation: 5 P0, 7 P1, 4 P2 Closed)

### Fixed
- **P0-01 Secret Redaction Order & Expanded Patterns**: Executed multi-line `PEM/PGP PRIVATE KEY`, `EXPLICIT_SECRET_PATTERNS` (`AIza*`, `hf_*`, `glpat-*`, `npm_*`, `pypi-*`, Slack tokens/webhooks, `redis://:pass@host` URL credentials, `?key=/signature=` query secrets, `Bearer/Basic` headers), and `LABELED_SECRET_RE` (including JSON-quoted keys) **before** stashing benign hex/UUID/URL spans, closing leaks of labeled hex/UUID secrets and URL-embedded keys across `SEC-01`, `FixRecord`, and `--diff`.
- **P0-02 Zero False-Positive Technical Identifiers**: Added CamelCase vowel-word coverage (`>= 0.55`), Shannon entropy + digit-run checks, DOI shielding prior to vendor/unknown token checks, and path/snake_case exclusions so scientific/engineering identifiers (`SuperconductingQubitControllerV2026`, `Tip4pIceNucleation230K2000ns`, `unit_test_coverage_report`, `10.1145/ab_test_methodology_2025`, `pwd = /opt/envoy/conf`) pass cleanly.
- **P0-03 Currency `$` vs. Inline LaTeX Math Disambiguation**: Neutralized currency tokens (`$2.8M`, `（$4.5M）`) prior to single-`$` inline math scanning and banned CJK sentence punctuation inside single-`$` spans so dual currency amounts on the same line never swallow intervening prose.
- **P0-04 Pre-Replace Verification, Convergent Fix & Zero-Width Secret Scan**: Normalized zero-width characters in secret pre-scanning, ran `FMT-04` residue stripping before convergent `FMT-03` citation splitting (`[1][cite_start][2]` -> `[1]、[2]` in one pass), and verified temp-file readback + re-lint **before** `os.replace` so `--in-place` originals are never touched on error.
- **P0-05 List-Nested Code Fences, Blockquotes & Indented Code Blocks**: Protected list-nested code fences (`>3` leading spaces), list-nested `>` blockquotes, and 4-space/tab indented code blocks (`tensor[1][2]` untouched).
- **P1-01..P1-07 Parser, Permission, Path, Anchor, Q4 & List Fixes**: Pre-validated YAML frontmatter (sparing leading `---` HRs), shielded CommonMark multi-backtick inline code inside HTML depth tracking with blank-line heading circuit breakers, preserved `0644` file modes while rejecting `0444` read-only targets and directory/dangling-symlink traps, masked space-containing paths/bare home dirs/`~/.ssh`/`/private/var/folders`, supported Chinese and URL-encoded `#锚点`, unwrapped inline LaTeX math for Q4 with English sentence splitting and anti-swallow bounds, fixed consecutive sibling list indents, and unified Pass-1/Pass-2 anchors and `--json` error payloads.
- **P2-01..P2-04 Prompt Audit & Package Unification**: Upgraded `prompt_negativity_audit.py` with nested fence stacks, CommonMark inline code, English sentence splitting, and `--include-markdown-fences` (`markdown/prompt/text`), defined the 5-column `Semantic Change Trace` schema, scoped `SEM-01` to opening summary tables, excluded headings/URLs from body word counts, and unified all package version tags to `v1.1.3` (36 automated tests and 20 golden cases passing).

## [1.1.2] - 2026-11-18 (Targeted P1 Semantic/Redaction/Lifecycle Fixes)

### Fixed
- Introduced local-span `Q4` extraction (`analyze_q4_spans`), unified `redact_sensitive_text` across `SEC-01`/`FixRecord`/`--diff`, separated `Preflight Passed` (`--check`) from `Deterministic Checks Passed` (`--fix`), restored `## When to Use`, and clarified Long-Document Agent Protocol (`CASE-19` & `CASE-20`).

## [1.1.1] - 2026-11-18 (Targeted Audit Hardening)

### Fixed
- Added `--overwrite` & symlink/hardlink guards, initial tri-state Q4, variable-length code fences, multi-line/quoted-attribute HTML protection, and `SEM-04/05` non-destructive path warnings (`CASE-11` to `CASE-18`).

## [1.1.0] - 2026-11-18 (Core Semantic Safeguards & Two-Level Routing)

### Added
- 5-Layer Fact Ledger, Q3-A/B/C split, Document + Section Two-Level Routing, `light / standard / deep` intensities, `Voice Card` binding, and separated surface vs. LLM prompt audit.

## [1.0.1] - 2026-11-18 (Security & File Protection)

### Fixed
- `SEC-01` snippet redaction, `--in-place` input file protection, `--diff` output, and atomic write + disk readback re-verification.

## [1.2.0] - Planned (Live Multi-Model Empirical Benchmark - Not Yet Executed)

- Expand golden suite to 30-50 cases and run live multi-model evaluations (Claude, GPT, Gemini) measuring fact retention, semantic drift, over-editing rate, and human review cost.
