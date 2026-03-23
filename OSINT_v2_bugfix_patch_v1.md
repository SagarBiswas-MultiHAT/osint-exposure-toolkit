# OSINT Exposure Toolkit v2 — Bug Fix Patch for VS Code Copilot
# Patch v24: Full HTML Template + Data Model + Reporting Fixes

═══════════════════════════════════════════════════════════
HOW TO USE THIS PROMPT
═══════════════════════════════════════════════════════════

This is a BUG FIX patch. It does NOT add features.
Apply ONLY the fixes described. Do NOT rebuild from scratch.
Implement in the exact order of the IMPLEMENTATION ORDER section.
Commit after each step before proceeding to the next.

Two real runs were analyzed to produce this list. Every bug is
confirmed from actual output — not theoretical. Fix exactly what
is described, nothing more.

═══════════════════════════════════════════════════════════
CONFIRMED BUG CATALOG
═══════════════════════════════════════════════════════════

Read this section fully before touching any file.

─────────────────────────────────────────────────────────────
BUG 1 [CRITICAL] — HTML REPORT: 8 SECTIONS COMPLETELY EMPTY
─────────────────────────────────────────────────────────────

File: reporting/templates/report.html.jinja

The Jinja2 template renders ONLY the credential-leaks section
and shodan-recon section with actual content. Every other section
is an empty shell with only a heading:

  <section id="github-exposure" class="card"><h2>GitHub Exposure</h2></section>
  <section id="email-intelligence" class="card"><h2>Email Intelligence</h2></section>
  <section id="social-footprint" class="card"><h2>Social Footprint</h2></section>
  <section id="paste-site-exposure" class="card"><h2>Paste Site Exposure</h2></section>
  <section id="js-file-secrets" class="card"><h2>JS File Secrets</h2></section>
  <section id="email-authentication" class="card"><h2>Email Authentication</h2></section>
  <section id="document-metadata" class="card"><h2>Document Metadata</h2></section>
  <section id="google-dork-recipe" class="card"><h2>Google Dork Recipe</h2></section>

All 8 of these sections must be fully implemented. The context
variables available from html_report.py are:
  github, email_intel, social, pastes, js_secrets, dns_auth,
  metadata, dorks (list of DorkResult objects), findings

Implement each section exactly as follows:

── GITHUB EXPOSURE ──────────────────────────────────────────

{% if github.skipped %}
  <p class="badge yellow">GitHub scan skipped — {{ github.skip_reason }}</p>
{% else %}
  Show two sub-sections:

  A) Repositories table:
     Columns: Repository | Language | Stars | Last Pushed | Active (≤30d) | Risk
     "Active" = YES (red) if pushed within 30 days, else NO (muted).
     If total_repos = 0: show muted text "No repositories found."

  B) Secrets table (only if secret_count > 0):
     Show a RED alert banner ABOVE the table:
       "⚠️ CRITICAL: Secret material detected in public repositories."
     Columns: Repository | File Path | Secret Type | Masked Value | Severity
     Each Severity cell: color-coded badge (red/orange/yellow by severity).
     If secret_count = 0: show green badge "No secrets detected in scanned repositories."

  Summary line above the tables:
    "Found {{ github.total_repos }} repositories
     ({{ github.active_repos_30d }} active in last 30 days).
     Secrets detected: {{ github.secret_count }}"
{% endif %}

── EMAIL INTELLIGENCE ───────────────────────────────────────

{% if email_intel.skipped %}
  <p class="badge yellow">{{ email_intel.skip_reason }}</p>
{% else %}
  Show a 2-column definition table (label | value):
    Email Address:    {{ email_intel.email }}
    Domain:           {{ email_intel.domain }}
    Format Valid:     green "✓ Valid" if true, red "✗ Invalid" if false
    Mail Provider:    {{ email_intel.mail_provider }}
    Is Disposable:    red "⚠ Yes — Throwaway address" if true, green "No" if false
    MX Records:       comma-joined list (or "None found" in red if empty)
    SMTP Verified:    green "VERIFIED" / yellow "UNKNOWN" / red "UNVERIFIED" badge
                      + an info icon (ℹ) with tooltip text:
                        "SMTP VRFY is disabled by most mail servers. UNKNOWN is
                         the expected result and does not indicate an error in
                         this tool."
    SPF Present:      green "✓ Present" if true, yellow "✗ Missing" if false

  If email_intel.risk_notes is non-empty:
    Show each note as a bullet point in a yellow info card below the table.
{% endif %}

── SOCIAL FOOTPRINT ─────────────────────────────────────────

{% if social.skipped %}
  <p class="badge yellow">{{ social.skip_reason }}</p>
{% else %}
  Show username variants tried:
    "Username variants checked: {{ social.username_variants | join(', ') }}"

  Platform badge grid (one badge per platform, 4 columns):
    EXPOSED     → green badge
    NOT_FOUND   → muted/gray badge
    UNKNOWN     → yellow badge
    Each badge shows the platform name and links to the URL.

  Positive signal platforms (HackerOne, Bugcrowd) when EXPOSED:
    Show in a separate "Positive Signals" sub-section below the grid
    with a cyan badge labeled "Security Researcher — positive signal."
    These are NOT counted in the risk exposure count.

  Summary line:
    "{{ social.total_exposure_count }} platform(s) exposed
     ({{ social.positive_signal_count }} positive security signals excluded)"
{% endif %}

── PASTE SITE EXPOSURE ──────────────────────────────────────

If paste_monitor.mode == "leakcheck":
  Show blue info card:
    "ℹ️ Paste lookup is not available in LeakCheck mode.
     Re-run with --use-hibp and Premium mode for paste site results."

Elif paste_monitor.mode == "free":
  Show muted text:
    "Paste lookup requires Premium HIBP mode. Re-run with --use-hibp
     for per-email paste site results."

Elif paste_monitor.total_pastes > 0:
  Show RED alert banner: "⚠️ Email found in {{ pastes.total_pastes }} public paste(s)."
  Table columns: Source | ID | Title | Date | Email Count

Else:
  Show green badge: "No paste site exposure detected."

── JS FILE SECRETS ──────────────────────────────────────────

{% if js_secrets.skipped %}
  <p class="badge yellow">{{ js_secrets.skip_reason }}</p>
{% else %}
  Summary line: "Scanned {{ js_secrets.js_files_scanned }} JS file(s)."

  If secrets_found is non-empty:
    RED alert banner: "⚠️ Secret material detected in public JS files."
    Table: File URL | Secret Type | Masked Value | Severity
    (Severity color-coded badge)
  Else:
    Green badge: "No secrets detected in scanned JS files."

  If internal_endpoints_found is non-empty:
    Yellow card: "Internal endpoints exposed: {{ list joined by ', ' }}"

  If environment_hints is non-empty:
    Yellow card: "Environment hints detected: {{ list joined by ', ' }}"
{% endif %}

── EMAIL AUTHENTICATION ─────────────────────────────────────

{% if dns_auth.skipped %}
  Show yellow info card:
    "DNS Email Authentication scan requires a domain target.
     Re-run with --domain flag to see SPF, DMARC, DKIM, and
     MTA-STS analysis."
  Do NOT show any SPF/DMARC/DKIM values. Do NOT show spoofability score.
{% else %}
  Show a status table (4 rows):
    Record   | Status        | Detail
    SPF      | badge         | policy strength (STRICT/SOFT/OPEN/MISSING)
    DMARC    | badge         | policy (reject/quarantine/none/MISSING) + rua
    DKIM     | badge         | "{{ N }} selector(s) found" or "No selectors found"
    MTA-STS  | badge         | mode (enforce/testing/none/MISSING)

  Badge color rules:
    SPF STRICT / DMARC reject / DKIM found / MTA-STS enforce → green
    SPF SOFT / DMARC quarantine / DMARC none → yellow
    SPF missing / DMARC missing / DKIM missing → red

  Spoofability score badge (shown prominently below the table):
    0–3  → green badge:  "LOW SPOOFING RISK ({{ score }}/10)"
    4–6  → yellow badge: "MEDIUM SPOOFING RISK ({{ score }}/10)"
    7–10 → red badge:    "HIGH SPOOFING RISK ({{ score }}/10)"
{% endif %}

── DOCUMENT METADATA ────────────────────────────────────────

{% if metadata.skipped %}
  <p class="badge yellow">{{ metadata.skip_reason }}</p>
{% else %}
  Summary line:
    "Found {{ metadata.documents_found }} document(s),
     scanned {{ metadata.documents_scanned }}."

  If findings is non-empty:
    Table: Document URL | File Type | Author | Software | Risk Notes | Severity
    (Severity color-coded badge)
    If any unique_authors: yellow card "Authors exposed: {{ list }}"
    If any internal_software: yellow card "Internal software exposed: {{ list }}"
  Else:
    Green badge: "No metadata leaks detected in scanned documents."
{% endif %}

── GOOGLE DORK RECIPE ───────────────────────────────────────

{% if google_dorks.skipped %}
  <p class="badge yellow">{{ google_dorks.skip_reason }}</p>
{% else %}
  For each result in dorks:
    A collapsible <details> block with <summary> = "{{ result.category }}"

    Inside the block:
      - Code block (dark background) showing each query on its own line
      - DDG result badge:
          RESULTS_FOUND → red badge "Live hits detected on DuckDuckGo"
          NO_RESULTS    → green badge "No results on DuckDuckGo"
          NOT_CHECKED   → muted badge "Not checked (rate limited or skipped)"
      - A muted instruction line:
          "Paste this query into Google to manually verify."

  Note below all dork sections (muted, italic):
    "These are passive reconnaissance queries only. Results are
     informational. Always obtain authorization before investigating
     any target."
{% endif %}

─────────────────────────────────────────────────────────────
BUG 2 [CRITICAL] — HTML SIDEBAR: ITEM 12 MISSING, WRONG NUMBERING
─────────────────────────────────────────────────────────────

File: reporting/templates/report.html.jinja

Current sidebar jumps: ...11. Shodan Recon → 13. Risk Summary → 14. Appendix
Item 12 is completely absent from the sidebar.

Fix the sidebar to exactly these 14 items in this order:

  1.  Executive Summary
  2.  Credential Leaks
  3.  GitHub Exposure
  4.  Email Intelligence
  5.  Social Footprint
  6.  Paste Site Exposure
  7.  JS File Secrets
  8.  Email Authentication
  9.  Document Metadata
  10. Google Dork Recipe
  11. Shodan Recon
  12. Risk Summary & Recommendations     ← ADD THIS (was incorrectly numbered 13)
  13. Appendix                           ← renumber from 14 to 13

Also fix the section id anchors in the main body to match:
  id="risk-summary"  → href="#risk-summary" (item 12)
  id="appendix"      → href="#appendix" (item 13)

─────────────────────────────────────────────────────────────
BUG 3 [CRITICAL] — EXECUTIVE SUMMARY: MISSING GAUGE + SEVERITY BARS
─────────────────────────────────────────────────────────────

File: reporting/templates/report.html.jinja

The executive summary section is missing two required visual elements.
Currently it only shows plain text "Exposure Score: N/100 — LABEL" and
a simple 5-card stat grid. Add the following ABOVE the stat grid:

A) Animated exposure gauge (220px conic-gradient circle):
   CSS: Use a conic-gradient with the exposure score percentage.
   The gauge color transitions:
     0–30   → var(--pass) green
     31–50  → var(--medium) orange
     51–70  → var(--high) red
     71–100 → var(--critical) deep red

   HTML structure:
     <div class="gauge-wrap">
       <div class="gauge" style="
         background: conic-gradient(
           {{ gauge_color }} {{ score }}%,
           var(--border) {{ score }}%
         );
       "></div>
       <div class="gauge-label">
         <span class="score-number">{{ score }}</span>
         <span class="score-denom">/100</span>
         <span class="score-label">{{ score_label }}</span>
       </div>
     </div>

   CSS to add to <style>:
     .gauge-wrap {
       display: flex;
       justify-content: center;
       margin: 24px 0;
     }
     .gauge {
       width: 220px;
       height: 220px;
       border-radius: 50%;
       display: flex;
       align-items: center;
       justify-content: center;
       position: relative;
     }
     .gauge-label {
       position: absolute;
       text-align: center;
       display: flex;
       flex-direction: column;
     }
     .score-number {
       font-size: 48px;
       font-weight: 700;
       color: var(--text);
     }
     .score-denom { font-size: 18px; color: var(--muted); }
     .score-label { font-size: 13px; color: var(--muted); margin-top: 4px; }

   Compute gauge_color in html_report.py before passing to template:
     if score <= 30:   gauge_color = "#2ecc71"  (green)
     elif score <= 50: gauge_color = "#f39c12"  (orange)
     elif score <= 70: gauge_color = "#ff4d4f"  (red)
     else:             gauge_color = "#ff0000"  (critical)
   Pass as: context["gauge_color"] = gauge_color

B) Severity breakdown bars (BELOW the stat grid):
   Use pure CSS. Compute counts in html_report.py and pass as
   context["severity_counts"] = {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N, "INFO": N}
   by counting the `risk` field across all items in the findings list.

   HTML structure for each severity level:
     <div class="sev-row">
       <span class="sev-label">CRITICAL</span>
       <div class="sev-bar-wrap">
         <div class="sev-bar" style="width: {{ pct }}%; background: var(--critical);"></div>
       </div>
       <span class="sev-count">{{ N }}</span>
     </div>

   Width percentage = (count / max(total_findings, 1)) * 100

   CSS to add:
     .sev-row {
       display: flex;
       align-items: center;
       gap: 12px;
       margin: 6px 0;
     }
     .sev-label { width: 80px; font-size: 13px; color: var(--muted); }
     .sev-bar-wrap {
       flex: 1;
       height: 10px;
       background: var(--border);
       border-radius: 5px;
       overflow: hidden;
     }
     .sev-bar { height: 100%; border-radius: 5px; transition: width 0.4s ease; }
     .sev-count { width: 30px; font-size: 13px; text-align: right; }

   Severity → bar color:
     CRITICAL → var(--critical)
     HIGH     → var(--high)
     MEDIUM   → var(--medium)
     LOW      → var(--low)
     INFO     → var(--muted)

─────────────────────────────────────────────────────────────
BUG 4 [HIGH] — EXECUTIVE SUMMARY: WRONG STAT CARD VALUES
─────────────────────────────────────────────────────────────

File: reporting/templates/report.html.jinja

Current executive summary stat cards have two problems:

A) "Credential Breaches" card shows `total_breaches` (HIBP count),
   which is 0 when engine=leakcheck even if leakcheck_found > 0.
   
   Fix: Show the correct count based on engine:
     If engine == "leakcheck":  show leakcheck_found
     If engine == "hibp":       show total_breaches
   
   Change card label to: "Credential Leaks" (engine-neutral term).
   Card value: {{ credential_leak.leakcheck_found if
                  credential_leak.engine == 'leakcheck'
                  else credential_leak.total_breaches }}

B) "Email Spoofability" card shows "0/10" when dns_auth.skipped = True.
   A score of 0 looks like perfect security, but it just means the
   module was skipped (no domain provided).
   
   Fix:
     If dns_auth.skipped: show "—" (em dash)
     Else: show "{{ dns_auth.spoofability_score }}/10"

C) "Shodan Open Ports" card:
   Current: shows 0 when skipped (looks like "zero open ports found")
   Fix: if shodan.skipped → show "—"; else show total_open_ports

─────────────────────────────────────────────────────────────
BUG 5 [HIGH] — CREDENTIAL_LEAK MODEL: DIRTY HIBP FIELDS WHEN ENGINE=LEAKCHECK
─────────────────────────────────────────────────────────────

File: modules/credential_leak.py + core/models.py

When engine = "leakcheck", the JSON output currently contains:
  "mode": "free"        ← WRONG: this is an HIBP field
  "hibp_source": "api"  ← WRONG: HIBP API was never called

These HIBP fields bleed through because the model defaults are
set to HIBP values rather than null.

Fix in core/models.py — CredentialLeakResult:
  Change the `mode` field default:
    mode: Optional[str] = None   (was: "free" or similar HIBP default)
  Change the `hibp_source` field default:
    hibp_source: Optional[str] = None   (was: "api")

Fix in modules/credential_leak.py — _run_leakcheck():
  When building the CredentialLeakResult for a LeakCheck run,
  explicitly set:
    mode = None
    hibp_source = None
    demo_mode = False
    total_breaches = 0
    total_pastes = 0
    breaches = []
    pastes = []

Do NOT change the HIBP code paths — only nullify these fields
when the LeakCheck branch returns its result.

─────────────────────────────────────────────────────────────
BUG 6 [HIGH] — GITHUB FOOTPRINT: WRONG SKIP REASON
─────────────────────────────────────────────────────────────

File: modules/github_footprint.py

Current skip_reason: "GitHub scan skipped — invalid query target."
This is factually wrong. The module is skipping because no API key
is configured, not because the target is invalid.

Fix: When api_keys.github is empty or None, return:
  skip_reason = "GitHub scan skipped — no API key configured. Add a free PAT to config.yaml."
  (This is exactly the message specified in the original v22 prompt.)

The "invalid query target" message should ONLY appear if a key IS
present but the target (email/domain) cannot be used to form a valid
GitHub search query (which is a separate failure mode).

─────────────────────────────────────────────────────────────
BUG 7 [HIGH] — MD REPORT: CREDENTIAL LEAKS TABLE ALWAYS SHOWS "—"
─────────────────────────────────────────────────────────────

File: reporting/markdown_report.py

When engine=leakcheck and leakcheck_found > 0, the MD report shows
an empty table with "— | — | — | — | —" instead of the actual
breach source names. Confirmed: run with user@example.com had 1000
LeakCheck sources but zero visible in the MD table.

Fix: In markdown_report.py, the credential leaks section must branch
on the engine:

  If engine == "leakcheck":
    Table header:
      | Source | Date | Password Type | Fields | Severity |
    Table rows:
      For each source in credential_leak.leakcheck_sources:
        | {{ source.name }} | {{ source.date or "—" }} |
          {{ source.passwordtype or "unknown" }} |
          {{ source.fields | join(', ') or "—" }} |
          {{ source.severity }} |
    If leakcheck_found == 0: write "No breach sources found." instead of the table.

  If engine == "hibp" and mode in ("live", "demo"):
    Existing HIBP breach table (keep as-is — don't change HIBP path)

  If engine == "hibp" and mode == "free":
    Existing "No individual check in Free mode" note (keep as-is)

─────────────────────────────────────────────────────────────
BUG 8 [MEDIUM] — MD REPORT: HEADER SHOWS "MODE: FREE" WHEN LEAKCHECK USED
─────────────────────────────────────────────────────────────

File: reporting/markdown_report.py

The report header currently includes:
  **Mode:** Free

This is the HIBP mode, not the credential engine. When LeakCheck
is used, this field is meaningless and actively wrong.

Fix: Replace the "Mode:" line with "Credential Engine:":
  If engine == "leakcheck":
    **Credential Engine:** LeakCheck ({{ credential_leak.leakcheck_mode | title }})
    e.g.: "LeakCheck (Public)" or "LeakCheck (Authenticated)"

  If engine == "hibp":
    **Credential Engine:** HIBP ({{ credential_leak.mode | title }})
    e.g.: "HIBP (Free)", "HIBP (Demo)", "HIBP (Live)"

─────────────────────────────────────────────────────────────
BUG 9 [MEDIUM] — MD REPORT: DNS AUTH SHOWS RAW FALSE/0 VALUES WHEN SKIPPED
─────────────────────────────────────────────────────────────

File: reporting/markdown_report.py

When dns_email_auth.skipped = True, the MD report currently shows:
  - **SPF Present:** False
  - **DMARC Present:** False
  - **DKIM Selectors:** 0
  - **MTA-STS:** False
  - **Spoofability:** 0 / 10

All these False/0 values are Pydantic defaults for the skipped module.
Showing them makes the domain look "clean" when actually the scan
simply didn't run. This is misleading.

Fix: In markdown_report.py, the Email Authentication section:
  If dns_auth.skipped:
    Write: "> Skipped — {{ dns_auth.skip_reason }}"
    Do NOT write any SPF/DMARC/DKIM/spoofability values.
  Else:
    Write the existing field values (they are real data).

─────────────────────────────────────────────────────────────
BUG 10 [MEDIUM] — MD REPORT: "SHODAN OPEN PORTS: 0" WHEN SKIPPED
─────────────────────────────────────────────────────────────

File: reporting/markdown_report.py

In the Executive Summary section:
  Current: - **Shodan Open Ports:** 0
  When shodan.skipped = True, this is a false "zero ports" reading.

Fix:
  If shodan.skipped:
    - **Shodan Open Ports:** N/A (no domain provided)
  Else:
    - **Shodan Open Ports:** {{ shodan.total_open_ports }}

─────────────────────────────────────────────────────────────
BUG 11 [MEDIUM] — HTML CREDENTIAL TABLE: NO PAGINATION FOR LARGE RESULTS
─────────────────────────────────────────────────────────────

File: reporting/templates/report.html.jinja

When LeakCheck returns many sources (confirmed: 1000 rows for
user@example.com), the full table is rendered inline causing a
massive HTML file and very poor render performance.

Fix: Add client-side pagination to the LeakCheck sources table.
Cap display at 50 rows per page with Prev/Next controls, identical
to the HIBP Free mode breach database table (which already has this).

Implementation (vanilla JS only — no libraries):
  - Render the full leakcheck_sources array into a JS variable
    (same pattern as breachRows for HIBP): leakcheckRows = [...]
  - Add search input filtering on the Source name column
  - 50 rows per page
  - Prev/Next buttons + "Showing X–Y of N sources"
  - Do this only when engine=leakcheck AND leakcheck_found > 0

Also add a note above the table when in public mode:
  "Note: In Public mode, only breach source names are available.
   Upgrade to Authenticated mode for field-level detail."

─────────────────────────────────────────────────────────────
BUG 12 [LOW] — HTML REPORT: MISSING GOOGLE FONTS IMPORT
─────────────────────────────────────────────────────────────

File: reporting/templates/report.html.jinja

The spec requires Inter (body) + JetBrains Mono (code/values) via
Google Fonts CDN. Neither font is imported in the current <head>.

Fix: Add to the <head> section, before the <style> tag:
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">

Add to CSS:
  body { font-family: 'Inter', system-ui, -apple-system, sans-serif; }
  code, .mono, table td.value { font-family: 'JetBrains Mono', monospace; }

Apply JetBrains Mono to: masked secret values, dork query blocks,
CVE IDs, IP addresses, port numbers, hash values.

─────────────────────────────────────────────────────────────
BUG 13 [LOW] — HTML REPORT: DEAD HIBP JS CODE RUNS ON LEAKCHECK RUNS
─────────────────────────────────────────────────────────────

File: reporting/templates/report.html.jinja

The <script> block always contains the HIBP breach table JS
(breachRows, renderTable, filteredRows) regardless of engine.
When engine=leakcheck, there is no #breachTable element in the DOM.
The `if (document.getElementById("breachTable"))` guard prevents a
crash, but the dead JS code is wasted bytes.

Fix: Wrap the HIBP breach table JS in a Jinja conditional:
  {% if credential_leak.engine == 'hibp' and credential_leak.mode == 'free' %}
    // ... HIBP breach table JS (breachRows, renderTable, etc.)
  {% endif %}

  And wrap the LeakCheck pagination JS in:
  {% if credential_leak.engine == 'leakcheck' and credential_leak.leakcheck_found > 0 %}
    // ... LeakCheck sources pagination JS
  {% endif %}

═══════════════════════════════════════════════════════════
WHAT IS WORKING CORRECTLY — DO NOT TOUCH
═══════════════════════════════════════════════════════════

These are confirmed working from the actual run outputs.
Do NOT modify any of these:

✓ CLI engine selection prompt (LeakCheck default / HIBP opt-in)
✓ LeakCheck Public API fetch + source parsing
✓ Score formula: min(sources * 5, 20) → correctly applied
✓ LinkedIn HTTP 999 handling → INFO log, status=UNKNOWN, no crash
✓ DuckDuckGo rate limit blocking → WARNING log, continues
✓ Social footprint platform badge detection
✓ Email intel: MX lookup, SMTP VRFY, provider detection, SPF check
✓ Module skipping: missing API key → skipped=True, score=0, no crash
✓ JSON report: structure and Pydantic serialization (except Bug 5)
✓ Exposure graph generation (both runs produced valid HTML graphs)
✓ Shodan: correctly skips when no domain, returns typed model
✓ Paste monitor: correctly handles engine=leakcheck case
✓ All 10 module results fed to scorer → final score computed correctly
✓ Rich CLI summary table + final score panel + elapsed time
✓ Output directory creation with timestamp
✓ Concurrent module execution (Batch 2 + Batch 3)
✓ Rate limiters (LinkedIn, DuckDuckGo, LeakCheck all behaving)
✓ asyncio.Semaphore(max_concurrent_requests) shared correctly

═══════════════════════════════════════════════════════════
IMPLEMENTATION ORDER
═══════════════════════════════════════════════════════════

Implement in this exact order. Commit after each step.

STEP 1 — core/models.py
  Fix CredentialLeakResult field defaults:
    mode: Optional[str] = None
    hibp_source: Optional[str] = None
  (Bug 5)

STEP 2 — modules/credential_leak.py
  In _run_leakcheck(), explicitly set mode=None, hibp_source=None
  when building the returned CredentialLeakResult.
  (Bug 5)

STEP 3 — modules/github_footprint.py
  Fix the skip_reason when api_keys.github is empty.
  (Bug 6)

STEP 4 — reporting/html_report.py
  Add gauge_color computation and pass to template context.
  Add severity_counts computation and pass to template context.
  Update the credential_leak value in context to handle
  engine-based stat card logic.
  (Bugs 3, 4)

STEP 5 — reporting/markdown_report.py
  Fix all MD report issues in one edit:
    a) Credential leaks table — branch on engine (Bug 7)
    b) Header "Mode:" → "Credential Engine:" (Bug 8)
    c) DNS Email Auth skipped → write blockquote, not raw values (Bug 9)
    d) Shodan Open Ports → "N/A" when skipped (Bug 10)
  (Bugs 7, 8, 9, 10)

STEP 6 — reporting/templates/report.html.jinja
  This is the largest step. Edit the template to fix all HTML issues:
    a) Add Google Fonts <link> tags to <head> (Bug 12)
    b) Add gauge CSS + severity bar CSS to <style> (Bug 3)
    c) Fix sidebar: add item 12, renumber 13 to Appendix (Bug 2)
    d) Executive Summary: add gauge HTML + severity bars (Bug 3)
    e) Executive Summary: fix stat card values for engine/skipped (Bug 4)
    f) Implement GitHub Exposure section (Bug 1)
    g) Implement Email Intelligence section (Bug 1)
    h) Implement Social Footprint section (Bug 1)
    i) Implement Paste Site Exposure section (Bug 1)
    j) Implement JS File Secrets section (Bug 1)
    k) Implement Email Authentication section (Bug 1)
    l) Implement Document Metadata section (Bug 1)
    m) Implement Google Dork Recipe section (Bug 1)
    n) Add LeakCheck pagination JS + wrap existing HIBP JS in conditional (Bugs 11, 13)

STEP 7 — Validation
  Run: ruff check .   → must pass with 0 errors
  Run: python -m pytest tests/ -v   → must pass all tests

  Smoke test A (email only):
    python main.py --email test@example.com
    → All 14 sidebar links must point to populated sections.
    → Executive Summary gauge must render visually.
    → Credential Leaks section must show engine badge.
    → Email Authentication section must show skip blockquote (no 0/10 value).
    → DNS section must NOT show False/0 values.

  Smoke test B (with domain):
    python main.py --email test@example.com --domain example.com
    → Email Authentication section must show SPF/DMARC/DKIM table.
    → Spoofability score badge must be visible.
    → Shodan section must show skip (no Shodan key) or results.
    → All 14 sections have content (not empty shells).

  Visual check of HTML report in browser:
    → Animated gauge visible in Executive Summary.
    → Severity breakdown bars visible.
    → All 14 sidebar links scroll to their sections correctly.
    → LeakCheck table shows source names (not all "—").
    → GitHub section renders skip message (no key) or results.
    → Fonts are Inter/JetBrains Mono (not system fallback).

═══════════════════════════════════════════════════════════
COPILOT BEHAVIORAL RULES FOR THIS PATCH
═══════════════════════════════════════════════════════════

RULE A: Touch ONLY the files listed in the bug fixes and
  implementation order above. Do not refactor any module
  that is not in this list.

RULE B: The Jinja2 template (report.html.jinja) is the biggest
  change. Edit it section by section in the order listed in Step 6.
  Do not rewrite the entire template — add/replace only the empty
  section blocks and the missing CSS/JS.

RULE C: When implementing the social footprint badge grid in the
  Jinja template, use the profiles list from the social context
  variable. Each profile has: platform, url, status, is_positive_signal.
  Do not try to re-derive these from the email address.

RULE D: The HIBP Free mode breach database table (with search,
  multi-filter, pagination) already works in the JS <script> block.
  Do NOT remove or modify that code. Only wrap it in the
  {% if engine == 'hibp' and mode == 'free' %} conditional (Bug 13).

RULE E: All JS in the template must remain vanilla JS.
  No jQuery. No Chart.js. No external JS libraries.
  CSS uses only CSS variables already defined in the <style> block.

RULE F: After completing the template, open it in a browser locally
  with a representative JSON file before considering the step done.
  If any section still shows an empty card, fix it before committing.

═══════════════════════════════════════════════════════════
END OF BUG FIX PATCH v24
═══════════════════════════════════════════════════════════
