# OSINT Exposure Toolkit v2 — Change Prompt for VS Code Copilot
# Patch v23: LeakCheck as Default + Shodan Module

═══════════════════════════════════════════════════════════
HOW TO USE THIS PROMPT
═══════════════════════════════════════════════════════════

This is a PATCH prompt. Do NOT rebuild the project from scratch.
Apply only the changes described below to the existing codebase
built from the v22 prompt.

Paste this entire prompt into Copilot Chat (@workspace, Agent mode).
Then implement the changes in the exact order listed in the
IMPLEMENTATION ORDER section at the bottom.

Commit after each implementation step before proceeding to the next.

═══════════════════════════════════════════════════════════
OVERVIEW OF CHANGES
═══════════════════════════════════════════════════════════

CHANGE 1: LeakCheck becomes the DEFAULT credential scan engine.
          HIBP (Free / Premium / Demo) is preserved in full but is
          now OPT-IN — only activated when the user explicitly asks.

CHANGE 2: A new MODULE 11 (Shodan Recon) is added.
          It performs passive host/service/port discovery against
          the target domain using the Shodan API.

═══════════════════════════════════════════════════════════
CHANGE 1 — LEAKCHECK AS DEFAULT, HIBP AS OPT-IN
═══════════════════════════════════════════════════════════

──────────────────────────────────────────
1A. LOGIC OVERVIEW
──────────────────────────────────────────

Previously: credential_leak.py defaulted to HIBP (Free/Premium/Demo).
Now:        credential_leak.py defaults to LeakCheck.
            HIBP is only entered when the user passes --use-hibp
            OR explicitly types "hibp" at the interactive engine prompt.

The three HIBP sub-modes (Free, Premium, Demo) are completely
unchanged in their internal logic. They are simply moved behind
the --use-hibp gate.

──────────────────────────────────────────
1B. NEW ENGINE SELECTION FLOW
──────────────────────────────────────────

At startup (before any module runs), if neither --use-hibp nor
--free-hibp nor --demo-mode is passed, AND an email is provided:

  Prompt:
    Select credential leak engine:
      [1] LeakCheck  (default) — Per-email breach lookup. API key optional.
      [2] HIBP       — Free / Premium / Demo modes available.

    Press Enter or type 1 to use LeakCheck, type 2 for HIBP: 

  If the user presses Enter (empty input) OR types "1" → use LeakCheck.
  If the user types "2" OR "hibp" → enter HIBP mode selection sub-prompt
    (the existing HIBP mode prompt: [1] Free HIBP / [2] Premium HIBP).
  If input is invalid → re-prompt once, then default to LeakCheck.
  Log INFO: "Credential engine: LeakCheck" or "Credential engine: HIBP ({mode})".

  If no --email was provided:
    Skip the prompt entirely.
    Use LeakCheck domain-level check (pastes only, no per-email lookup).
    Log INFO: "No email provided — credential scan limited to domain pastes."

  If --use-hibp flag is passed → skip engine prompt, go directly to the
    existing HIBP mode selection sub-prompt ([1] Free / [2] Premium).

  If --free-hibp flag is passed → skip all prompts, use HIBP Free mode directly.
    (Existing behavior preserved, now only reachable via this flag.)

  If --demo-mode flag is passed → skip all prompts, use HIBP Demo mode directly.
    (Existing behavior preserved.)

──────────────────────────────────────────
1C. LEAKCHECK MODULE SPEC
──────────────────────────────────────────

Add LeakCheck logic inside modules/credential_leak.py as a new
private section: _run_leakcheck(). Do NOT create a separate file.

LeakCheck API — two sub-modes, auto-selected:

  Sub-mode A — AUTHENTICATED (api_keys.leakcheck is set in config.yaml):
    Endpoint: GET https://leakcheck.io/api/v2/query/{email}
    Header:   X-API-Key: {api_keys.leakcheck}
    Returns JSON:
      {
        "success": true,
        "found": 3,
        "sources": [
          {
            "name": "BreachName",
            "date": "2020-01",
            "unverified": false,
            "passwordtype": "plaintext",
            "fields": ["email", "password"]
          }
        ]
      }
    Rate limit: 1 request per 1000ms (enforce with AsyncRateLimiter).
    On HTTP 429 → wait 10 seconds, retry once, then skip and log WARNING.
    On HTTP 401/403 → log WARNING "LeakCheck API key invalid or expired.",
      fall back to Public sub-mode for this run.

  Sub-mode B — PUBLIC (api_keys.leakcheck is empty OR key invalid):
    Endpoint: GET https://leakcheck.io/api/public?check={email}
    No authentication required.
    Returns JSON:
      {
        "success": true,
        "found": 2,
        "sources": ["BreachName1", "BreachName2"]
      }
    Note: Public API returns source names only, not field-level detail.
          Map each string name to a minimal source object:
            { "name": source_name, "date": null,
              "unverified": false, "passwordtype": "unknown", "fields": [] }
    Rate limit: 1 request per 2000ms (enforce with AsyncRateLimiter).
    Show this note in the HTML report (styled as a blue info card):
      "ℹ️  LeakCheck Public Mode — Add a LeakCheck API key to config.yaml
       for full breach detail including field types and dates."

LeakCheck Severity Classification (same logic as HIBP):
  CRITICAL: "password" OR "plaintext" OR "hash" in passwordtype
            OR "password" in fields
  HIGH:     "password_hint" OR "security_question" in fields
  MEDIUM:   "phone" OR "address" OR "dob" in fields
  LOW:      email or username only (no credential data)

LeakCheck Score Impact Formula (max 30, identical contract to HIBP):
  base = min(total_sources * 5, 20)
  if overall_severity == "CRITICAL": base += 10
  elif overall_severity == "HIGH":   base += 5
  elif overall_severity == "MEDIUM": base += 3
  score_impact = min(base, 30)

Output — extend the existing CredentialLeakResult Pydantic model.
Add these new optional fields (all default to None when not in use):

  "engine": "leakcheck" | "hibp",         # which engine was used this run
  "leakcheck_mode": "authenticated" | "public" | null,
  "leakcheck_sources": [                  # populated when engine = leakcheck
    {
      "name": "BreachName",
      "date": "2020-01",                  # null in public mode
      "unverified": false,
      "passwordtype": "plaintext",        # "unknown" in public mode
      "fields": ["email", "password"],    # [] in public mode
      "severity": "CRITICAL"             # computed by classifier above
    }
  ],
  "leakcheck_found": 3                    # total sources count; 0 if not found

All existing HIBP fields (mode, demo_mode, hibp_source, total_breaches,
total_pastes, breaches, pastes, data_classes_found) remain in the model
unchanged. They default to their zero/null/empty values when engine = "leakcheck".

The "severity" and "score_impact" top-level fields continue to be
computed from whichever engine ran. The scorer receives score_impact
the same way regardless of engine.

──────────────────────────────────────────
1D. PASTE MONITOR DEPENDENCY UPDATE
──────────────────────────────────────────

modules/paste_monitor.py depends on Module 1 for paste data.
When engine = "leakcheck":
  - LeakCheck does not return paste data.
  - paste_monitor sets mode = "leakcheck", total_pastes = 0, score_impact = 0.
  - HTML report shows:
      "Paste lookup is not available in LeakCheck mode.
       Re-run with --use-hibp and Premium mode for paste site results."

When engine = "hibp": existing behavior is fully unchanged.

──────────────────────────────────────────
1E. HTML REPORT UPDATES FOR LEAKCHECK
──────────────────────────────────────────

Credential Leaks section in the report:

  When engine = "leakcheck" AND leakcheck_found > 0:
    Render a breach table:
      Columns: Source | Date | Fields Exposed | Password Type | Verified | Severity
      (In Public mode, Date / Fields / Password Type columns show "—")
    RED alert banner if CRITICAL severity detected.
    Info card if public mode (blue, as described in 1C).

  When engine = "leakcheck" AND leakcheck_found == 0:
    Green card: "No breaches found for this email in LeakCheck database."

  When engine = "hibp":
    Existing HIBP rendering logic is completely unchanged.

Add "engine" badge to the Credential Leaks section header:
  Show "LeakCheck" or "HIBP (Free|Premium|Demo)" as a small styled badge
  next to the section title so the client can see which source was used.

──────────────────────────────────────────
1F. CLI FLAG CHANGES
──────────────────────────────────────────

ADD this new flag to main.py:

  --use-hibp    → Skip engine prompt, go directly to HIBP mode selection
                  ([1] Free / [2] Premium sub-prompt).
                  Mutually exclusive with --free-hibp and --demo-mode
                  (those still bypass the sub-prompt as before).

KEEP all existing flags unchanged:
  --free-hibp   → HIBP Free mode (no prompt at all)
  --demo-mode   → HIBP Demo mode (no prompt at all)

New usage examples to add to Section 4 (do not remove existing ones):
  python main.py --email user@example.com                      # LeakCheck by default
  python main.py --email user@example.com --use-hibp           # HIBP mode selection prompt
  python main.py --email user@example.com --use-hibp --free-hibp  # ERROR: mutually exclusive

Mutually exclusive group rule:
  --use-hibp cannot be combined with --free-hibp or --demo-mode.
  If combined, raise click.UsageError:
    "--use-hibp is redundant when --free-hibp or --demo-mode is set.
     Use only one HIBP flag."

──────────────────────────────────────────
1G. config.yaml CHANGES
──────────────────────────────────────────

Under api_keys, ADD:
  leakcheck: ""     # Optional. Authenticated API from leakcheck.io/profile.
                    # Leave empty to use the free public endpoint.
                    # Authenticated mode returns full field-level breach detail.

Under rate_limits, ADD:
  leakcheck_auth_delay: 1.0    # Authenticated LeakCheck: 1 req/second
  leakcheck_public_delay: 2.0  # Public LeakCheck: 1 req per 2 seconds

Under modules, ADD:
  shodan_recon: true            # New Module 11 — see Change 2 below

──────────────────────────────────────────
1H. constants.py CHANGES
──────────────────────────────────────────

ADD these constants (do NOT remove or modify any existing ones):

  LEAKCHECK_AUTH_URL: str = "https://leakcheck.io/api/v2/query/{email}"
  LEAKCHECK_PUBLIC_URL: str = "https://leakcheck.io/api/public?check={email}"

  LEAKCHECK_PASSWORD_TYPES_CRITICAL: list[str] = [
      "plaintext", "password", "hash", "bcrypt", "md5", "sha1", "sha256"
  ]

  LEAKCHECK_SEVERITY_FIELDS: dict[str, str] = {
      # field value → severity it implies if found in breach fields list
      "password":          "CRITICAL",
      "password_hint":     "HIGH",
      "security_question": "HIGH",
      "phone":             "MEDIUM",
      "address":           "MEDIUM",
      "dob":               "MEDIUM",
  }

In FINDING_PREFIXES dict, ADD:
  "shodan_recon" → "SHODAN"

In SEVERITY_LABELS — no changes needed.

──────────────────────────────────────────
1I. TESTS FOR LEAKCHECK
──────────────────────────────────────────

File: tests/test_credential_leak.py

ADD (do not remove existing HIBP tests):

  test_leakcheck_authenticated_breach_found:
    Mock aiohttp GET to LEAKCHECK_AUTH_URL returning a 200 JSON response
    with 2 sources (1 CRITICAL, 1 MEDIUM).
    Assert: engine = "leakcheck", leakcheck_found = 2,
            severity = "CRITICAL", score_impact > 0.

  test_leakcheck_public_breach_found:
    Mock aiohttp GET to LEAKCHECK_PUBLIC_URL returning 200 JSON with
    found = 1, sources = ["SomeBreach"].
    Assert: leakcheck_mode = "public", leakcheck_found = 1,
            fields = [] on each source.

  test_leakcheck_not_found:
    Mock aiohttp GET returning { "success": true, "found": 0, "sources": [] }.
    Assert: leakcheck_found = 0, score_impact = 0, severity = "LOW".

  test_leakcheck_429_retry_then_skip:
    Mock aiohttp GET returning HTTP 429 twice.
    Assert: module returns skipped=False, leakcheck_found = 0,
            score_impact = 0, a WARNING is logged.

  test_leakcheck_fallback_to_public_on_401:
    Mock aiohttp GET to AUTH endpoint returning HTTP 401.
    Mock aiohttp GET to PUBLIC endpoint returning 200 with found = 1.
    Assert: leakcheck_mode = "public" (fell back correctly).

  test_engine_default_is_leakcheck:
    Instantiate the module without --use-hibp.
    Assert engine selection returns "leakcheck" when no flag is set.

Add to conftest.py:
  leakcheck_auth_fixture: dict — mock authenticated response (2 sources)
  leakcheck_public_fixture: dict — mock public response (1 source name)

═══════════════════════════════════════════════════════════
CHANGE 2 — MODULE 11: SHODAN RECON
═══════════════════════════════════════════════════════════

──────────────────────────────────────────
2A. FILE AND PURPOSE
──────────────────────────────────────────

New file: modules/shodan_recon.py

Runs only when a DOMAIN is provided.
If no domain → set skipped=True, skip_reason="No domain provided — Shodan requires a domain target.", score_impact=0.
If api_keys.shodan is empty → set skipped=True, skip_reason="Shodan scan skipped — no API key configured. Add a free key to config.yaml.", score_impact=0. Log WARNING.
NEVER crash on missing key.

Purpose: Passively discover what Shodan knows about the target domain's
         IP infrastructure — open ports, running services, CVEs, banners.
         This is READ-ONLY from Shodan's database. No active scanning.

──────────────────────────────────────────
2B. PROCESS FLOW
──────────────────────────────────────────

Step 1 — DNS resolution (using dnspython, same library already in use):
  Resolve A records for the target domain.
  Collect up to 5 unique IPv4 addresses.
  If DNS resolution fails → log WARNING, set skipped=True, return.

Step 2 — Shodan Host Lookup per IP:
  Endpoint: GET https://api.shodan.io/shodan/host/{ip}?key={api_keys.shodan}
  For each resolved IP (up to 5 — use scan_limits.max_shodan_ips from config.yaml).
  Rate limit: 1 request per 1000ms (enforce with AsyncRateLimiter).
  On HTTP 404 ("No information available") → treat as clean, no findings, continue.
  On HTTP 401/403 → log WARNING "Shodan API key invalid.", set skipped=True, return.
  On HTTP 429 → wait 5 seconds, retry once, then skip IP and log WARNING.
  On any other non-200 → log WARNING with status code, skip that IP, continue.

Step 3 — Parse Shodan host response:
  Extract per-IP:
    ip_str:           the IP address string
    hostnames:        list of PTR/hostnames Shodan found (may be empty list)
    org:              string (ISP/org owning the IP, e.g. "Cloudflare, Inc.")
    country_name:     string
    isp:              string
    last_update:      ISO date string
    open_ports:       list of integers (from data[].port)
    services:         list of dicts (see ShodanService model below)
    vulns:            list of CVE strings (from the "vulns" key if present)
    tags:             list of strings (e.g. "cloud", "cdn", "tor")

  For each service banner (each item in the "data" array of the Shodan response):
    port:             int
    transport:        "tcp" | "udp"
    product:          string | null (e.g. "nginx", "Apache httpd")
    version:          string | null (e.g. "1.18.0")
    banner_excerpt:   first 200 characters of the raw banner (data[].data),
                      stripped of non-printable characters.
                      NEVER store the full banner — 200 chars max, hard limit.
    cpe:              list of strings (Common Platform Enumeration identifiers)
    ssl_subject:      string | null — SSL cert subject CN if ssl key present
    http_title:       string | null — data[].http.title if present

──────────────────────────────────────────
2C. RISK CLASSIFICATION
──────────────────────────────────────────

Flag each finding with a severity:

  CRITICAL:
    - Port 22 (SSH) open AND product contains "OpenSSH" with version < 7.0
    - Any CVE in the vulns list with CVSS score >= 9.0
      (Check NVD only if a cve_lookup helper is feasible;
       otherwise flag ALL CVEs from Shodan as HIGH by default — do not
       make extra API calls to NVD. CVE scoring is a best-effort bonus.)
    - Port 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB),
      6379 (Redis), 9200 (Elasticsearch), 5984 (CouchDB) open
      with no SSL detected → CRITICAL (database exposed without encryption)

  HIGH:
    - Any CVE present in the vulns list (if CVSS not checked)
    - Port 21 (FTP), 23 (Telnet), 512, 513, 514 (rsh/rlogin/rexec) open
    - Port 445 (SMB), 135 (RPC), 139 (NetBIOS) open
    - SSL/TLS cert expired (check ssl.cert.expires if present in Shodan data)
    - Self-signed certificate detected (ssl.cert.subject == ssl.cert.issuer)

  MEDIUM:
    - Port 8080, 8443, 8888 (alternative HTTP/HTTPS) open
    - Tag "tor" present in tags list
    - HTTP title contains "phpMyAdmin", "Kibana", "Grafana", "Jenkins",
      "Jupyter", "Portainer", "RabbitMQ" — admin panel exposed
    - Port 25, 465, 587 (SMTP) open with no STARTTLS detected

  LOW:
    - Standard ports open with current software versions
    - Port 80 / 443 open (normal web — informational only)

──────────────────────────────────────────
2D. SCORE IMPACT FORMULA (max 25)
──────────────────────────────────────────

  critical_count = number of CRITICAL findings across all IPs
  high_count     = number of HIGH findings across all IPs
  medium_count   = number of MEDIUM findings across all IPs
  cve_count      = total unique CVEs found across all IPs

  base = min(critical_count * 8 + high_count * 4 + medium_count * 2, 20)
  if cve_count > 0: base += min(cve_count * 2, 5)
  score_impact = min(base, 25)

  When skipped (no domain / no key): score_impact = 0.

──────────────────────────────────────────
2E. PYDANTIC MODELS (add to models.py)
──────────────────────────────────────────

class ShodanService(BaseModel):
    port: int
    transport: str
    product: Optional[str] = None
    version: Optional[str] = None
    banner_excerpt: Optional[str] = None   # max 200 chars
    cpe: list[str] = []
    ssl_subject: Optional[str] = None
    http_title: Optional[str] = None
    severity: str = "LOW"                  # computed by risk classifier

class ShodanHostResult(BaseModel):
    ip_str: str
    hostnames: list[str] = []
    org: Optional[str] = None
    country_name: Optional[str] = None
    isp: Optional[str] = None
    last_update: Optional[str] = None
    open_ports: list[int] = []
    services: list[ShodanService] = []
    vulns: list[str] = []
    tags: list[str] = []
    overall_severity: str = "LOW"          # highest severity across all services + CVEs

class ShodanReconResult(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    skipped: bool = False
    skip_reason: Optional[str] = None
    target_domain: Optional[str] = None
    resolved_ips: list[str] = []
    hosts: list[ShodanHostResult] = []
    total_open_ports: int = 0
    total_cves: int = 0
    unique_cves: list[str] = []
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    overall_severity: str = "LOW"
    score_impact: int = 0

──────────────────────────────────────────
2F. MODULE FUNCTION SIGNATURE
──────────────────────────────────────────

async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    target_domain: Optional[str],
) -> ShodanReconResult:

Follows the exact same signature shape as all other modules (Rule 8).
Uses the shared session and semaphore.
Creates its own AsyncRateLimiter(config.rate_limits["shodan_delay"]).

──────────────────────────────────────────
2G. config.yaml CHANGES FOR SHODAN
──────────────────────────────────────────

Under api_keys, ADD:
  shodan: ""          # Free API key from shodan.io/dashboard.
                      # Free tier allows 1 req/second, host lookup only.
                      # No active scanning — read-only query against Shodan DB.

Under rate_limits, ADD:
  shodan_delay: 1.0   # Shodan free tier: 1 request per second

Under scan_limits, ADD:
  max_shodan_ips: 5   # Max resolved IPs to query per run

──────────────────────────────────────────
2H. constants.py CHANGES FOR SHODAN
──────────────────────────────────────────

ADD (do NOT modify existing constants):

  SHODAN_HOST_URL: str = "https://api.shodan.io/shodan/host/{ip}"

  SHODAN_CRITICAL_PORTS: list[int] = [
      3306, 5432, 27017, 6379, 9200, 5984
  ]

  SHODAN_HIGH_PORTS: list[int] = [
      21, 23, 445, 135, 139, 512, 513, 514
  ]

  SHODAN_MEDIUM_PORTS: list[int] = [
      8080, 8443, 8888
  ]

  SHODAN_ADMIN_TITLES: list[str] = [
      "phpMyAdmin", "Kibana", "Grafana", "Jenkins",
      "Jupyter", "Portainer", "RabbitMQ"
  ]

  SHODAN_LEGACY_PROTOCOLS: list[int] = [21, 23, 512, 513, 514]

──────────────────────────────────────────
2I. PROJECT LAYOUT ADDITIONS
──────────────────────────────────────────

Add to the project layout in README.md and in the directory tree:

  modules/
  └── shodan_recon.py           # MODULE 11 — Shodan passive host recon

  tests/
  └── test_shodan_recon.py      # Tests for Module 11

──────────────────────────────────────────
2J. RUNTIME BATCH PLACEMENT
──────────────────────────────────────────

Add shodan_recon to Runtime Batch 2 (concurrent with github, email, dns):

  Runtime Batch 2 (concurrent via asyncio.gather()):
    github_footprint, email_intel, dns_email_auth, shodan_recon  ← ADD HERE

shodan_recon result is passed to exposure_scorer in Batch 4 alongside
all other module results. No special ordering needed.

──────────────────────────────────────────
2K. EXPOSURE SCORER UPDATE
──────────────────────────────────────────

In modules/exposure_scorer.py, add Shodan to the scoring table:

  Shodan host/port recon:    25 pts max

The scorer continues to simply sum score_impact values from each module
(including shodan_recon.score_impact). No formula changes to the scorer
itself — the ShodanReconResult already computes score_impact correctly.

The total weight table now sums to 165 (was 140), still capped at 100.

Add "SHODAN" to FINDING_PREFIXES in constants.py (already covered in 1H).
Shodan finding IDs: SHODAN-001, SHODAN-002, etc.

Per-finding structure for Shodan (same schema as other modules):
  {
    "id": "SHODAN-001",
    "module": "shodan_recon",
    "category": "Host & Service Exposure",
    "title": "Critical database port exposed without encryption",
    "risk": "CRITICAL",
    "score_impact": <int>,
    "data_classes": [],
    "recommendation": "Restrict database ports to private networks. Never expose port 3306/5432/27017 publicly.",
    "references": ["https://www.shodan.io/"]
  }

──────────────────────────────────────────
2L. HTML REPORT UPDATES FOR SHODAN
──────────────────────────────────────────

Add sidebar item 13: "Shodan Recon" (after "Google Dork Recipe",
before "Risk Summary & Recommendations"). Renumber "Risk Summary" to 13
and "Appendix" to 14.

Shodan Recon section content:

  If skipped: show "Shodan scan skipped — [skip_reason]" info card.

  If results present:
    a) IP overview table:
         Columns: IP Address | Org / ISP | Country | Open Ports | CVEs | Severity
         Color-code Severity cell: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=green

    b) Services detail table (one row per service across all IPs):
         Columns: IP | Port | Protocol | Product | Version | Severity | HTTP Title
         Show banner_excerpt in a collapsible <details> element per row.
         ("Click to expand banner excerpt")
         Truncate banner_excerpt display to 200 chars (already enforced in model).

    c) CVE panel (only if unique_cves is non-empty):
         A red warning card listing all unique CVE IDs.
         Each CVE ID is a clickable link: https://nvd.nist.gov/vuln/detail/{CVE-ID}
         Note beneath: "CVE data sourced from Shodan. Verify severity at NVD before reporting."

    d) Port risk heatmap (vanilla JS + inline SVG grid — no external libraries):
         Visual 10×N grid of port badges, color-coded by severity.
         CRITICAL = red, HIGH = orange, MEDIUM = yellow, LOW/INFO = blue.
         Hovering a badge shows: Port Number | Service | Severity

  All tables sortable (vanilla JS only, consistent with existing report tables).

Add to Executive Summary 4-card stats grid (replacing one slot or adding a 5th card):
  5th card: "Shodan Open Ports: N" (shows "—" if skipped or no domain)

──────────────────────────────────────────
2M. JSON AND MARKDOWN REPORT UPDATES
──────────────────────────────────────────

JSON report (reporting/json_report.py):
  Add to the context dict and serialized output:
    "shodan": ShodanReconResult.model_dump(mode="json")

Markdown report (reporting/markdown_report.py):
  Add a new "## Shodan Recon" section after "## Google Dork Recipe".
  Format:
    - Summary sentence: "Shodan found N open ports across M IPs."
    - Table: IP | Ports | CVEs | Severity
    - If CVEs: list them as bullet points with NVD links.
    - If skipped: show the skip reason as an info blockquote.

HTML template context (reporting/templates/report.html.jinja):
  Add "shodan": ShodanReconResult to the context dict passed by html_report.py.

──────────────────────────────────────────
2N. TESTS FOR SHODAN
──────────────────────────────────────────

New file: tests/test_shodan_recon.py

  test_shodan_skipped_no_domain:
    Call run() with target_domain=None.
    Assert: skipped=True, score_impact=0.

  test_shodan_skipped_no_api_key:
    Call run() with a config where api_keys.shodan = "".
    Assert: skipped=True, score_impact=0, WARNING logged.

  test_shodan_critical_db_port_exposed:
    Mock DNS resolution → ["1.2.3.4"]
    Mock Shodan host response with port 3306 open, no SSL.
    Assert: critical_findings >= 1, overall_severity = "CRITICAL",
            score_impact > 0.

  test_shodan_cve_found:
    Mock Shodan response with "vulns": {"CVE-2021-44228": {...}}.
    Assert: unique_cves = ["CVE-2021-44228"], total_cves = 1, high_findings >= 1.

  test_shodan_host_not_found_404:
    Mock Shodan GET returning HTTP 404.
    Assert: hosts = [], score_impact = 0, no crash.

  test_shodan_invalid_key_401:
    Mock Shodan GET returning HTTP 401.
    Assert: skipped=True, WARNING logged.

  test_shodan_banner_truncated:
    Mock Shodan response with a banner > 200 chars.
    Assert: banner_excerpt length <= 200 for all services.

  test_shodan_score_formula:
    Construct a ShodanReconResult with 2 critical_findings, 1 high_finding.
    Manually compute expected score_impact.
    Assert score_impact matches formula: min(2*8 + 1*4, 20) = 20.

Add to conftest.py:
  shodan_host_fixture: dict — mock Shodan host response for a domain with
    port 80 (HTTP, nginx), port 443 (HTTPS, nginx), port 3306 (MySQL exposed).
    Include one CVE entry. Use realistic fake data.

═══════════════════════════════════════════════════════════
IMPLEMENTATION ORDER
═══════════════════════════════════════════════════════════

Implement in this exact order. Commit after each step.

STEP 1 — constants.py
  Add: LEAKCHECK_AUTH_URL, LEAKCHECK_PUBLIC_URL,
       LEAKCHECK_PASSWORD_TYPES_CRITICAL, LEAKCHECK_SEVERITY_FIELDS,
       SHODAN_HOST_URL, SHODAN_CRITICAL_PORTS, SHODAN_HIGH_PORTS,
       SHODAN_MEDIUM_PORTS, SHODAN_ADMIN_TITLES, SHODAN_LEGACY_PROTOCOLS.
  Update: FINDING_PREFIXES — add "shodan_recon" → "SHODAN".

STEP 2 — config.yaml
  Add: api_keys.leakcheck, api_keys.shodan.
  Add: rate_limits.leakcheck_auth_delay, rate_limits.leakcheck_public_delay,
       rate_limits.shodan_delay.
  Add: scan_limits.max_shodan_ips.
  Add: modules.shodan_recon.

STEP 3 — models.py
  Add: ShodanService, ShodanHostResult, ShodanReconResult.
  Extend: CredentialLeakResult with engine, leakcheck_mode,
          leakcheck_sources, leakcheck_found fields.

STEP 4 — modules/credential_leak.py
  Add: _run_leakcheck() private function (authenticated + public sub-modes).
  Update: engine selection logic and startup prompt.
  Update: run() to dispatch to _run_leakcheck() or _run_hibp() based on engine.
  No changes to any existing HIBP sub-functions (_run_hibp_free, _run_hibp_premium).

STEP 5 — modules/paste_monitor.py
  Update: handle engine = "leakcheck" case (return score_impact=0 with info message).

STEP 6 — modules/shodan_recon.py  (NEW FILE)
  Implement full module per spec in sections 2A–2F.

STEP 7 — main.py
  Add: --use-hibp CLI flag.
  Add: engine selection prompt logic.
  Update: Runtime Batch 2 to include shodan_recon.
  Update: pass shodan result to scorer and reporters.

STEP 8 — modules/exposure_scorer.py
  Add: shodan_recon result to scoring sum.

STEP 9 — reporting/ (all three reporters + Jinja template)
  Update: html_report.py, json_report.py, markdown_report.py,
          report.html.jinja per sections 1E, 2L, 2M.

STEP 10 — tests/
  Update: tests/test_credential_leak.py (add LeakCheck tests per 1I).
  Add:    tests/test_shodan_recon.py (per 2N).
  Update: tests/conftest.py (add leakcheck fixtures and shodan_host_fixture).

STEP 11 — Validation
  Run: ruff check .   → must pass with 0 errors.
  Run: python -m pytest tests/ -v   → must pass all tests.
  Smoke test: python main.py --email test@example.com --domain example.com --demo-mode
              → should show LeakCheck engine section AND Shodan section in output.

═══════════════════════════════════════════════════════════
COPILOT BEHAVIORAL RULES (apply to this patch)
═══════════════════════════════════════════════════════════

RULE A: DO NOT TOUCH any code not mentioned in this prompt.
  Existing modules (github_footprint, email_intel, social_footprint,
  js_secret_scanner, dns_email_auth, metadata_extractor, google_dorks,
  exposure_scorer) are UNCHANGED unless explicitly referenced above.

RULE B: All new constants go into core/constants.py ONLY.
  No module may define its own copy of SHODAN_* or LEAKCHECK_* values.

RULE C: shodan_recon.py MUST follow Rule 8 (session + semaphore signature).
  It must NOT create its own aiohttp.ClientSession.

RULE D: All new Pydantic models go into core/models.py.
  Do not define models inside module files.

RULE E: When engine = "leakcheck", the word "HIBP" must not appear
  anywhere in the terminal output or HTML report for that run.
  Engine badge must correctly show "LeakCheck (Authenticated)" or
  "LeakCheck (Public)" instead.

RULE F: banner_excerpt in ShodanService is hard-capped at 200 characters.
  Enforce this in the model using a Pydantic field_validator, not just
  in the parsing code.
    @field_validator("banner_excerpt")
    @classmethod
    def truncate_banner(cls, v):
        return v[:200] if v else v

RULE G: Do NOT expose raw Shodan API keys in logs.
  Never log the api_keys.shodan value. Only log the first 4 chars + "***"
  if you need to confirm key presence in a debug message.

RULE H: Ruff ASYNC compliance (Rule 10 from original prompt) applies
  to shodan_recon.py. Use asyncio.get_running_loop(), never time.sleep(),
  never blocking I/O inside async def without run_in_executor.

═══════════════════════════════════════════════════════════
END OF PATCH PROMPT v23
═══════════════════════════════════════════════════════════
