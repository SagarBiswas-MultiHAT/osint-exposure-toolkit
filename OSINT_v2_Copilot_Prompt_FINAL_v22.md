# OSINT Digital Exposure Toolkit v2
# VS Code GitHub Copilot — Final Build Prompt v22 (10/10)

═══════════════════════════════════════════════════════════
HOW TO USE THIS PROMPT WITH COPILOT
═══════════════════════════════════════════════════════════

1. Open VS Code with GitHub Copilot Agent (Claude Sonnet or GPT-4o) enabled.
2. Create an empty project folder and open it as your workspace.
3. Open Copilot Chat in Agent mode (@workspace).
4. Paste this entire prompt as a single instruction to start the build.
5. Implement batch by batch per Section 14. Commit after each batch completes
   before asking Copilot to proceed to the next.
6. If Copilot's context resets mid-build, re-paste the relevant Section(s)
   from Section 3 plus Section 13 (Code Standards) and Section 14 (Order).
7. After all batches: run `ruff check .` and `python -m pytest tests/ -v`
   and confirm both pass before considering the build complete.

═══════════════════════════════════════════════════════════

You are a senior OSINT engineer, cybersecurity consultant, and Python architect.

Your task is to build a complete, production-grade "OSINT Digital Exposure Toolkit"
as a professional portfolio project for a freelance security consultant's Fiverr profile.

This is a COMPANION tool to an existing attack-surface-toolkit (v1). Where v1 maps
a target's web infrastructure, v2 answers a different question:

    "How exposed is this person or organization across the open internet right now?"

All techniques must be PASSIVE, ETHICAL, and NON-DESTRUCTIVE.
No exploitation. No brute force. No unauthorized access. No payload injection.
Only publicly available data sources and open APIs.

═══════════════════════════════════════════════════════════
SECTION 1: PROJECT IDENTITY AND PURPOSE
═══════════════════════════════════════════════════════════

Tool name:        osint-exposure-toolkit
Version:          1.0.0
Target:           An email address OR a domain name OR both
Primary output:   "Digital Exposure Report" — client-ready HTML/JSON/MD deliverable
Positioning:      What a security consultant hands to a client before a pentest starts

Use cases:
  - A startup wants to know what attackers can find about them before launch
  - A developer wants to audit their own digital footprint
  - A company wants to see if any employee credentials are publicly leaked
  - A freelance security consultant needs a premium deliverable for Fiverr clients

This tool does NOT derive email addresses from domains. If the user wants         ← v22
per-email HIBP lookup, they must provide --email explicitly. Do not generate      ← v22
candidate emails like admin@, info@, webmaster@, etc.                             ← v22

═══════════════════════════════════════════════════════════
SECTION 2: PROJECT ARCHITECTURE
═══════════════════════════════════════════════════════════

Language: Python 3.11+
Structure: Modular, async-first, production-style

Project layout:

osint-exposure-toolkit/
├── main.py                         # CLI entrypoint (Click + Rich)       ← v22
├── config.yaml                     # API keys, timeouts, output settings
├── requirements.txt
├── pyproject.toml                  # Ruff + pytest config
├── README.md
├── Dockerfile
├── .dockerignore                   # Excludes output/, .git/, __pycache__, etc.
├── docker-compose.yml
├── .github/
│   └── workflows/
│       └── ci.yml                  # lint + test pipeline
├── core/
│   ├── __init__.py
│   ├── config_loader.py            # Loads and validates config.yaml
│   ├── logger.py                   # Rich-based logging (file + console)
│   ├── rate_limiter.py             # Async per-source rate limiting (see Section 3)  ← v22
│   ├── models.py                   # Pydantic v2 models for all data structures
│   └── constants.py                # All hardcoded values live here only (see Section 3)  ← v22
├── modules/
│   ├── __init__.py
│   ├── credential_leak.py          # MODULE 1  — HIBP breach checks (Free / Premium / Demo)
│   ├── github_footprint.py         # MODULE 2  — GitHub org/user repos + secret scanning
│   ├── email_intel.py              # MODULE 3  — Email validation, MX, SMTP VRFY, SPF
│   ├── social_footprint.py         # MODULE 4  — Public social/web presence discovery
│   ├── paste_monitor.py            # MODULE 5  — Thin wrapper over Module 1 paste results
│   ├── js_secret_scanner.py        # MODULE 6  — Publicly loaded JS file secret pattern scanner
│   ├── dns_email_auth.py           # MODULE 7  — SPF, DMARC, DKIM, MTA-STS full validation
│   ├── google_dorks.py             # MODULE 8  — Passive dork query builder + optional DDG check
│   ├── metadata_extractor.py       # MODULE 9  — Public document metadata leaks
│   └── exposure_scorer.py          # MODULE 10 — Weighted 0–100 exposure scoring engine
├── reporting/
│   ├── __init__.py
│   ├── html_report.py
│   ├── json_report.py
│   ├── markdown_report.py
│   └── templates/
│       └── report.html.jinja
├── graph/
│   ├── __init__.py
│   └── exposure_graph.py           # NetworkX + PyVis digital exposure graph
├── tests/
│   ├── conftest.py                 # Shared fixtures — see Section 9
│   ├── fixtures/
│   │   └── hibp_mock.json          # Real historical breach fixture data
│   ├── test_credential_leak.py
│   ├── test_github_footprint.py
│   ├── test_email_intel.py
│   ├── test_exposure_scorer.py
│   ├── test_config_loader.py
│   ├── test_social_footprint.py
│   ├── test_paste_monitor.py
│   ├── test_js_secret_scanner.py
│   ├── test_metadata_extractor.py
│   ├── test_dns_email_auth.py
│   ├── test_google_dorks.py
│   └── test_reports.py             # Smoke tests for all report generators       ← v22
└── output/                         # Auto-created, per-target + timestamp
    └── target_2026-01-01_12-00/
        ├── report.html
        ├── report.md
        ├── report.json
        └── exposure_graph.html

═══════════════════════════════════════════════════════════
SECTION 3: CORE AND MODULE — DETAILED SPECIFICATIONS            ← v22 (title expanded)
═══════════════════════════════════════════════════════════

──────────────────────────────────────────                       ← v22 NEW BLOCK
CORE: constants.py
File: core/constants.py
──────────────────────────────────────────

All hardcoded values for the entire project live in this single file.
No module may define its own version of any value listed below.

Required contents:

  TOOL_NAME: str = "osint-exposure-toolkit"
  TOOL_VERSION: str = "1.0.0"

  USER_AGENT: str =                                                          ← v22
    "Mozilla/5.0 (compatible; OSINT-Exposure-Toolkit/1.0;                    ← v22
     +https://github.com/sagarbiswas-multihat)"                              ← v22

  SECRET_PATTERNS: dict[str, str]
    All 14 regex patterns specified in Module 2 (AWS Access Key through
    Generic token). Keys are the human-readable pattern names
    (e.g. "AWS Access Key"), values are the raw regex strings.

  JS_EXTRA_PATTERNS: dict[str, str]
    The 4 additional patterns from Module 6:
      "Internal IP", "Internal Path Hint", "Commented Credential",
      "Environment Flag"

  DISPOSABLE_DOMAINS: list[str]
    Top 50 disposable email domains. Must include at minimum:
      mailinator.com, guerrillamail.com, temp-mail.org, throwaway.email,
      yopmail.com, fakeinbox.com, sharklasers.com, guerrillamailblock.com,
      grr.la, dispostable.com, mailnesia.com, tempail.com, tempr.email,
      discard.email, discardmail.com, trashmail.com, trashmail.net,
      10minutemail.com, tempmailo.com, getnada.com, emailondeck.com,
      33mail.com, maildrop.cc, inboxkitten.com, meltmail.com,
      mohmal.com, tempinbox.com, harakirimail.com, jetable.org,
      spamgourmet.com, mytemp.email, throwam.com, tempmailer.com,
      tmail.ws, tmpmail.net, binkmail.com, mailcatch.com,
      trashmail.me, mailnull.com, mailforspam.com, safetymail.info,
      filzmail.com, mailmoat.com, trashymail.com, sharklasers.com,
      spam4.me, grr.la, guerrillamail.info, guerrillamail.de,
      guerrillamail.net, guerrillamail.biz

  SOCIAL_PLATFORMS: dict[str, str]
    Platform name → URL template with {username} placeholder.
    All platforms listed in Module 4 (GitHub, GitLab, NPM, PyPI,
    Docker Hub, HackerOne, Bugcrowd, LinkedIn, Dev.to, Twitter/X,
    Medium, HackerNews, Keybase).
    Gravatar is handled separately (MD5 hash, not username-based).

  POSITIVE_SIGNAL_PLATFORMS: list[str]
    ["HackerOne", "Bugcrowd"]

  DKIM_SELECTORS: list[str]
    The 13 selectors from Module 7: default, google, k1, mail, smtp,
    selector1, selector2, dkim, email, s1, s2, mxvault, protonmail

  MAIL_PROVIDERS: dict[str, str]
    MX hostname substring → provider name.
    google.com → "Google Workspace", googlemail.com → "Google Workspace",
    outlook.com → "Microsoft 365", hotmail.com → "Microsoft 365",
    microsoft.com → "Microsoft 365", zoho.com → "Zoho Mail",
    protonmail.com → "ProtonMail", proton.me → "ProtonMail"

  DORK_TEMPLATES: dict[str, list[str]]
    Dork category name → list of query template strings with {domain}
    and/or {email} placeholders. All 6 categories from Module 8.

  SEVERITY_LABELS: dict[str, str]
    Score range to label mapping from Module 10:
      "0-15" → "MINIMAL EXPOSURE", "16-30" → "LOW EXPOSURE",
      "31-50" → "MODERATE EXPOSURE", "51-70" → "HIGH EXPOSURE",
      "71-100" → "CRITICAL EXPOSURE"

  FINDING_PREFIXES: dict[str, str]
    Module name → finding ID prefix:
      "credential_leak" → "CRED", "github_footprint" → "GH",
      "email_intel" → "EMAIL", "social_footprint" → "SOC",
      "paste_monitor" → "PASTE", "js_secret_scanner" → "JS",
      "dns_email_auth" → "DNS", "metadata_extractor" → "META",
      "google_dorks" → "DORK"

  CONFIG_FILES_TO_SCAN: list[str]                                            ← v22
    The ordered list of files to scan per repo in Module 2:
      .env.example, .env.sample, config.py, settings.py, config.js,
      application.properties, app.config, docker-compose.yml,
      docker-compose.prod.yml, .travis.yml, .circleci/config.yml,
      Dockerfile, README.md

  SPOOFABILITY_WEIGHTS: dict[str, int]                                       ← v22
    SPF_MISSING → 4, SPF_WEAK → 2, DMARC_MISSING → 3,
    DMARC_NONE → 2, DKIM_MISSING → 3

──────────────────────────────────────────                       ← v22 NEW BLOCK
CORE: rate_limiter.py
File: core/rate_limiter.py
──────────────────────────────────────────

Provides a per-source async rate limiter to enforce the per-API delays
defined in config.yaml rate_limits section.

Class: AsyncRateLimiter

  def __init__(self, delay_seconds: float) -> None:
      """
      Args:
          delay_seconds: Minimum interval between consecutive requests
                         for this source (e.g. 1.5 for HIBP, 5.0 for DDG).
      """
      Stores delay_seconds and initialises last_request_time to 0.0.

  async def acquire(self) -> None:
      """
      If less than delay_seconds has elapsed since the last acquire() call,
      await asyncio.sleep(remaining_time). Then update last_request_time
      to the current monotonic time.
      Uses asyncio.get_running_loop().time() for monotonic clock.
      Thread-safe via asyncio.Lock().
      """

Usage pattern in modules:
  limiter = AsyncRateLimiter(config.rate_limits["hibp_delay"])
  async with semaphore:        # controls global concurrency (max_concurrent_requests)
      await limiter.acquire()  # enforces per-API pacing independently
      async with session.get(url, headers={"User-Agent": USER_AGENT}) as resp:
          ...

The semaphore (from main.py) controls max_concurrent_requests globally.
The AsyncRateLimiter controls per-source pacing independently.
Both are used together — they solve different problems.

Each module creates its own AsyncRateLimiter instance using the appropriate
delay from config.rate_limits. The rate limiter is NOT shared across modules
(each API source has its own pacing requirement).

──────────────────────────────────────────
MODULE 1: Credential Leak Detection
File: modules/credential_leak.py
──────────────────────────────────────────

HIBP operates in THREE distinct modes. The mode is determined at startup.
Report STRUCTURE must be identical across all three modes — the same sections,
same sidebar items, same scoring table. Content will naturally differ
(Free mode shows breach landscape; Premium shows per-email results).

─ MODE SELECTION ─────────────────────────────────────

On startup, if neither --free-hibp nor --demo-mode is passed, the CLI
interactively prompts:

    Select HIBP scan mode:
      [1] Free HIBP    — No API key required. Shows breach landscape only.
      [2] Premium HIBP — Per-email breach lookup. Requires API key in config.yaml.

    Enter choice [1/2]:

If no --email was provided on the CLI → skip the prompt entirely, use Free mode
automatically. Log INFO: "No email provided — HIBP defaulting to Free mode (breach landscape only)."
If the user enters anything other than "1" or "2" → re-prompt once with:
  "Invalid choice. Please enter 1 for Free HIBP or 2 for Premium HIBP: "
If still invalid → default to Free mode, log WARNING "Invalid HIBP mode input — defaulting to Free mode."
If --free-hibp flag is passed → skip prompt, use Free mode.
If --demo-mode flag is passed → skip prompt, use Demo mode.

─ FREE HIBP MODE ─────────────────────────────────────

API call: GET https://haveibeenpwned.com/api/v3/breaches
No authentication required. Returns all known breach metadata.

In the HTML report, render a "Known Breach Database Coverage" section:

  a) Summary stat block (two large numbers):
       "HIBP tracks N breaches affecting X billion accounts"
       Compute N = count of all breaches returned.
       Compute X = sum(breach.PwnCount for all breaches) / 1_000_000_000, rounded to 1 decimal.

  b) Fully interactive breach table (vanilla JS, zero external libraries):
       Columns: Name | Domain | Breach Date | Data Classes | Verified | Records
       Features:
         - Live search box: filters Name and Domain columns as user types (case-insensitive)
         - DataClasses filter: multi-select dropdown listing unique data classes across all breaches
         - BreachDate year filter: dropdown of unique years
         - IsVerified filter: checkbox toggle (checked = show verified only)
         - Default sort: PwnCount descending (largest breaches first)
         - Pagination: 50 rows per page with Prev / Next buttons
         - Row count indicator: "Showing X–Y of N breaches"
         - All filters AND sort AND pagination work together simultaneously

  c) Note below the table:
       "Your target was not individually checked in Free mode. Switch to Premium
        HIBP mode for per-email breach lookup. The table above represents the full
        public breach landscape your target email could appear in."

  No per-email API calls are made in Free mode. No API key needed.

─ PREMIUM HIBP MODE ─────────────────────────────────

Sub-mode A — LIVE (api_keys.hibp is set in config.yaml):
  Call GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
    Header: hibp-api-key: {key}
    Rate limit: 1 request per 1500ms — enforce strictly with AsyncRateLimiter   ← v22
  Call GET https://haveibeenpwned.com/api/v3/pasteaccount/{email}
    Same header and rate limit.
  Return structured CredentialLeakResult with per-email findings.

Sub-mode B — DEMO (api_keys.hibp is empty in config.yaml OR --demo-mode flag):
  Load tests/fixtures/hibp_mock.json silently. No API call.
  Show this banner in the HTML report (styled as a yellow warning card):
    "⚠️  Demo Mode — No HIBP API key configured. Breach data loaded from
      fixture file. Add your key to config.yaml for live per-email results."
  Include in JSON output: { "demo_mode": true, "hibp_source": "fixture" }

─ FIXTURE FILE ───────────────────────────────────────

File: tests/fixtures/hibp_mock.json
Must use EXACT HIBP API v3 field names throughout.

Breach fields: Name, Title, Domain, BreachDate, AddedDate, ModifiedDate,
  PwnCount, Description, LogoPath, DataClasses, IsVerified, IsFabricated,
  IsSensitive, IsRetired, IsSpamList, IsMalware

Paste fields: Source, Id, Title, Date, EmailCount

Populate with these REAL historical breaches (use accurate public data):
  1. LinkedIn (2012)
       DataClasses: ["Email addresses", "Passwords"]
       PwnCount: 164611595
       IsVerified: true
       → Severity: CRITICAL (passwords found)
  2. Adobe (2013)
       DataClasses: ["Email addresses", "Password hints", "Usernames"]
       PwnCount: 153000000
       IsVerified: true
       → Severity: HIGH
  3. Dropbox (2012)
       DataClasses: ["Email addresses", "Passwords"]
       PwnCount: 68648009
       IsVerified: true
       → Severity: CRITICAL
  4. MySpace (2008)
       DataClasses: ["Email addresses", "Passwords", "Usernames"]
       PwnCount: 359420698
       IsVerified: true
       → Severity: CRITICAL

Target email in fixture: demo@example.com
Include 2 realistic Pastebin paste entries with real-looking Ids and dates.

─ BREACH SEVERITY CLASSIFICATION ────────────────────

Classify each breach by its DataClasses:
  CRITICAL: contains "Passwords" AND ("Email addresses" OR "Usernames")
  HIGH:     contains "Password hints" OR "Security questions and answers"
  MEDIUM:   contains personal info (Phone numbers, Addresses, Dates of birth)
  LOW:      email or username only, no sensitive credential data

─ SCORE_IMPACT FORMULA (max 30) ─────────────────────     ← v22 NEW BLOCK

  base = min(total_breaches * 5, 20)
  if overall severity == "CRITICAL": base += 10
  elif overall severity == "HIGH":   base += 5
  elif overall severity == "MEDIUM": base += 3
  score_impact = min(base, 30)

  Free mode: score_impact = 0 (no per-email results to score).
  Demo mode: apply the formula normally to fixture data.

─ OUTPUT MODEL ──────────────────────────────────────

CredentialLeakResult (Pydantic v2, ConfigDict(use_enum_values=True)):
  {
    "email": "target@example.com",  # Optional[str] = None — null in domain-only runs
    "mode": "live" | "demo" | "free",
    "demo_mode": false,
    "hibp_source": "live" | "fixture" | "public_api",
    "total_breaches": 4,
    "total_pastes": 2,
    "severity": "CRITICAL",
    "breaches": [{ all HIBP breach fields... }],
    "pastes": [{ all HIBP paste fields... }],
    "data_classes_found": ["Passwords", "Email addresses", "Usernames"],
    "score_impact": 30  # max 30 — computed by formula above                 ← v22
  }

DO NOT include LeakCheck.io. Remove all references to it.

──────────────────────────────────────────
MODULE 2: GitHub Footprint and Secret Scanner
File: modules/github_footprint.py
──────────────────────────────────────────

IMPORTANT: If api_keys.github is empty in config.yaml → skip this module entirely.
Log: WARNING "GitHub scan skipped — no API key configured. Add a free PAT to config.yaml."
Show in HTML report: "GitHub scan skipped — no API key configured."
NEVER crash on missing key.

If key is present, proceed with full scan:

PART A — Organization/User Discovery:
  - GitHub Search API: GET /search/users?q={domain or name}
  - GET /orgs/{org}/repos (if org found)
  - GET /users/{user}/repos
  - For each repo collect:
    { name, description, language, stars, forks, last_pushed,
      is_fork, default_branch, topics, clone_url }
  - Flag repos pushed within last 30 days (active = higher risk)
  - Detect repos with public GitHub Pages enabled

  GitHub API pagination: use only the first page of results (default 30     ← v22
  items per page). Do not implement multi-page pagination — the             ← v22
  scan_limits cap (max 10 repos) makes it unnecessary.                      ← v22

PART B — Secret Pattern Scanning:
  Scan these files per repo via raw.githubusercontent.com
  (in the order listed in CONFIG_FILES_TO_SCAN from constants.py):          ← v22
    .env.example, .env.sample, config.py, settings.py, config.js,
    application.properties, app.config, docker-compose.yml,
    docker-compose.prod.yml, .travis.yml, .circleci/config.yml,
    Dockerfile, README.md
  For .github/workflows/ files: first call GET /repos/{owner}/{repo}/contents/.github/workflows
  via GitHub API to list all .yml filenames, then fetch each one individually via
  raw.githubusercontent.com. Skip if the directory does not exist (404).
  Respect scan_limits.max_workflow_files from config.yaml.

  Apply all 14 regex patterns from SECRET_PATTERNS in constants.py:          ← v22
    AWS Access Key:        AKIA[0-9A-Z]{16}
    AWS Secret:            (?i)(?:aws_secret|secret_access_key)\s*[=:]\s*['"]?([0-9a-zA-Z/+]{40})
    GitHub Token:          ghp_[a-zA-Z0-9]{36}
    Stripe Secret Key:     sk_live_[0-9a-zA-Z]{24}
    Stripe Public Key:     pk_live_[0-9a-zA-Z]{24}
    Slack Token:           xox[baprs]-[0-9a-zA-Z-]+
    Google API Key:        AIza[0-9A-Za-z\-_]{35}
    Twilio SID:            AC[a-z0-9]{32}
    SendGrid Key:          SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}
    JWT Token:             eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-.+/=]*
    Private Key Header:    -----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----
    Database URL:          (postgresql|mysql|mongodb|redis)://[^\s'"]+
    Generic password:      (password|passwd|secret|api_key|apikey)\s*[=:]\s*['"][^'"]{8,}['"]
    Generic token:         (token|auth_token|access_token)\s*[=:]\s*['"][^'"]{8,}['"]

  CRITICAL secret safety rule:
    NEVER log or store the full secret value anywhere.
    Mask ALL matched values as: first_4_chars + "***" + last_4_chars
    Example: "AKIAIOSFODNN7EXAMPLE" → "AKIA***MPLE"
    Apply this masking in models, JSON output, HTML report, markdown, and logs.

    WHICH GROUP TO MASK:
      AWS Secret pattern ONLY: mask group(1) — the 40-char key value,
        not the surrounding "aws_secret_access_key = '...'" context.
      ALL other patterns (including those with capture groups used for
        alternation such as Database URL, Generic password, Generic token,
        Private Key Header): mask group(0) — the full match.

  Rate limits:
    - Max repos scanned per run: scan_limits.max_github_repos (default 10)
    - Max successfully fetched files per repo: scan_limits.max_github_files (default 5).
      Attempt files in the order listed above; stop once the limit is reached.
      Workflow files are attempted last and count toward this cap.
    - Max workflow files: scan_limits.max_workflow_files (default 3)
    - 1 request per second to GitHub API (enforce with AsyncRateLimiter)     ← v22

  Email filter: skip any candidate subdomain/user containing "@".

─ SCORE_IMPACT FORMULA (max 25) ─────────────────────     ← v22 NEW BLOCK

  base = min(secret_count * 5, 15)
  if overall severity == "CRITICAL": base += 10
  elif overall severity == "HIGH":   base += 5
  elif overall severity == "MEDIUM": base += 3
  score_impact = min(base, 25)

  When skipped (no API key): score_impact = 0.

Output model (GitHubFootprintResult):
  {
    "skipped": false,
    "skip_reason": null,
    "target": "example.com",
    "users_found": ["user1"],
    "orgs_found": ["orgname"],
    "total_repos": 12,
    "active_repos_30d": 4,
    "secrets_found": [
      { "repo_name": "...", "file_path": "...", "pattern_type": "AWS Access Key",
        "masked_value": "AKIA***MPLE", "line_number": 42,
        "commit_hash": "abc123def456..."
      }
    ],
    "secret_count": 3,
    "severity": "CRITICAL",
    "score_impact": 25  # max 25 — computed by formula above               ← v22
  }

  Note on commit_hash: use the HEAD SHA already present in the repo object fetched
  in Part A. Set to null if unavailable — never make an extra API call for this
  field and never crash if it is missing.

──────────────────────────────────────────
MODULE 3: Email Intelligence
File: modules/email_intel.py
──────────────────────────────────────────

Use dnspython for all DNS lookups (MX, TXT/SPF). No external API.
Use Python stdlib smtplib (NOT aiosmtplib) for SMTP VRFY checks.

Checks:
  a) Email format and structure validation (regex)
  b) MX record lookup via dnspython — verify mail server exists
  c) Mail server identification from MX hostname patterns
       (use MAIL_PROVIDERS dict from constants.py):                          ← v22
       google.com / googlemail.com → "Google Workspace"
       outlook.com / hotmail.com / microsoft.com → "Microsoft 365"
       zoho.com → "Zoho Mail"
       protonmail.com / proton.me → "ProtonMail"
       else → "Custom / Unknown"
  d) Disposable email detection — compare against DISPOSABLE_DOMAINS         ← v22
     list from constants.py (top 50 disposable domains)
  e) SPF record check via dnspython TXT lookup on the email domain
  f) SMTP VRFY check using smtplib:
       - Connect to first MX server on port 25, timeout 5 seconds
       - Issue EHLO then VRFY {email}
       - 250/252 → "VERIFIED"
       - 550/551/553 → "UNVERIFIED"
       - Timeout, ConnectionRefusedError, or any exception → "UNKNOWN"
       - ALWAYS catch ALL exceptions — never crash on SMTP failure
       - Log timeout/refused as WARNING (not ERROR)
       - Log unexpected exceptions as WARNING (not ERROR)

  ASYNC SAFETY: smtplib is blocking I/O. Never call it directly inside async def.
  Wrap the entire SMTP check in a thread executor to avoid freezing the event loop:
    def _smtp_check_sync(mx_host: str, email: str) -> str:
        # all smtplib logic here — returns "VERIFIED" / "UNVERIFIED" / "UNKNOWN"
    result = await asyncio.get_running_loop().run_in_executor(None, _smtp_check_sync, mx_host, email)
  Note: use asyncio.get_running_loop() NOT get_event_loop() — the latter is deprecated
  in Python 3.10+ and will be flagged by ruff's ASYNC ruleset.

  Report tooltip on smtp_verified field (render as an info icon in HTML):
    "SMTP VRFY is disabled by most mail servers. UNKNOWN is the expected
     result and does not indicate an error in this tool. For best results,
     run from a VPS with unrestricted outbound port 25."

Output model (EmailIntelResult):
  {
    "email": "target@example.com",
    "domain": "example.com",
    "format_valid": true,
    "mx_records": ["aspmx.l.google.com"],
    "mail_provider": "Google Workspace",
    "is_disposable": false,
    "smtp_verified": "UNKNOWN",
    "spf_present": true,
    "risk_notes": ["Corporate email on Google Workspace — real identity likely attached"],
    "score_impact": 5
  }
  score_impact formula:
    0  — if format_valid = False or no MX records found (not a real mailbox)
    5  — if is_disposable = True (throwaway identity, high risk)
    3  — if smtp_verified = "VERIFIED" (confirmed live mailbox = real identity attached)
    1  — all other cases (valid format, real provider, unverified)

──────────────────────────────────────────
MODULE 4: Social and Web Footprint Discovery
File: modules/social_footprint.py
──────────────────────────────────────────

All checks are passive HTTP HEAD/GET requests only.
Do NOT scrape page content. Only verify existence (200 vs 404/403).
Do NOT attempt authenticated access.

Domain-only mode: if no --email was provided, this module cannot derive a username.
Set skipped=True, skip_reason="No email provided — username derivation requires email local part."
Return empty SocialFootprintResult with score_impact=0. Do not crash.

Platforms to check (use SOCIAL_PLATFORMS dict from constants.py):             ← v22
  Developer:   GitHub, GitLab, NPM, PyPI, Docker Hub
  Security:    HackerOne, Bugcrowd
  Professional:LinkedIn, Dev.to
  Social/Web:  Twitter/X, Medium, HackerNews, Keybase
  Identity:    Gravatar (MD5 hash of lowercased email — no username needed)

For Gravatar: MD5 hash the lowercased email using hashlib.
  URL: https://www.gravatar.com/avatar/{md5_hash}?d=404

Username variants derived from email local part (max 4 variants per platform):
  "john.doe" → try: johndoe, john.doe, john_doe, john-doe

For each platform:
  - HTTP HEAD request, 5s timeout
  - 200 = EXPOSED
  - 404 = NOT_FOUND
  - 403/429/other = UNKNOWN
  - Rate limit: 1 request per 500ms (enforce with AsyncRateLimiter)          ← v22
  - Security research platforms (HackerOne, Bugcrowd — listed in             ← v22
    POSITIVE_SIGNAL_PLATFORMS from constants.py) → mark as positive,         ← v22
    not a risk. Note in report: "Security researcher profile — positive signal."

PLATFORM-SPECIFIC STATUS CODES:
  LinkedIn returns HTTP 999 for automated/bot requests. Treat 999 identically
  to 403 — set status = "UNKNOWN", log INFO (not WARNING), do not crash.
  This is expected behavior, not an error.

Output model (SocialFootprintResult):
  {
    "skipped": false,
    "skip_reason": null,
    "target_email": "john.doe@example.com",
    "username_variants": ["johndoe", "john.doe", "john_doe", "john-doe"],
    "platforms_found": [
      { "platform": "GitHub", "url": "https://github.com/johndoe",
        "status": "EXPOSED", "risk_context": "developer",
        "is_positive_signal": false }
    ],
    "total_exposure_count": 6,
    "exposure_categories": ["Developer", "Professional", "Security"],
    "score_impact": 10
  }
  score_impact formula: min(total_exposure_count * 1, 10)
  HackerOne and Bugcrowd profiles (is_positive_signal = True) are excluded
  from total_exposure_count before applying this formula.

──────────────────────────────────────────
MODULE 5: Paste Site Monitor
File: modules/paste_monitor.py
──────────────────────────────────────────

This module is a THIN WRAPPER and FORMATTER over Module 1 results.
It does NOT make any additional API calls.
It does NOT use IntelX. Remove all references to IntelX.

Behavior:
  - In Premium HIBP mode (live or demo): extract paste results already
    collected by Module 1 (credential_leak.py) and format them for display.
  - In Free HIBP mode: paste section in the report shows:
      "Paste lookup requires Premium HIBP mode.
       Re-run with Premium mode for per-email paste site results."
  - Never make independent API calls.

Output model (PasteResult):
  {
    "mode": "premium" | "free",
    "total_pastes": 2,
    "pastes": [{ HIBP paste fields... }],
    "severity": "MEDIUM",
    "score_impact": 15
  }
  score_impact rule: 15 if total_pastes > 0 AND mode = "premium"; 0 in all other cases.
  (Free mode produces no pastes — score_impact must be 0, not 15.)
  Note: score_impact is intentionally binary (0 or 15), not graded by paste count.
  Paste exposure is a binary signal — any appearance in a paste is equally significant.

──────────────────────────────────────────
MODULE 6: JS File Secret Scanner
File: modules/js_secret_scanner.py
──────────────────────────────────────────

Only runs when a domain is provided. Skip with note if email-only scan.

Process:
  1. Fetch the homepage of the target domain via aiohttp
  2. Extract all <script src="..."> URLs on the same domain (not CDN scripts)
  3. For each JS file (max 10 files, max 500KB per file — skip and log if larger):
     a. Fetch raw content via aiohttp
     b. Run all 14 secret patterns from SECRET_PATTERNS in constants.py      ← v22
     c. Additionally scan using JS_EXTRA_PATTERNS from constants.py:         ← v22
          Internal IPs:             (10\.|192\.168\.|172\.16\.)[\d.]+
          Internal path hints:      /api/internal/|/internal/|/_private/
          Commented credentials:    //\s*(password|token)\s*[:=]
          Environment flags:        NODE_ENV=production|ENVIRONMENT=staging
          Hardcoded internal refs:  any URL not matching the public domain
  4. For each match:
     { js_file_url, pattern_type, masked_value (first4***last4),
       line_context (50 chars around match, secret portion masked) }
     Apply the same masking rule as Module 2: AWS Secret pattern → mask group(1);
     all other patterns including those with alternation capture groups → mask group(0).
  5. Rate limit: 1 request per second (enforce with AsyncRateLimiter).       ← v22
     Skip files that return non-200.

─ SCORE_IMPACT FORMULA (max 20) ─────────────────────     ← v22 NEW BLOCK

  base = min(len(secrets_found) * 5, 15)
  if len(internal_endpoints_found) > 0: base += 3
  if len(environment_hints) > 0: base += 2
  score_impact = min(base, 20)

  When skipped (email-only scan): score_impact = 0.

Output model (JSSecretResult):
  {
    "skipped": false,
    "target_domain": "example.com",
    "js_files_scanned": 6,
    "secrets_found": [{ match data... }],
    "internal_endpoints_found": ["/api/internal/v2/"],
    "environment_hints": ["ENVIRONMENT=staging"],
    "severity": "HIGH",
    "score_impact": 20  # max 20 — computed by formula above               ← v22
  }

──────────────────────────────────────────
MODULE 7: DNS Email Authentication Analysis
File: modules/dns_email_auth.py
──────────────────────────────────────────

Full analysis using dnspython and aiohttp only. No external APIs.

Checks:

  a) SPF record:
       - Presence (DNS TXT lookup on domain)
       - Syntax: v=spf1 present
       - Policy strength:
           -all → STRICT (good)
           ~all → SOFT (weak — flag MEDIUM)
           +all → OPEN (HIGH risk — anyone can spoof)
           missing -all/+all/~all → flag as WEAK
       - Mechanism count > 10 DNS lookups → flag as OVER_LIMIT

  b) DMARC record:
       - Presence at _dmarc.{domain}
       - Policy: none (LOW — monitoring only) / quarantine (MEDIUM) / reject (GOOD)
       - Reporting address (rua) missing → flag
       - Subdomain policy (sp=) value
       - Alignment (aspf, adkim)

  c) DKIM:
       - Probe selectors from DKIM_SELECTORS list in constants.py            ← v22
       - Run DKIM selector probes concurrently using asyncio.gather(),       ← v22
         limited to config.rate_limits["dns_concurrent"] simultaneous        ← v22
         lookups (use asyncio.Semaphore(dns_concurrent)).                    ← v22
       - For each found: extract key algorithm and key length
       - RSA key < 2048 bits → MEDIUM risk
       - No selectors found at all → LOW risk flag

  d) MTA-STS:
       - Check _mta-sts.{domain} TXT record
       - Fetch https://mta-sts.{domain}/.well-known/mta-sts.txt
       - Parse policy mode (none / testing / enforce)

  e) Spoofability score (0 = unspoofable, 10 = trivially spoofable):
       Use SPOOFABILITY_WEIGHTS from constants.py:                           ← v22
       SPF missing:           +4
       SPF soft or open:      +2
       DMARC missing:         +3
       DMARC policy=none:     +2
       DKIM missing:          +3
       Cap: score = min(calculated_total, 10)
       If SPF + DMARC + DKIM all absent → set score = 10 directly (override arithmetic).
       All three correct and strict → score = 0

Output model (EmailAuthResult):
  {
    "domain": "example.com",
    "spf": { "present": true, "policy": "~all", "strength": "WEAK",
             "mechanism_count": 4, "over_limit": false },
    "dmarc": { "present": false, "policy": null, "rua": null, "sp": null },
    "dkim_selectors_found": [],
    "mta_sts": { "present": false, "mode": null },
    "spoofability_score": 8,
    "spoofability_label": "HIGH SPOOFING RISK",
    "score_impact": 18
  }
  score_impact formula: score_impact = spoofability_score * 2
  (spoofability_score caps at 10, so score_impact caps at 20 — matching the weight table.)

──────────────────────────────────────────
MODULE 8: Google Dork Query Builder
File: modules/google_dorks.py
──────────────────────────────────────────

Primary function: generate passive dork queries as a "Recon Recipe" for clients.
No API key required. Pure string generation for all dork categories.
No Bing Search API. No IntelX. Remove all references to both.

Use DORK_TEMPLATES from constants.py for query generation.                   ← v22

OPTIONAL live check (DuckDuckGo only):
  URL: https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}
  Rate limit: 1 request per 5 seconds (enforce with AsyncRateLimiter)        ← v22
  Max 3 dork queries checked per run (configurable in config.yaml)
  On 202 / 429 / non-200 / timeout → skip silently, log WARNING, continue
  If 2 consecutive requests are blocked → disable DuckDuckGo for remainder of run
  Parse response: if result count > 0 in HTML → "RESULTS_FOUND", else "NO_RESULTS"

Dork categories to generate:

  a) File exposure:
       site:{domain} ext:pdf | ext:doc | ext:xls | ext:csv
       site:{domain} ext:env | ext:sql | ext:bak | ext:log
       site:{domain} filetype:pdf "confidential" | "internal use"

  b) Admin/login panels:
       site:{domain} inurl:admin | inurl:login | inurl:dashboard
       site:{domain} inurl:wp-admin | inurl:phpmyadmin | inurl:cpanel

  c) Credential exposure:
       site:pastebin.com "{email}"           ← only include if --email is provided
       site:pastebin.com "{domain}" password  ← always include if --domain is provided
       site:github.com "{domain}" password | secret | api_key  ← always include if --domain is provided

  d) Error/debug exposure:
       site:{domain} "SQL syntax" | "stack trace" | "Traceback"
       site:{domain} "Index of /" inurl:backup | inurl:logs

  e) Cloud storage exposure:
       site:s3.amazonaws.com "{domain}"
       site:storage.googleapis.com "{domain}"
       site:blob.core.windows.net "{domain}"

  f) Code repository exposure:
       site:github.com "{domain}" filename:.env
       site:github.com "{domain}" filename:config.yaml password

For each category, return a DorkResult (Pydantic v2 model):
  {
    "category": "File Exposure",
    "dork_queries": ["site:example.com ext:pdf", ...],
    "risk_level": "MEDIUM",
    "ddg_result": "RESULTS_FOUND" | "NO_RESULTS" | "NOT_CHECKED",
    "manual_check_instruction": "Paste this query into Google to verify.",
    "score_impact": 0
  }

  score_impact for the Google Dorks module (fed into exposure_scorer.py):
    score_impact = min(count_of_categories_with_ddg_result="RESULTS_FOUND", 5)
    (0 if none found, 1 per category with hits, capped at 5 — matches weight table max)

──────────────────────────────────────────
MODULE 9: Document Metadata Extractor
File: modules/metadata_extractor.py
──────────────────────────────────────────

Only runs when a domain is provided. Skip with note if email-only scan.

Process:
  1. Parse sitemap.xml and robots.txt Disallow paths from the target domain
  2. Find document URLs ending in .pdf or .docx (max 5 documents)
  3. Fetch each document via aiohttp
  4. Extract metadata:
       PDF:  use pypdf — Author, Creator, Producer, Subject, Keywords, CreationDate
       DOCX: use python-docx — core_properties (author, last_modified_by,
             created, modified, company, keywords)
  5. Flag any metadata containing:
       Personal names (Author, last_modified_by) → MEDIUM
       Internal software with version strings → LOW
       Company name not matching public brand → MEDIUM

─ SCORE_IMPACT FORMULA (max 10) ─────────────────────     ← v22 NEW BLOCK

  base = min(len(unique_authors) * 3, 6)
  if len(internal_software) > 0: base += 2
  if any finding has severity == "MEDIUM": base += 2
  score_impact = min(base, 10)

  When skipped (email-only scan) or documents_found = 0: score_impact = 0.

Output model (MetadataResult):
  {
    "skipped": false,
    "skip_reason": null,
    "documents_found": 3,
    "documents_scanned": 2,
    "findings": [
      { "url": "https://example.com/report.pdf",
        "file_type": "pdf",
        "metadata": { "Author": "John Doe", "Creator": "Microsoft Word 2019" },
        "risk_notes": ["Author name exposed: John Doe"],
        "severity": "MEDIUM" }
    ],
    "unique_authors": ["John Doe"],
    "internal_software": ["Microsoft Word 2019"],
    "score_impact": 8  # max 10 — computed by formula above                 ← v22
  }

──────────────────────────────────────────
MODULE 10: Exposure Scoring Engine
File: modules/exposure_scorer.py
──────────────────────────────────────────

Category weights (total = 100 points maximum, additive, capped at 100):

  Credential leaks (HIBP):              30 pts max
  GitHub secrets found:                 25 pts max
  JS file secrets found:                20 pts max
  Paste site exposure:                  15 pts max
  Social footprint size:                10 pts max
  Email intelligence (MX/SMTP/SPF):     5 pts max
  DNS / Email Auth (SPF+DMARC+DKIM):   20 pts max   ← single entry, from dns_email_auth.py
  Document metadata leaks:             10 pts max
  Google dork risk (DDG hits):          5 pts max

  Note: weights sum to 140 but the score is always capped at 100.
        dns_email_auth.py produces one score_impact value (max 20) fed into this table.

SCORER LOGIC — read carefully:
  exposure_scorer.py collects the score_impact value already returned by each module
  in its Pydantic result object and sums them directly. It does NOT re-apply the
  weight table independently. The weight table above is the contract each module
  must honour when computing its own score_impact — it is NOT a multiplier applied
  by the scorer. Final score = min(sum(all score_impact values), 100).

Score to label (use SEVERITY_LABELS from constants.py):                      ← v22
  0–15:   MINIMAL EXPOSURE
  16–30:  LOW EXPOSURE
  31–50:  MODERATE EXPOSURE
  51–70:  HIGH EXPOSURE
  71–100: CRITICAL EXPOSURE

FINDING ID SCHEME — use FINDING_PREFIXES from constants.py:                  ← v22
  CRED-001, CRED-002 ...  → credential_leak module
  GH-001, GH-002    ...  → github_footprint module
  EMAIL-001         ...  → email_intel module
  SOC-001           ...  → social_footprint module
  PASTE-001         ...  → paste_monitor module
  JS-001, JS-002    ...  → js_secret_scanner module
  DNS-001           ...  → dns_email_auth module
  META-001          ...  → metadata_extractor module
  DORK-001          ...  → google_dorks module

  Counter resets per module (each module starts at 001).
  Format strictly: {PREFIX}-{counter:03d}

Per-finding output structure:
  {
    "id": "CRED-001",
    "module": "credential_leak",
    "category": "Credential Leak",
    "title": "Email found in 4 public data breaches",
    "risk": "CRITICAL",
    "score_impact": 30,
    "data_classes": ["Passwords", "Email addresses"],
    "recommendation": "Change all passwords for breached accounts immediately and enable 2FA.",
    "references": ["https://haveibeenpwned.com/"]
  }

═══════════════════════════════════════════════════════════
SECTION 4: CLI INTERFACE
═══════════════════════════════════════════════════════════

Use `click` for CLI argument parsing and `rich` for all terminal display    ← v22
(banners, spinners, tables, prompts). These are complementary, not          ← v22
competing — click handles argument definitions and validation, rich         ← v22
handles visual output.                                                      ← v22

Accept these arguments (at least one of --email or --domain required):

  --email     target@example.com    Email to investigate
  --domain    example.com           Domain to investigate
  --free-hibp                       Skip HIBP mode prompt, use Free mode directly
  --demo-mode                       Skip HIBP mode prompt, use Demo mode (fixture data)
  --skip-pastes                     Skip paste monitor module
  --modules   dns,github,js         Run specific modules only
                                    Valid short names and their module file mappings:
                                      creds    → credential_leak.py
                                      github   → github_footprint.py
                                      email    → email_intel.py
                                      social   → social_footprint.py
                                      pastes   → paste_monitor.py
                                      metadata → metadata_extractor.py
                                      dorks    → google_dorks.py
                                      js       → js_secret_scanner.py
                                      dns      → dns_email_auth.py
                                    Unknown names → log WARNING and skip.
                                    paste_monitor always runs if creds runs (dependency).
                                    --skip-pastes overrides this dependency rule even
                                    when creds is included in --modules.
                                    When --modules is used, batch sequencing is bypassed —
                                    only the specified modules run, always after core/
                                    foundation is initialized (config, logger, rate_limiter).
  --output    html,json,md          Select output formats (default: all)
  --no-graph                        Skip exposure graph generation
  --config    path/to/config.yaml   Use custom config file

Usage examples:
  python main.py --email target@example.com
  python main.py --domain example.com
  python main.py --email cto@startup.com --domain startup.com
  python main.py --email user@example.com --free-hibp
  python main.py --email user@example.com --demo-mode
  python main.py --domain example.com --modules github,js,dns
  python main.py --email user@example.com --domain example.com --output html,json
  python main.py --domain example.com --no-graph

Rich terminal features:
  - ASCII banner on startup: tool name, version, "Passive OSINT | Ethical | Non-Destructive"
  - HIBP mode prompt (if applicable) using Rich prompt, not plain input()
  - Per-module progress spinner with live status text
  - Color coding: GREEN = clean, YELLOW = warning, RED = risk, CYAN = info
  - Summary table on completion:
      Module | Findings | Severity | Score Impact
  - Final score displayed prominently with label
  - Total elapsed time shown at end

Resilience rules (apply to every module):
  - Missing API key → skip module, log WARNING, never crash
  - Network timeout → log WARNING with module name, never crash
  - Unexpected exception → log ERROR with traceback, never crash
  - All modules must complete even if some fail

─ AIOHTTP SESSION LIFECYCLE ──────────────────────────

CRITICAL: Create exactly ONE shared aiohttp.ClientSession in main.py.
Pass it as a parameter to every module function that makes HTTP calls.
Close it in a finally block after all modules and report generation complete.

  async def main():
      session = aiohttp.ClientSession(
          headers={"User-Agent": USER_AGENT}     # from constants.py        ← v22
      )
      try:
          results = await run_all_modules(session, ...)
          await generate_reports(results, ...)
      finally:
          await session.close()

NEVER create a new ClientSession inside a module function.
This ensures the asyncio.Semaphore(max_concurrent_requests) defined below
correctly controls ALL outbound HTTP across ALL modules simultaneously.
Creating per-call sessions bypasses the semaphore and causes
ResourceWarning: Unclosed client session at teardown.

─ CONCURRENCY MODEL ──────────────────────────────────

Use a single asyncio.Semaphore(max_concurrent_requests) shared across all
outbound HTTP calls to enforce the config.yaml max_concurrent_requests limit.
Pass both session and semaphore to all module functions.

Runtime execution map — implement in this exact order:

  Runtime Batch 1 (sequential):
    credential_leak  → runs first, result passed directly to paste_monitor
    paste_monitor    → runs immediately after credential_leak, NOT in gather()

  Runtime Batch 2 (concurrent via asyncio.gather()):
    github_footprint, email_intel, dns_email_auth

  Runtime Batch 3 (concurrent via asyncio.gather()):
    social_footprint, js_secret_scanner, metadata_extractor, google_dorks

  Runtime Batch 4 (sequential, after all above complete):
    exposure_scorer  → receives all results, computes final score

  Runtime Batch 5 (reporting, after scorer completes):
    await asyncio.gather(
        html_report.generate(...),
        json_report.generate(...),
        markdown_report.generate(...)
    )
    Then (sequential, after reports):
    await exposure_graph.generate(...)   ← only if --no-graph is not set

  Note: Runtime batches are execution order only. Build batches in Section 14
  are construction order for Copilot — do not confuse the two.

═══════════════════════════════════════════════════════════
SECTION 5: CONFIGURATION (config.yaml)
═══════════════════════════════════════════════════════════

general:
  output_dir: ./output
  log_level: INFO
  request_timeout: 15
  max_concurrent_requests: 3
  output_formats: [html, json, md]  # Default output formats. Overridden by --output flag.
                                    # config_loader.py must normalize this to a Python list
                                    # regardless of source: YAML list stays as-is;
                                    # CLI --output comma-string is split and stripped.
                                    # e.g. "html,json" → ["html", "json"]

api_keys:
  hibp: ""          # Required for Premium mode only. Paid subscription at haveibeenpwned.com/API/Key
                    # Free HIBP mode and Demo mode work without this key.
  github: ""        # Optional. Create free PAT at github.com/settings/tokens
                    # No scopes required for public repo reads.
                    # An unscoped PAT raises rate limit from 60 to 5000 req/hr.

modules:
  credential_leak: true
  github_footprint: true
  email_intel: true
  social_footprint: true
  paste_monitor: true
  metadata_extractor: true
  google_dorks: true
  js_secret_scanner: true
  dns_email_auth: true
  exposure_graph: true

rate_limits:
  hibp_delay: 1.5           # HIBP enforces 1 request per 1500ms — do not lower
  github_delay: 1.0         # GitHub API: 5000 req/hour with PAT
  social_check_delay: 0.5   # Per social platform check
  ddg_delay: 5.0            # DuckDuckGo HTML endpoint: 1 req per 5 seconds
  dns_concurrent: 5         # Max concurrent DNS lookups for DKIM probing      ← v22

scan_limits:
  max_github_repos: 10      # Max repos to scan for secrets
  max_github_files: 5       # Max successfully fetched files per repo
  max_workflow_files: 3     # Max .github/workflows/ yml files scanned per repo
  max_js_files: 10          # Max JS files per domain
  max_docs_to_fetch: 5      # Max documents for metadata extraction
  max_social_platforms: 15  # Max social platform existence checks
  max_dork_live_checks: 3   # Max DuckDuckGo live dork checks per run

═══════════════════════════════════════════════════════════
SECTION 6: REPORT SPECIFICATIONS                                ← v22 (title expanded)
═══════════════════════════════════════════════════════════

──────────────────────────────────────────                       ← v22
6A: HTML REPORT — VISUAL QUALITY SPEC                            ← v22
──────────────────────────────────────────                       ← v22

Design tokens (consistent with attack-surface-toolkit v1 for brand continuity):
  --bg:       #0d1117
  --card:     #161b22
  --accent:   #58a6ff
  --text:     #c9d1d9
  --muted:    #8b949e
  --high:     #ff4d4f
  --medium:   #f39c12
  --low:      #1f6feb
  --pass:     #2ecc71
  --border:   #30363d
  --critical: #ff0000

Fonts: Inter (body) + JetBrains Mono (code/values) via Google Fonts CDN.
Standalone HTML — no other external dependencies except fonts.

Report header:
  - "DIGITAL EXPOSURE REPORT" as main title (large, prominent)
  - Target (email + domain) clearly shown below title
  - Assessment date + tool version
  - "Passive OSINT | Authorized Assessment" badge strip

Fixed sidebar navigation (12 sections):
  1. Executive Summary
  2. Credential Leaks
  3. GitHub Exposure
  4. Email Intelligence
  5. Social Footprint
  6. Paste Site Exposure
  7. JS File Secrets
  8. Email Authentication
  9. Document Metadata
  10. Google Dork Recipe
  11. Risk Summary & Recommendations
  12. Appendix

Executive Summary section:
  a) Large animated exposure gauge (conic-gradient, same as v1 but larger: 220px)
  b) 4-card stats grid (styled metric cards):
       Credential Breaches: N       (Free mode: shows "—  Free mode" in muted text)
       GitHub Secrets Found: N      (shows 0 or "Skipped" if no key)
       Social Profiles Exposed: N / checked
       Email Spoofability: X/10     (shows "—" if domain-only scan)
  c) Severity breakdown — pure CSS horizontal bars with counts:
       CRITICAL ██████████ N
       HIGH     ████       N
       MEDIUM   ██         N
       LOW      █          N
       INFO     ▌          N

Credential Leaks section:
  - In Free mode: render the full interactive breach database table
    (search + multi-filter + pagination as specified in Module 1)
  - In Premium mode (live or demo): render per-email breach table
    Columns: Breach Name | Date | Records | Data Classes | Verified | Severity
    Show demo mode banner (yellow warning card) when in demo mode
  - RED alert banner if "Passwords" found in any breach DataClasses

GitHub Exposure section:
  - If skipped: show "GitHub scan skipped — no API key configured" note
  - Repos table: Name | Language | Stars | Last Pushed | Active | Risk
  - Secrets table: Repo | File | Secret Type | Masked Value | Severity
  - CRITICAL red banner if any secrets detected

Social Footprint section:
  - Platform grid: badge per platform
    EXPOSED = green badge | NOT_FOUND = gray badge | UNKNOWN = yellow badge
  - Username variants tried shown below the grid
  - Separate positive signals: HackerOne / Bugcrowd badges marked as
    "Security Researcher" with a note (not counted as risk)

Email Authentication section:
  - SPF / DMARC / DKIM status table with pass/fail/partial indicators
  - Spoofability score displayed as a colored badge (0–3 green, 4–6 yellow, 7–10 red)
  - MTA-STS presence noted

All tables: sortable with vanilla JS (no jQuery, no external libraries).
All filters in the breach table: vanilla JS only.
Pagination: vanilla JS only.

Print-to-PDF CSS: @media print with clean white background and no sidebar.

Report footer:
  "This report was generated passively using publicly available data sources.
   No unauthorized access was performed. Assessment conducted by Sagar Biswas.
   Contact: eng.sagarbiswas.aiub@gmail.com | sagarbiswas-multihat.github.io"

Use Jinja2 for templating (reporting/templates/report.html.jinja).

The following context dict is passed to the template by html_report.py:
  {
    "target_email":     str | None,
    "target_domain":    str | None,
    "generated_at":     str,          # ISO 8601 datetime string
    "tool_version":     str,          # e.g. "1.0.0"
    "hibp_mode":        str,          # "free" | "demo" | "live"
    "score":            int,          # final capped exposure score 0–100
    "score_label":      str,          # e.g. "HIGH EXPOSURE"
    "credential_leak":  CredentialLeakResult,
    "github":           GitHubFootprintResult,
    "email_intel":      EmailIntelResult,
    "social":           SocialFootprintResult,
    "pastes":           PasteResult,
    "js_secrets":       JSSecretResult,
    "dns_auth":         EmailAuthResult,
    "metadata":         MetadataResult,
    "dorks":            list[DorkResult],
    "findings":         list[dict],   # per-finding output structures from exposure_scorer
  }

──────────────────────────────────────────                       ← v22 NEW BLOCK
6B: JSON REPORT
File: reporting/json_report.py
──────────────────────────────────────────

Serialize the exact same context dict passed to the HTML template (listed
above in Section 6A) into a single JSON file.

Structure:
  {
    "meta": {
      "tool_name": "osint-exposure-toolkit",
      "tool_version": "1.0.0",
      "generated_at": "2026-01-01T12:00:00Z",
      "target_email": "target@example.com",
      "target_domain": "example.com",
      "hibp_mode": "demo"
    },
    "score": 72,
    "score_label": "CRITICAL EXPOSURE",
    "credential_leak": { ... CredentialLeakResult.model_dump(mode="json") },
    "github": { ... GitHubFootprintResult.model_dump(mode="json") },
    "email_intel": { ... EmailIntelResult.model_dump(mode="json") },
    "social": { ... SocialFootprintResult.model_dump(mode="json") },
    "pastes": { ... PasteResult.model_dump(mode="json") },
    "js_secrets": { ... JSSecretResult.model_dump(mode="json") },
    "dns_auth": { ... EmailAuthResult.model_dump(mode="json") },
    "metadata": { ... MetadataResult.model_dump(mode="json") },
    "dorks": [ ... list of DorkResult.model_dump(mode="json") ],
    "findings": [ ... per-finding structures from exposure_scorer ]
  }

Use Pydantic's .model_dump(mode="json") for each result object to ensure
all datetime, enum, and Path values are serialized correctly.
Write to {output_dir}/report.json using aiofiles.
Output must be valid JSON (json.dumps with indent=2, ensure_ascii=False).

──────────────────────────────────────────                       ← v22 NEW BLOCK
6C: MARKDOWN REPORT
File: reporting/markdown_report.py
──────────────────────────────────────────

Generate a human-readable Markdown document suitable for inclusion in
Git repositories, Notion pages, or email summaries.

Structure:

  # Digital Exposure Report

  **Target:** target@example.com / example.com
  **Date:** 2026-01-01 12:00 UTC
  **Tool:** osint-exposure-toolkit v1.0.0
  **Mode:** Demo (fixture data)

  ## Executive Summary

  - **Exposure Score:** 72 / 100 — CRITICAL EXPOSURE
  - **Credential Breaches:** 4
  - **GitHub Secrets:** 3
  - **Social Profiles Exposed:** 6
  - **Email Spoofability:** 8 / 10

  ## Credential Leaks

  | Breach Name | Date       | Records     | Data Classes              | Severity |
  |-------------|------------|-------------|---------------------------|----------|
  | LinkedIn    | 2012-05-05 | 164,611,595 | Email addresses, Passwords| CRITICAL |
  ...

  ## GitHub Exposure

  (Repos table + Secrets table in Markdown format)

  ## Email Intelligence

  (Key-value pairs: provider, disposable status, SMTP result, SPF)

  ## Social Footprint

  (Platform status table)

  ## Paste Site Exposure

  (Paste table or "Requires Premium HIBP mode" message)

  ## JS File Secrets

  (Findings table or "Skipped" message)

  ## Email Authentication

  (SPF / DMARC / DKIM / MTA-STS status + spoofability score)

  ## Document Metadata

  (Findings table or "Skipped" message)

  ## Google Dork Queries

  (Each category as a subsection with queries in fenced code blocks)

  ## Findings Summary

  | ID       | Category         | Risk     | Score Impact | Recommendation |
  |----------|------------------|----------|--------------|----------------|
  | CRED-001 | Credential Leak  | CRITICAL | 30           | Change all ... |
  ...

  ## Recommendations

  (Top 5 prioritized action items based on highest-scoring findings)

  ---
  *Generated by osint-exposure-toolkit v1.0.0 — Passive OSINT assessment.*

Use Markdown tables for all tabular data. Format numbers with commas.
Write to {output_dir}/report.md using aiofiles.

═══════════════════════════════════════════════════════════
SECTION 7: EXPOSURE GRAPH
═══════════════════════════════════════════════════════════

File: graph/exposure_graph.py
Output: exposure_graph.html (standalone, no external deps)
Library: networkx + pyvis

Node types (color-coded):
  TARGET (email/domain)  → large blue node, center
  BREACH                 → red node (size scales with PwnCount)
  SECRET FOUND           → large red node
  SOCIAL PROFILE         → teal node (EXPOSED) / gray (NOT_FOUND)
  PASTE                  → yellow node
  DOCUMENT               → gray node
  GITHUB REPO            → orange node
  DNS RECORD             → purple node

Edges with relationship labels:
  Target → Breach:         "found in breach"
  Target → GitHub Repo:    "maintains"
  GitHub Repo → Secret:    "exposes secret"
  Target → Social Profile: "profile found"
  Target → Paste:          "appeared in paste"
  Target → Document:       "document metadata"

Hover tooltips: type, name, risk level, date.
Node size scales with score_impact from that finding.
Physics simulation: Barnes-Hut enabled.
Standalone HTML, zero external dependencies.
Instantiate PyVis with: Network(cdn_resources='in_line', notebook=False)
This embeds vis.js directly into the HTML file — required for true offline/standalone
output. Without this, PyVis loads vis-network.min.js from a CDN and silently breaks
in air-gapped or offline demo environments.

═══════════════════════════════════════════════════════════
SECTION 8: LIBRARIES (requirements.txt)
═══════════════════════════════════════════════════════════

aiohttp>=3.9.0
dnspython>=2.4.0
beautifulsoup4>=4.12.0
lxml>=5.0.0
rich>=13.7.0
jinja2>=3.1.0
networkx>=3.2.0
pyvis>=0.3.2
pydantic>=2.5.0
pyyaml>=6.0.0
click>=8.1.0
aiofiles>=23.2.0
pypdf>=3.0.0
python-docx>=1.1.0
pytest>=7.4.0
pytest-asyncio>=0.23.0
ruff>=0.3.0

stdlib only (no pip install needed):
  smtplib, hashlib, re, asyncio, urllib.parse, json, pathlib, datetime

aiofiles usage: used exclusively in the reporting layer (html_report.py,
json_report.py, markdown_report.py) for async file writes to the output
directory. Do NOT use aiofiles inside any module under modules/.

═══════════════════════════════════════════════════════════
SECTION 9: TESTING
═══════════════════════════════════════════════════════════

─ CONFTEST.PY — SHARED FIXTURES ─────────────────────

Create tests/conftest.py with the following shared fixtures available
to ALL test files. Do NOT duplicate these fixtures in individual test files.

  import pytest
  import json
  from pathlib import Path
  from unittest.mock import AsyncMock, MagicMock
  from core.config_loader import AppConfig

  @pytest.fixture
  def mock_config() -> AppConfig:
      """Minimal valid AppConfig for all tests. Uses empty API keys (demo/skip mode)."""
      return AppConfig(
          general={"output_dir": "./output", "log_level": "INFO",
                   "request_timeout": 15, "max_concurrent_requests": 3,
                   "output_formats": ["html", "json", "md"]},
          api_keys={"hibp": "", "github": ""},
          modules={m: True for m in [
              "credential_leak", "github_footprint", "email_intel",
              "social_footprint", "paste_monitor", "metadata_extractor",
              "google_dorks", "js_secret_scanner", "dns_email_auth", "exposure_graph"
          ]},
          rate_limits={"hibp_delay": 1.5, "github_delay": 1.0,
                       "social_check_delay": 0.5, "ddg_delay": 5.0, "dns_concurrent": 5},
          scan_limits={"max_github_repos": 10, "max_github_files": 5,
                       "max_workflow_files": 3, "max_js_files": 10,
                       "max_docs_to_fetch": 5, "max_social_platforms": 15,
                       "max_dork_live_checks": 3}
      )

  @pytest.fixture
  def hibp_fixture_data() -> dict:
      """Loads tests/fixtures/hibp_mock.json. Used wherever HIBP responses are mocked."""
      fixture_path = Path(__file__).parent / "fixtures" / "hibp_mock.json"
      with open(fixture_path) as f:
          return json.load(f)

  @pytest.fixture
  def mock_aiohttp_session():
      """
      Returns a MagicMock that mimics aiohttp.ClientSession.
      Use as: session.get.return_value.__aenter__.return_value.json = AsyncMock(return_value=data)
      Individual tests customize the return values they need.
      """
      session = MagicMock()
      session.get = MagicMock()
      session.head = MagicMock()
      return session

  @pytest.fixture                                                            ← v22
  def mock_all_results():                                                    ← v22
      """                                                                    ← v22
      Returns a dict of default/empty Pydantic result models for all 9      ← v22
      data-collection modules + scorer. Used by test_reports.py to render   ← v22
      reports without running real modules.                                  ← v22
      Import all result models from core.models and instantiate with        ← v22
      skipped=True or minimal valid data and score_impact=0.                ← v22
      """                                                                    ← v22
      # Implementation: import all result models from core.models            ← v22
      # and return a dict keyed by the template context variable names       ← v22
      # (credential_leak, github, email_intel, social, pastes, js_secrets,  ← v22
      #  dns_auth, metadata, dorks, findings, score, score_label, etc.)     ← v22
      ...                                                                    ← v22

─ PYTEST-ASYNCIO DECORATOR RULE ─────────────────────

asyncio_mode = "auto" is set in pyproject.toml.
DO NOT add @pytest.mark.asyncio decorators to any async test functions.
The auto mode handles all async tests automatically.
Adding @pytest.mark.asyncio in auto mode causes deprecation warnings
and may trigger errors in future pytest-asyncio versions.

─ FIXTURE FILE ───────────────────────────────────────

tests/fixtures/hibp_mock.json:
  Must be created with exact HIBP API v3 field names.
  Contains: 4 breaches (LinkedIn, Adobe, Dropbox, MySpace) + 2 pastes.
  Used by all tests that mock HIBP responses.

─ TEST SPECIFICATIONS ────────────────────────────────

test_credential_leak.py:
  - Free mode: mock /api/v3/breaches response → assert summary stats correct
  - Demo mode: load fixture → assert 4 breaches, severity CRITICAL
  - Live mode (mocked): assert per-email endpoint called with correct header
  - Severity classification: "Passwords" in DataClasses → CRITICAL
  - Empty response → total_breaches = 0, score_impact = 0
  - No HIBP key in config → mode falls back to demo automatically

test_github_footprint.py:
  - Empty github key in config → skipped = True, no crash
  - Mock repos API with 5 repos → assert correct repo count
  - Secret pattern: provide string with AWS key → assert AKIA match, masked correctly
  - Masking: "AKIAIOSFODNN7EXAMPLE" → "AKIA***MPLE"
  - Email filter: name containing "@" → excluded from results

test_email_intel.py:
  - Mock DNS MX lookup → assert mail_provider detected correctly
  - "mailinator.com" → is_disposable = True
  - "not-an-email" → format_valid = False
  - SMTP ConnectionRefusedError → smtp_verified = "UNKNOWN", no crash
  - SMTP timeout → smtp_verified = "UNKNOWN", logged as WARNING

test_exposure_scorer.py:
  - Zero findings input → score = 0, label = "MINIMAL EXPOSURE"
  - Max findings from all modules → score capped at 100
  - Credential breach CRITICAL + github secrets → score >= 50

test_config_loader.py:
  - Valid config.yaml → loads without error
  - Missing api_keys section → uses defaults (empty strings)
  - Unknown field in config → ignored, no crash

test_social_footprint.py:
  - Mock HTTP HEAD returning 200 for GitHub URL → status = "EXPOSED"
  - Mock HTTP HEAD returning 404 → status = "NOT_FOUND"
  - Mock HTTP HEAD returning 429 → status = "UNKNOWN", no crash
  - Mock HTTP HEAD returning 999 (LinkedIn) → status = "UNKNOWN", no crash,
    logged at INFO level (not WARNING)
  - Username variant generation: "john.doe" → assert all 4 variants produced
  - HackerOne 200 response → is_positive_signal = True, not counted in risk score
  - Gravatar MD5 hash: lowercased email → correct md5 hex digest in URL
  - score_impact = 0 when no platforms found

test_paste_monitor.py:
  - Premium mode with 2 pastes from fixture → total_pastes = 2, mode = "premium"
  - Free mode → total_pastes = 0, mode = "free", report message set correctly
  - Demo mode (fixture) → pastes extracted correctly from CredentialLeakResult
  - score_impact = 0 when mode = "free"
  - No independent API calls made (assert aiohttp.ClientSession never called)

test_js_secret_scanner.py:
  - Email-only scan (no domain) → skipped = True, no crash
  - Mock homepage HTML with 2 script tags → assert 2 JS URLs extracted
  - Mock JS content containing AWS key pattern → assert match detected, value masked
  - Mock JS content containing internal IP 192.168.1.1 → assert finding recorded
  - JS file larger than 500KB → skipped with log WARNING, not scanned
  - Non-200 response for JS file → skipped silently, scan continues

test_metadata_extractor.py:
  - Email-only scan (no domain) → skipped = True, skip_reason set, no crash
  - Mock PDF with Author metadata "John Doe" → finding severity = "MEDIUM"
  - Mock DOCX with last_modified_by set → risk_notes contains author name
  - Mock sitemap.xml with 3 PDF URLs → documents_found = 3
  - PDF fetch returns non-200 → documents_scanned count not incremented
  - score_impact = 0 when documents_found = 0

test_dns_email_auth.py:
  - Domain with no SPF TXT record → spf.present = False, spoofability += 4
  - Domain with "+all" SPF → strength = "OPEN", HIGH risk flag set
  - DMARC present with policy=none → dmarc.policy = "none", LOW label
  - DMARC missing entirely → spoofability += 3
  - All three (SPF, DMARC, DKIM) absent → spoofability_score = 10 directly
  - All three present and strict → spoofability_score = 0
  - DKIM selector found with RSA key < 2048 bits → MEDIUM risk flag
  - MTA-STS fetch returns 200 with "enforce" → mta_sts.mode = "enforce"
  - DNS timeout on any lookup → log WARNING, return partial result, no crash
  - score_impact = spoofability_score * 2 (assert 8*2=16, 10*2=20, 0*2=0)

test_google_dorks.py:
  - Domain provided → assert all 6 dork categories generated with correct query strings
  - No --email provided → category c email-specific dork omitted, domain dorks present
  - DDG returns 200 with result hints → ddg_result = "RESULTS_FOUND"
  - DDG returns 429 → skip silently, ddg_result = "NOT_CHECKED", log WARNING, no crash
  - 2 consecutive DDG blocks → DDG disabled for remainder of run, all remaining = "NOT_CHECKED"
  - score_impact = 0 when all ddg_results = "NOT_CHECKED" or "NO_RESULTS"
  - score_impact = 3 when 3 categories return "RESULTS_FOUND"
  - score_impact never exceeds 5 regardless of hits

test_reports.py:                                                             ← v22 NEW BLOCK
  Smoke tests for all three report generators and the exposure graph.
  Uses mock_all_results fixture from conftest.py.
  - HTML report: render with mock data → assert output file exists,
    file size > 0, contains "DIGITAL EXPOSURE REPORT" string,
    contains each sidebar section name
  - JSON report: render with mock data → assert output file exists,
    json.loads(content) succeeds without error, top-level "meta" key present,
    "score" key present and is int
  - Markdown report: render with mock data → assert output file exists,
    file starts with "# Digital Exposure Report",
    contains "## Executive Summary" and "## Findings Summary"
  - Exposure graph: render with mock data → assert output file exists,
    file size > 0, contains "<html" (valid HTML output)
  - All reporters: use tmp_path fixture for output directory (pytest built-in)
  - No real API calls, no real filesystem pollution

All tests: python -m pytest tests/ -v → 100% pass
All code: ruff check . → All checks passed

pyproject.toml lint config:
  [tool.ruff]
  line-length = 100
  target-version = "py311"

  [tool.ruff.lint]
  select = ["E", "F", "I", "W", "B", "UP", "ASYNC"]
  ignore = [
      "E501",     # line too long
      "ASYNC109", # timeout parameter style
      "ASYNC240", # pathlib in async (not using trio/anyio)
  ]

  [tool.pytest.ini_options]
  asyncio_mode = "auto"
  testpaths = ["tests"]

═══════════════════════════════════════════════════════════
SECTION 10: GITHUB ACTIONS CI
═══════════════════════════════════════════════════════════

File: .github/workflows/ci.yml

name: lint-and-test

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}
      - run: pip install --upgrade pip
      - run: pip install -r requirements.txt
      - run: ruff check .
      - run: python -m pytest tests/ -v

This CI must achieve the green checkmark on GitHub Actions.
Use actions/checkout@v4, actions/setup-python@v5, actions/cache@v4 only.
No deprecated action versions.

═══════════════════════════════════════════════════════════
SECTION 11: DOCKER SUPPORT
═══════════════════════════════════════════════════════════

Dockerfile:
  FROM python:3.11-slim
  RUN useradd -m osint
  WORKDIR /app
  COPY requirements.txt .
  RUN pip install --no-cache-dir -r requirements.txt
  COPY . .
  RUN chown -R osint:osint /app
  USER osint
  VOLUME ["/app/output", "/app/config.yaml"]
  ENTRYPOINT ["python", "main.py"]

docker-compose.yml:
  services:
    osint:
      build: .
      volumes:
        - ./output:/app/output
        - ./config.yaml:/app/config.yaml
      command: ["--email", "target@example.com", "--domain", "example.com", "--free-hibp"]
      # Use --free-hibp or --demo-mode to skip the interactive HIBP prompt.
      # Docker does not allocate a TTY by default — omitting a mode flag will hang.

.dockerignore:
  Create this file to prevent sensitive and unnecessary data from
  entering the Docker build context:

  output/
  .git/
  .github/
  __pycache__/
  **/__pycache__/
  *.pyc
  *.pyo
  *.pyd
  .env
  .env.*
  *.log
  .pytest_cache/
  .ruff_cache/
  dist/
  build/
  *.egg-info/

  # Exclude any scan reports from previous runs
  # (output/ is already listed above — belt-and-suspenders)
  output/**

  REASON: This is a security tool. Previous scan results (output/) may
  contain real target data. The .git/ directory may contain secrets in
  commit history. Neither should be bundled into Docker images.

═══════════════════════════════════════════════════════════
SECTION 12: README.md SPECIFICATION
═══════════════════════════════════════════════════════════

Rewrite README.md completely. Human voice throughout — senior security
engineer explaining to a peer. No robotic AI phrasing, no bullet walls.
Mix prose paragraphs with structured sections.

Sections (in order):
  1. Tool name as H1 + badges: Python 3.11 | MIT | CI Status
  2. One-line description
  3. What This Is (2 paragraphs: purpose + context)
  4. How It Differs from attack-surface-toolkit v1 (brief comparison table)
  5. HIBP Scan Modes (Free / Premium / Demo — explain all three clearly)
  6. Features (all 10 modules with brief descriptions — 9 data-collection modules + 1 scoring engine)
  7. Report Outputs (describe all 4 deliverable files)
  8. Architecture (ASCII diagram + brief explanation)
  9. Installation: venv + Docker + Docker Compose
  10. Usage (all CLI examples with one-line use-case descriptions)
  11. Configuration (full config.yaml with inline comments)
  12. Sample Output (small findings table)
  13. Running Tests
  14. Ethical Use Statement (prominent, professional, 2–3 sentences)
  15. License: MIT
  16. Author / Portfolio Note

═══════════════════════════════════════════════════════════
SECTION 13: CODE STANDARDS
═══════════════════════════════════════════════════════════

Apply all of the following without exception:

  - Type hints on ALL functions and methods
  - Docstrings on all classes and all public methods
  - Pydantic v2 models with ConfigDict(use_enum_values=True) on all
    models that contain enum fields (prevents SubdomainStatus.LIVE bugs)
  - No hardcoded values in modules — all constants in constants.py           ← v22
    (see Section 3 core/constants.py for the exhaustive list)                ← v22
  - Async/await throughout — use aiohttp for all HTTP, not requests
  - All module functions: proper exception handling with specific types
  - Timeout or network failure → log WARNING, return empty/default result, never crash
  - Logging at INFO/WARNING/ERROR levels — never use print() in modules
  - Secret values: ALWAYS mask as first4***last4 in all outputs
  - No God classes — single responsibility per module
  - All enum fields: use_enum_values=True in Pydantic ConfigDict
  - smtplib for SMTP checks (stdlib, no pip install needed)
  - dnspython for all DNS lookups
  - All modules return a typed Pydantic model even when skipped
    (skipped=True with empty data, not None)
  - All module async functions accept (session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore, config: AppConfig, ...) as parameters.
    Never instantiate ClientSession inside a module.
  - All __init__.py files: leave empty (pass only). Do not add re-exports,  ← v22
    __all__ lists, or wildcard imports. Modules are imported directly        ← v22
    by path (e.g. from modules.credential_leak import run).                 ← v22
  - All aiohttp requests must include the USER_AGENT header from            ← v22
    constants.py. This is set once on the shared ClientSession in main.py   ← v22
    via default_headers — individual modules do NOT need to add it           ← v22
    per-request. However, if a module creates a one-off request with        ← v22
    custom headers, it must include USER_AGENT explicitly.                   ← v22

DO NOT use:
  - requests (use aiohttp)
  - aiosmtplib (use stdlib smtplib)
  - subprocess for external tools
  - Bing Search API
  - IntelX API
  - LeakCheck.io
  - Any exploit or active-attack frameworks
  - Selenium or browser automation
  - Any paid API without a documented free tier

═══════════════════════════════════════════════════════════
SECTION 14: IMPLEMENTATION ORDER
═══════════════════════════════════════════════════════════

Implement in this exact order. Complete each batch before starting the next.

BATCH 1 — Foundation:
  core/constants.py          # ALL constants enumerated in Section 3        ← v22
  core/models.py (all Pydantic models for all 10 modules)
  core/config_loader.py
  core/logger.py
  core/rate_limiter.py       # AsyncRateLimiter class per Section 3         ← v22
  config.yaml
  requirements.txt
  pyproject.toml
  .github/workflows/ci.yml
  .dockerignore
  tests/conftest.py
  tests/fixtures/hibp_mock.json

BATCH 2 — High-value OSINT modules (build in this order):
  modules/credential_leak.py    (Free + Premium + Demo modes)
  modules/github_footprint.py   (with secret scanning)
  modules/email_intel.py        (dnspython + smtplib)
  modules/dns_email_auth.py     (full SPF/DMARC/DKIM/MTA-STS)

BATCH 3 — Enrichment modules:
  modules/social_footprint.py
  modules/paste_monitor.py      (thin wrapper over Module 1)
  modules/js_secret_scanner.py
  modules/metadata_extractor.py
  modules/google_dorks.py       (dork builder + optional DDG check)
  modules/exposure_scorer.py

BATCH 4 — Reporting and graph:
  reporting/json_report.py
  reporting/markdown_report.py
  reporting/html_report.py
  reporting/templates/report.html.jinja
  graph/exposure_graph.py

BATCH 5 — CLI, tests, Docker, README:
  main.py                       (full Click + Rich CLI with mode prompt     ← v22
                                 + shared session lifecycle)
  tests/test_credential_leak.py
  tests/test_github_footprint.py
  tests/test_email_intel.py
  tests/test_exposure_scorer.py
  tests/test_config_loader.py
  tests/test_social_footprint.py
  tests/test_paste_monitor.py
  tests/test_js_secret_scanner.py
  tests/test_metadata_extractor.py
  tests/test_dns_email_auth.py
  tests/test_google_dorks.py
  tests/test_reports.py          # Smoke tests for report generators        ← v22
  Dockerfile
  docker-compose.yml
  README.md

═══════════════════════════════════════════════════════════
SECTION 15: VALIDATION TARGETS
═══════════════════════════════════════════════════════════

After full implementation, the following commands must pass:

  ruff check .                        → All checks passed
  python -m pytest tests/ -v          → All tests pass (including test_reports.py)  ← v22
  python main.py --email test@example.com --domain example.com --demo-mode
                                      → Runs without exception
  python main.py --email test@example.com --free-hibp
                                      → Free mode runs, breach table generated

Expected HTML report behavior:
  - Opens in browser with dark theme
  - Sidebar navigation works
  - Exposure gauge animates
  - All stats visible in executive summary
  - Breach table in Free mode: search + filter + pagination all functional
  - Demo mode banner visible in Premium sections when applicable
  - All tables sortable
  - Print-to-PDF clean layout

Expected JSON report behavior:                                              ← v22
  - Valid JSON (parseable by any JSON tool)                                  ← v22
  - Contains "meta" top-level key with tool_version and generated_at        ← v22
  - All module result keys present                                          ← v22

Expected Markdown report behavior:                                          ← v22
  - Clean Markdown (renders correctly on GitHub)                             ← v22
  - All sections present with proper headings                                ← v22
  - Tables render correctly in GitHub/VS Code Markdown preview               ← v22

Expected CLI behavior:
  - Rich banner on startup
  - Mode prompt appears correctly (or skipped by flag)
  - Modules with missing keys show WARNING and skip (not crash)
  - Summary table rendered on completion
  - No ResourceWarning: Unclosed client session in output

═══════════════════════════════════════════════════════════
SECTION 16: QUALITY BAR
═══════════════════════════════════════════════════════════

This project is a Fiverr portfolio piece targeting $30–80 per order.
Every output must justify that price point visually and technically.

The client is a startup CTO opening the HTML report on a laptop in a meeting.
The report must be impressive at first glance and professional under scrutiny.
Every module must fail gracefully without alarming error output.
The CLI must feel like a polished security tool, not a student script.

Think like a freelance security consultant who charges for this deliverable.
Build it to that standard from the first line of code.

═══════════════════════════════════════════════════════════
SECTION 17: COPILOT CLARIFICATIONS
═══════════════════════════════════════════════════════════

These are precise behavioral rules to resolve ambiguities Copilot commonly
gets wrong on projects of this complexity. Apply every rule unconditionally.

─ RULE 1: ONE SHARED AIOHTTP SESSION ────────────────

There is exactly ONE aiohttp.ClientSession for the entire run.
It is created in main.py before any module executes.
It is configured with default_headers={"User-Agent": USER_AGENT}.           ← v22
It is passed as a parameter into every module function.
It is closed in a finally block in main.py after reports are written.
This is non-negotiable. Any module that creates its own ClientSession is wrong.

─ RULE 2: NO @pytest.mark.asyncio DECORATORS ────────

asyncio_mode = "auto" is set in pyproject.toml.
Do NOT add @pytest.mark.asyncio to any test function.
Auto mode handles all async tests. Adding the decorator causes
deprecation warnings and version-dependent test failures.

─ RULE 3: CONFTEST.PY IS THE ONLY SOURCE OF SHARED FIXTURES ──

tests/conftest.py defines mock_config, hibp_fixture_data, mock_aiohttp_session,
and mock_all_results.                                                        ← v22
No test file may redefine these fixtures locally.
If a test needs additional fixtures, it may define them locally in that
test file only — never duplicate a conftest fixture.

─ RULE 4: LINKEDIN RETURNS 999, NOT 4XX ─────────────

LinkedIn responds with HTTP status code 999 for automated requests.
This is not an error. Handle 999 exactly like 403:
  status = "UNKNOWN", log at INFO level, do not crash, do not raise.
The test for this case is in test_social_footprint.py.

─ RULE 5: FINDING IDs ARE DETERMINISTIC ─────────────

Finding IDs follow the exact scheme in Module 10 (Section 3):
  Prefix: CRED, GH, EMAIL, SOC, PASTE, JS, DNS, META, DORK
  Format: {PREFIX}-{counter:03d}
  Counter resets to 001 per module, per run.
Do not invent alternative prefixes or formats.
Use FINDING_PREFIXES from constants.py as the source of truth.               ← v22

─ RULE 6: REPORT GENERATION IS AWAITED IN BATCH 5 ──

After exposure_scorer completes, reports are generated with:
  await asyncio.gather(html_report.generate(...), json_report.generate(...),
                       markdown_report.generate(...))
  if not args.no_graph:
      await exposure_graph.generate(...)

Report generation is NOT fire-and-forget. NOT synchronous.
All three reporters run concurrently. The graph runs after them.

─ RULE 7: .DOCKERIGNORE IS MANDATORY ────────────────

.dockerignore must exist in the project root before the Dockerfile is built.
It must exclude at minimum: output/, .git/, __pycache__/, *.pyc, .env, *.log
See Section 11 for the full required contents.

─ RULE 8: SESSION AND SEMAPHORE SIGNATURES ──────────

Every async module function that makes HTTP calls must have this signature shape:
  async def run(
      session: aiohttp.ClientSession,
      semaphore: asyncio.Semaphore,
      config: AppConfig,
      ...module-specific params...
  ) -> ModuleResultModel:

The semaphore is acquired with:
  async with semaphore:
      async with session.get(url, ...) as response:
          ...

This is the only way the max_concurrent_requests limit works correctly.

─ RULE 9: SKIPPED MODULES RETURN TYPED MODELS ───────

When a module is skipped (missing key, wrong scan type, etc.) it MUST return
its full Pydantic result model with skipped=True and score_impact=0.
It must NEVER return None, raise an exception, or skip assignment.
The orchestrator in main.py always expects a typed result, not None.

─ RULE 10: RUFF ASYNC RULES COMPLIANCE ──────────────

The ruff config selects the "ASYNC" ruleset.
Specifically:
  - Use asyncio.get_running_loop() not asyncio.get_event_loop() (deprecated)
  - Never call blocking I/O (smtplib, file reads) directly inside async def
    without run_in_executor
  - Never use time.sleep() inside async code — use asyncio.sleep()
These will be flagged as ASYNC violations and will fail ruff check.

─ RULE 11: CONSTANTS.PY IS THE SINGLE SOURCE OF TRUTH ──     ← v22 NEW RULE

All regex patterns, platform URLs, DKIM selectors, disposable domain lists,
dork templates, severity labels, finding prefixes, and the User-Agent string
are defined ONLY in core/constants.py.

No module may define its own copy of any value that exists in constants.py.
Import from constants.py — never duplicate.

If a value appears in both a module file and constants.py, the module file
is wrong. Delete it and import from constants.py.

─ RULE 12: __init__.py FILES ARE EMPTY ──────────────     ← v22 NEW RULE

All __init__.py files in core/, modules/, reporting/, and graph/ contain
only an empty file or a single `pass` statement.

Do not add:
  - from .module import *
  - __all__ = [...]
  - Any re-export logic

Modules are imported by their full dotted path:
  from modules.credential_leak import run
  from core.constants import SECRET_PATTERNS

─ RULE 13: CLICK FOR PARSING, RICH FOR DISPLAY ─────     ← v22 NEW RULE

Use the `click` library for all CLI argument parsing (decorators, options,
flags, validation, help text).

Use the `rich` library for all terminal display (Console, Panel, Table,
Spinner, Prompt, progress bars, color output).

These two libraries are complementary:
  - click handles: @click.command(), @click.option(), argument types, --help
  - rich handles: console.print(), Live(), Table(), Prompt.ask()

Do NOT use argparse. Do NOT use click.echo() for styled output — use
rich.console.Console().print() instead.

─ RULE 14: SCORE_IMPACT FORMULAS ARE EXPLICIT ───────     ← v22 NEW RULE

Every module has an explicit score_impact formula documented in Section 3.
Do not invent alternative formulas. Do not use vague "proportional" logic.
Implement the exact formula as specified:

  credential_leak:   base = min(total_breaches * 5, 20); severity bonus; cap 30
  github_footprint:  base = min(secret_count * 5, 15); severity bonus; cap 25
  email_intel:       0 / 1 / 3 / 5 depending on disposable/verified/other
  social_footprint:  min(exposure_count * 1, 10)
  paste_monitor:     15 if pastes > 0 AND premium mode; else 0
  js_secret_scanner: base = min(secrets * 5, 15); endpoint/env bonus; cap 20
  dns_email_auth:    spoofability_score * 2; cap 20
  metadata_extractor:base = min(authors * 3, 6); software/severity bonus; cap 10
  google_dorks:      min(categories_with_hits, 5)

If a formula is ambiguous, re-read the Module specification in Section 3.
The Section 3 formula is authoritative.