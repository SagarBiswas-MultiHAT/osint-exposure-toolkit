# osint-exposure-toolkit

![Python](https://img.shields.io/badge/Python-3.11-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![CI](https://img.shields.io/badge/CI-lint%20and%20test-brightgreen)

Passive, ethical OSINT toolkit that answers one practical question: **how exposed is this target right now on the public internet?**

---

## What This Project Is

`osint-exposure-toolkit` is a portfolio-grade security assessment tool designed for consultants and engineering teams who want a client-ready exposure report before a pentest starts.

The toolkit does not perform exploitation, brute-force attempts, payload injection, or unauthorized access. It gathers and correlates publicly available signals (credential leaks, public code exposure, DNS/email posture, social presence, indexed content, and Shodan intelligence) into one structured score and report pack.

If you hand this report to a startup CTO, they should immediately understand:
- what is currently exposed,
- why it matters,
- what to fix first.

---

## How It Differs from attack-surface-toolkit v1

| Toolkit | Core Question | Output |
|---|---|---|
| attack-surface-toolkit v1 | What internet-facing infrastructure exists? | Attack surface map |
| osint-exposure-toolkit v2 | How exposed is this person/org across open data sources? | Digital Exposure Report |

---

## Credential Engines (Important)

This project now supports **two credential leak engines**.

### 1) LeakCheck (Default)
- This is the default path when you provide `--email`.
- Uses authenticated API mode when `api_keys.leakcheck` is set.
- Falls back to public mode when no key is present or key is invalid.

### 2) HIBP (Opt-in)
- Enabled only when you explicitly pass one of:
  - `--use-hibp`
  - `--free-hibp`
  - `--demo-mode`

HIBP sub-modes:
- **Free**: breach landscape only, no per-email check
- **Premium**: per-email breach + paste lookup
- **Demo**: local fixture-backed Premium-style output

---

## Module Map (11 Modules)

1. **Credential Leak Detection** (LeakCheck default, HIBP optional)
2. **GitHub Footprint & Secret Pattern Scan**
3. **Email Intelligence** (format, MX, provider, SPF, SMTP VRFY)
4. **Social Footprint Discovery**
5. **Paste Monitor** (wrapper over credential module)
6. **Public JavaScript Secret Scanner**
7. **DNS Email Auth Analysis** (SPF/DMARC/DKIM/MTA-STS)
8. **Google Dork Builder + optional DDG checks**
9. **Document Metadata Extraction**
10. **Exposure Scoring Engine**
11. **Shodan Recon** (passive host/service/port/CVE intelligence)

---

## Output Artifacts

Each run creates a timestamped directory under `output/target_YYYY-MM-DD_HH-MM/` containing:

- `report.html` — polished client-facing report with interactive sections
- `report.json` — machine-readable full payload
- `report.md` — concise human-readable text report
- `exposure_graph.html` — network visualization of exposure relationships

---

## Architecture Overview

```text
main.py
 ├─ core/
 │   ├─ constants.py
 │   ├─ config_loader.py
 │   ├─ logger.py
 │   ├─ rate_limiter.py
 │   └─ models.py
 ├─ modules/
 │   ├─ credential_leak.py
 │   ├─ github_footprint.py
 │   ├─ email_intel.py
 │   ├─ social_footprint.py
 │   ├─ paste_monitor.py
 │   ├─ js_secret_scanner.py
 │   ├─ dns_email_auth.py
 │   ├─ google_dorks.py
 │   ├─ metadata_extractor.py
 │   ├─ exposure_scorer.py
 │   └─ shodan_recon.py
 ├─ reporting/
 │   ├─ html_report.py
 │   ├─ json_report.py
 │   ├─ markdown_report.py
 │   └─ templates/report.html.jinja
 ├─ graph/exposure_graph.py
 └─ tests/
```

---

## Installation

### Local (recommended)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Docker

```bash
docker build -t osint-exposure-toolkit .
docker run --rm -v $(pwd)/output:/app/output osint-exposure-toolkit --domain example.com --demo-mode
```

### Docker Compose

```bash
docker compose up --build
```

---

## Configuration (`config.yaml`)

At minimum, review these sections before running:

- `api_keys`: optional keys for LeakCheck, HIBP, GitHub, and Shodan
- `modules`: enable/disable modules without touching code
- `rate_limits`: per-source pacing (important for API stability)
- `scan_limits`: hard caps to prevent runaway scans

Tip: Keep API keys out of Git history. Use local config or environment workflows in deployment.

---

## Usage (Comprehensive)

### A) Quick start

```bash
# Default credential engine (LeakCheck), email-only target
python main.py --email user@example.com

# Domain-only target (runs domain-capable modules)
python main.py --domain example.com

# Full target context (recommended)
python main.py --email cto@example.com --domain example.com
```

### B) Credential engine control

```bash
# LeakCheck is default (same as no engine flags)
python main.py --email user@example.com

# Force HIBP path and choose Free/Premium interactively
python main.py --email user@example.com --use-hibp

# Force HIBP Free immediately
python main.py --email user@example.com --free-hibp

# Force HIBP Demo immediately
python main.py --email user@example.com --demo-mode

# Invalid combination (expected error)
python main.py --email user@example.com --use-hibp --free-hibp
```

### C) Select specific modules

Available aliases for `--modules`:
- `cred`, `github`, `email`, `social`, `pastes`, `js`, `dns`, `metadata`, `dorks`, `shodan`

```bash
# Run only GitHub + JS + DNS
python main.py --domain example.com --modules github,js,dns

# Run Shodan only
python main.py --domain example.com --modules shodan

# Credential + scoring-relevant web modules
python main.py --email user@example.com --domain example.com --modules cred,github,js,dorks,shodan
```

### D) Output control

```bash
# Generate only HTML + JSON
python main.py --email user@example.com --domain example.com --output html,json

# Disable graph generation
python main.py --email user@example.com --domain example.com --no-graph

# Custom config file path
python main.py --email user@example.com --config ./config.yaml
```

### E) Useful validation runs

```bash
# Full smoke path (demo)
python main.py --email test@example.com --domain example.com --demo-mode

# HIBP free-mode behavior check
python main.py --email test@example.com --free-hibp

# LeakCheck default behavior check
python main.py --email test@example.com --domain example.com
```

---

## What to Expect in the Report

- **Executive Summary** with exposure score + severity label
- **Credential Leaks** section with engine badge (LeakCheck or HIBP mode)
- **Shodan Recon** section for host/service/port/CVE view (domain runs)
- **Risk Summary** with normalized finding IDs and remediation guidance

---

## Testing & Quality Gates

```bash
ruff check .
python -m pytest tests/ -v
```

Recommended before every release:
1. `ruff` clean
2. full `pytest` pass
3. at least one end-to-end CLI run with report generation

---

## Ethical Use Statement

This tool is strictly for passive, authorized security assessments. Use it only on targets you own or are contractually permitted to evaluate. No active exploitation logic is included, and no unauthorized access is performed.

---

## License

MIT

---

## Author / Portfolio Note

Built by Sagar Biswas as a practical consultant-facing digital exposure assessment deliverable.
