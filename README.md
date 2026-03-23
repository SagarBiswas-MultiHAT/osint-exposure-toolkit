# osint-exposure-toolkit

![Python](https://img.shields.io/badge/Python-3.11-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![CI](https://img.shields.io/badge/CI-lint%20and%20test-brightgreen)

Passive OSINT toolkit for measuring digital exposure from public internet signals.

## What This Is

`osint-exposure-toolkit` is a consultant-grade reconnaissance companion focused on exposure visibility, not exploitation. It aggregates breach intelligence, repository leakage signals, social footprint indicators, DNS email-auth posture, metadata leakage, and search-index exposure into one consolidated risk report.

This project is designed as a pre-engagement deliverable: something you can hand to a startup CTO before a pentest to show what adversaries can already infer from public data sources.

## How It Differs from attack-surface-toolkit v1

| Toolkit | Primary question | Output |
|---|---|---|
| attack-surface-toolkit v1 | What internet-facing infrastructure exists? | Surface map |
| osint-exposure-toolkit v2 | How exposed is the org/person across public data? | Digital Exposure Report |

## HIBP Scan Modes

- **Free**: Pulls global breach landscape (`/breaches`) without per-email lookup.
- **Premium**: Uses HIBP API key for per-email breach + paste checks.
- **Demo**: Uses local fixture data (`tests/fixtures/hibp_mock.json`) for deterministic runs.

## Features

1. Credential leak detection (HIBP Free/Premium/Demo)
2. GitHub footprint and secret pattern scanning
3. Email intelligence (format, MX, provider, SPF, SMTP VRFY)
4. Social footprint profile checks
5. Paste-site exposure formatter
6. JavaScript public secret scanner
7. DNS email-auth analysis (SPF/DMARC/DKIM/MTA-STS)
8. Google dork recipe with optional DDG checks
9. Document metadata extraction
10. Exposure scoring engine and finding normalization

## Report Outputs

Each scan writes a timestamped output folder containing:

- `report.html`
- `report.json`
- `report.md`
- `exposure_graph.html`

## Architecture

```text
main.py
 ├─ core/ (config, models, constants, logging, rate limiter)
 ├─ modules/ (10 module pipeline)
 ├─ reporting/ (html/json/markdown)
 └─ graph/ (network visualization)
```

## Installation

### Local (venv)

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

## Usage

```bash
python main.py --email target@example.com
python main.py --domain example.com
python main.py --email cto@startup.com --domain startup.com
python main.py --email user@example.com --free-hibp
python main.py --email user@example.com --demo-mode
python main.py --domain example.com --modules github,js,dns
python main.py --email user@example.com --domain example.com --output html,json
python main.py --domain example.com --no-graph
```

## Configuration

See `config.yaml` for API keys, module toggles, rate limits, scan limits, and output defaults.

## Sample Output

| ID | Category | Risk | Score Impact | Recommendation |
|---|---|---|---:|---|
| CRED-001 | Credential Leak | CRITICAL | 30 | Rotate exposed credentials and enforce MFA |

## Running Tests

```bash
ruff check .
python -m pytest tests/ -v
```

## Ethical Use Statement

This toolkit performs passive and non-destructive OSINT checks only. Use it only for authorized assessments on assets and identities you own or are explicitly permitted to evaluate. The project is intended for defensive security posture assessment.

## License

MIT

## Author / Portfolio Note

Built by Sagar Biswas as a professional security consulting deliverable for digital exposure audits.
