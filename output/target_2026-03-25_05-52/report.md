# Digital Exposure Report

**Target:** security@shopify.com / shopify.com
**Date:** 2026-03-25 05:54 UTC
**Tool:** osint-exposure-toolkit v1.0.0
**Credential Engine:** HIBP (Demo)

## Executive Summary

- **Exposure Score:** 63 / 100 — HIGH EXPOSURE
- **Credential Leaks:** 4
- **GitHub Secrets:** 0
- **Social Profiles Exposed:** 5
- **Email Spoofability:** 2 / 10
- **Shodan Open Ports:** 13

## Credential Leaks

| Breach Name | Date | Records | Data Classes | Severity |
|---|---|---:|---|---|
| LinkedIn | 2012-05-05 | 164,611,595 | Email addresses, Passwords | CRITICAL |
| Adobe | 2013-10-04 | 153,000,000 | Email addresses, Password hints, Usernames | HIGH |
| Dropbox | 2012-07-01 | 68,648,009 | Email addresses, Passwords | CRITICAL |
| MySpace | 2008-06-11 | 359,420,698 | Email addresses, Passwords, Usernames | CRITICAL |

## GitHub Exposure

- **Repositories Scanned:** 10
- **Secret Findings:** 0

## Email Intelligence

- **Provider:** Google Workspace
- **Disposable:** False
- **SMTP:** VERIFIED
- **SPF:** True

## Social Footprint

| Platform | Status | Positive Signal |
|---|---|---|
| GitHub | EXPOSED | No |
| GitLab | EXPOSED | No |
| NPM | UNKNOWN | No |
| PyPI | UNKNOWN | No |
| Docker Hub | NOT_FOUND | No |
| HackerOne | EXPOSED | Yes |
| Bugcrowd | EXPOSED | Yes |
| LinkedIn | UNKNOWN | No |
| Dev.to | EXPOSED | No |
| Twitter/X | UNKNOWN | No |
| Medium | UNKNOWN | No |
| HackerNews | EXPOSED | No |
| Keybase | EXPOSED | No |
| Gravatar | NOT_FOUND | No |

## Paste Site Exposure

- **Mode:** premium
- **Total Pastes:** 2

## JS File Secrets

- **JS Files Scanned:** 0
- **Findings:** 0

## Email Authentication


- **SPF Present:** True
- **DMARC Present:** True
- **DKIM Selectors:** 2
- **MTA-STS:** False
- **Spoofability:** 2 / 10

## Document Metadata

- **Documents Found:** 0
- **Findings:** 0

## Google Dork Queries

### Credential & Token Exposure

```text
site:pastebin.com "security@shopify.com"
site:github.com "security@shopify.com" (password OR "api key" OR token)
site:github.com "shopify.com" (password OR secret OR api_key OR access_token)
site:gitlab.com "shopify.com" (password OR secret OR token)
site:stackoverflow.com "security@shopify.com" "api key"
```

### Exposed Configs & Env Files

```text
site:shopify.com (filetype:env OR inurl:.env)
site:shopify.com (filetype:yaml OR filetype:yml) (password OR token OR secret)
site:shopify.com (filetype:json OR filetype:ini) (apikey OR auth OR credential)
site:github.com "shopify.com" filename:.env
site:github.com "shopify.com" (filename:config.yml OR filename:settings.py) (secret OR token)
```

### Backups & Archives

```text
site:shopify.com (ext:bak OR ext:old OR ext:backup OR ext:tmp)
site:shopify.com (ext:zip OR ext:tar OR ext:gz OR ext:7z) (backup OR database)
site:shopify.com intitle:"index of" (backup OR dump OR archive)
site:shopify.com (inurl:backup OR inurl:backups OR inurl:dump)
```

### Cloud Storage & Buckets

```text
site:s3.amazonaws.com "shopify.com"
site:s3.amazonaws.com "security@shopify.com"
site:blob.core.windows.net "shopify.com"
site:storage.googleapis.com "shopify.com"
site:digitaloceanspaces.com "shopify.com"
```

### Admin & Management Surfaces

```text
site:shopify.com (inurl:admin OR inurl:login OR inurl:dashboard)
site:shopify.com (inurl:wp-admin OR inurl:phpmyadmin OR inurl:cpanel)
site:shopify.com (inurl:jenkins OR inurl:grafana OR inurl:kibana)
site:shopify.com (inurl:swagger OR inurl:api-docs OR inurl:redoc)
```

### Error, Debug & Log Leakage

```text
site:shopify.com ("SQL syntax" OR "stack trace" OR "Traceback")
site:shopify.com ("Exception" OR "Unhandled" OR "Fatal error")
site:shopify.com "Index of /" (inurl:logs OR inurl:debug)
site:shopify.com (filetype:log OR filetype:txt) (error OR exception OR warning)
```

### Documents & Sensitive Terms

```text
site:shopify.com (ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:csv)
site:shopify.com filetype:pdf ("confidential" OR "internal use" OR "do not distribute")
site:shopify.com ("private key" OR "internal only" OR "restricted") filetype:pdf
site:shopify.com filetype:xlsx (salary OR payroll OR invoice)
```

### CI/CD & DevOps Exposure

```text
site:shopify.com (.gitlab-ci.yml OR Jenkinsfile OR docker-compose.yml)
site:github.com "shopify.com" ("workflow" OR "actions") (secret OR token)
site:shopify.com (inurl:.git OR inurl:.svn)
site:shopify.com ("npmrc" OR "pypirc" OR "pip.conf") (token OR password)
```

## Shodan Recon

Shodan found 13 open ports across 1 IPs.

| IP | Ports | CVEs | Severity |
|---|---|---|---|
| 23.227.38.33 | 80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880 | — | MEDIUM |

## Findings Summary

| ID | Category | Risk | Score Impact | Recommendation |
|---|---|---|---:|---|
| CRED-001 | Credential Leak | CRITICAL | 30 | Reset passwords and enforce MFA for all affected accounts. |
| EMAIL-001 | Email Intelligence | LOW | 3 | Use monitored inboxes, anti-abuse rules, and stricter onboarding controls. |
| SOC-001 | Social Footprint | MEDIUM | 5 | Review profile privacy and remove unnecessary public identifiers. |
| PASTE-001 | Paste Exposure | HIGH | 15 | Perform credential rotation and monitor paste sites continuously. |
| DNS-001 | Email Authentication | LOW | 4 | Enforce SPF -all, DMARC reject/quarantine, and operational DKIM selectors. |
| DORK-001 | Search Engine Exposure | LOW | 2 | Review indexed content and harden access/robots directives where appropriate. |
| SHODAN-001 | Host & Service Exposure | LOW | 4 | Restrict exposed management/database ports to private networks and review public service hardening. |

## Recommendations

1. Rotate exposed credentials and enforce MFA.
2. Harden SPF, DMARC, DKIM, and monitor spoofing.
3. Remove secret material from public repositories and JS assets.
4. Sanitize metadata from downloadable documents.
5. Review public profile visibility and search indexing footprints.

---
*Generated by osint-exposure-toolkit v1.0.0 — Passive OSINT assessment.*
