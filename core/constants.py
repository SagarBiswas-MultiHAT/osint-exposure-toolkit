"""Project-wide constants for the OSINT Exposure Toolkit.

All hardcoded values are centralized here and imported across modules.
"""

from __future__ import annotations

TOOL_NAME: str = "osint-exposure-toolkit"
TOOL_VERSION: str = "1.0.0"

USER_AGENT: str = (
    "Mozilla/5.0 (compatible; OSINT-Exposure-Toolkit/1.0; "
    "+https://github.com/sagarbiswas-multihat)"
)

SECRET_PATTERNS: dict[str, str] = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws(.{0,20})?(secret|access)?.{0,20}[=:]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36,255}",
    "Slack Token": r"xox[baprs]-[A-Za-z0-9-]{10,48}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret Key": r"sk_(live|test)_[0-9a-zA-Z]{24,}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Private Key Block": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}",
    "Password Assignment": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "Database URL": r"(?i)(postgres|mysql|mongodb|redis)(\+srv)?://[^\s'\"]+",
    "OAuth Client Secret": r"(?i)(client_secret|oauth_secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Bearer Token": r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "Generic token": r"(token|auth_token|access_token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
}

JS_EXTRA_PATTERNS: dict[str, str] = {
    "Internal IP": r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\b",
    "Internal Path Hint": r"(?i)\b(?:/admin|/internal|/debug|/staging|/private)\b",
    "Commented Credential": r"(?i)//\s*(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+",
    "Environment Flag": r"(?i)\b(?:NODE_ENV|ENVIRONMENT|APP_ENV)\s*[=:]\s*['\"]?(dev|staging|prod|production|test)['\"]?",
}

DISPOSABLE_DOMAINS: list[str] = [
    "mailinator.com",
    "guerrillamail.com",
    "temp-mail.org",
    "throwaway.email",
    "10minutemail.com",
    "10minutemail.net",
    "yopmail.com",
    "getnada.com",
    "maildrop.cc",
    "trashmail.com",
    "tempmailo.com",
    "dispostable.com",
    "tempail.com",
    "mintemail.com",
    "fakeinbox.com",
    "spamgourmet.com",
    "mailnesia.com",
    "mytemp.email",
    "moakt.com",
    "mailcatch.com",
    "temp-mail.io",
    "emailondeck.com",
    "spambox.us",
    "mytrashmail.com",
    "mail-temporaire.fr",
    "sharklasers.com",
    "guerrillamailblock.com",
    "guerrillamail.info",
    "grr.la",
    "pokemail.net",
    "spam4.me",
    "bccto.me",
    "dropmail.me",
    "mohmal.com",
    "mail7.io",
    "fakemail.net",
    "mailforspam.com",
    "mailmetrash.com",
    "incognitomail.org",
    "tmpmail.org",
    "tempr.email",
    "temporarymail.com",
    "anonymbox.com",
    "mailnull.com",
    "trashmail.net",
    "mailimate.com",
    "awaymail.com",
    "guerrillamail.net",
    "guerrillamail.biz",
    "spamex.com",
]

SOCIAL_PLATFORMS: dict[str, str] = {
    "GitHub": "https://github.com/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "NPM": "https://www.npmjs.com/~{username}",
    "PyPI": "https://pypi.org/user/{username}/",
    "Docker Hub": "https://hub.docker.com/u/{username}",
    "HackerOne": "https://hackerone.com/{username}",
    "Bugcrowd": "https://bugcrowd.com/{username}",
    "LinkedIn": "https://www.linkedin.com/in/{username}",
    "Dev.to": "https://dev.to/{username}",
    "Twitter/X": "https://x.com/{username}",
    "Medium": "https://medium.com/@{username}",
    "HackerNews": "https://news.ycombinator.com/user?id={username}",
    "Keybase": "https://keybase.io/{username}",
}

POSITIVE_SIGNAL_PLATFORMS: list[str] = ["HackerOne", "Bugcrowd"]

DKIM_SELECTORS: list[str] = [
    "default",
    "google",
    "k1",
    "mail",
    "smtp",
    "selector1",
    "selector2",
    "dkim",
    "email",
    "s1",
    "s2",
    "mxvault",
    "protonmail",
]

MAIL_PROVIDERS: dict[str, str] = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "hotmail.com": "Microsoft 365",
    "microsoft.com": "Microsoft 365",
    "zoho.com": "Zoho Mail",
    "protonmail.com": "ProtonMail",
    "proton.me": "ProtonMail",
}

DORK_TEMPLATES: dict[str, list[str]] = {
    "File Exposure": [
        "site:{domain} (ext:pdf OR ext:doc OR ext:xls OR ext:csv)",
        "site:{domain} filetype:pdf (\"confidential\" OR \"internal use\")",
    ],
    "Admin and Login Panels": [
        "site:{domain} (inurl:admin OR inurl:login OR inurl:dashboard)",
        "site:{domain} (inurl:wp-admin OR inurl:phpmyadmin OR inurl:cpanel)",
    ],
    "Credential Exposure": [
        "site:pastebin.com \"{email}\"",
        "site:github.com \"{domain}\" (password OR secret OR api_key)",
    ],
    "Error and Debug Exposure": [
        "site:{domain} (\"SQL syntax\" OR \"stack trace\" OR \"Traceback\")",
        "site:{domain} \"Index of /\" (inurl:backup OR inurl:logs)",
    ],
    "Cloud Storage Exposure": [
        "site:s3.amazonaws.com \"{domain}\"",
        "site:blob.core.windows.net \"{domain}\"",
    ],
    "Code Repository Exposure": [
        "site:github.com \"{domain}\" filename:.env",
        "site:github.com \"{domain}\" filename:config.yaml password",
    ],
}

SEVERITY_LABELS: dict[str, str] = {
    "0-15": "MINIMAL EXPOSURE",
    "16-30": "LOW EXPOSURE",
    "31-50": "MODERATE EXPOSURE",
    "51-70": "HIGH EXPOSURE",
    "71-100": "CRITICAL EXPOSURE",
}

FINDING_PREFIXES: dict[str, str] = {
    "credential_leak": "CRED",
    "github_footprint": "GH",
    "email_intel": "EMAIL",
    "social_footprint": "SOC",
    "paste_monitor": "PASTE",
    "js_secret_scanner": "JS",
    "dns_email_auth": "DNS",
    "metadata_extractor": "META",
    "google_dorks": "DORK",
}

CONFIG_FILES_TO_SCAN: list[str] = [
    ".env.example",
    ".env.sample",
    "config.py",
    "settings.py",
    "config.js",
    "application.yml",
    "docker-compose.yml",
    "Dockerfile",
    "README.md",
]

SPOOFABILITY_WEIGHTS: dict[str, int] = {
    "SPF_MISSING": 4,
    "SPF_WEAK": 2,
    "DMARC_MISSING": 3,
    "DMARC_NONE": 2,
    "DKIM_MISSING": 3,
}
