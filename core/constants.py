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

LEAKCHECK_AUTH_URL: str = "https://leakcheck.io/api/v2/query/{email}"
LEAKCHECK_PUBLIC_URL: str = "https://leakcheck.io/api/public?check={email}"

LEAKCHECK_PASSWORD_TYPES_CRITICAL: list[str] = [
    "plaintext",
    "password",
    "hash",
    "bcrypt",
    "md5",
    "sha1",
    "sha256",
]

LEAKCHECK_SEVERITY_FIELDS: dict[str, str] = {
    "password": "CRITICAL",
    "password_hint": "HIGH",
    "security_question": "HIGH",
    "phone": "MEDIUM",
    "address": "MEDIUM",
    "dob": "MEDIUM",
}

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
    "Credential & Token Exposure": [
        "site:pastebin.com \"{email}\"",
        "site:github.com \"{email}\" (password OR \"api key\" OR token)",
        "site:github.com \"{domain}\" (password OR secret OR api_key OR access_token)",
        "site:gitlab.com \"{domain}\" (password OR secret OR token)",
        "site:stackoverflow.com \"{email}\" \"api key\"",
    ],
    "Exposed Configs & Env Files": [
        "site:{domain} (filetype:env OR inurl:.env)",
        "site:{domain} (filetype:yaml OR filetype:yml) (password OR token OR secret)",
        "site:{domain} (filetype:json OR filetype:ini) (apikey OR auth OR credential)",
        "site:github.com \"{domain}\" filename:.env",
        "site:github.com \"{domain}\" (filename:config.yml OR filename:settings.py) (secret OR token)",
    ],
    "Backups & Archives": [
        "site:{domain} (ext:bak OR ext:old OR ext:backup OR ext:tmp)",
        "site:{domain} (ext:zip OR ext:tar OR ext:gz OR ext:7z) (backup OR database)",
        "site:{domain} intitle:\"index of\" (backup OR dump OR archive)",
        "site:{domain} (inurl:backup OR inurl:backups OR inurl:dump)",
    ],
    "Cloud Storage & Buckets": [
        "site:s3.amazonaws.com \"{domain}\"",
        "site:s3.amazonaws.com \"{email}\"",
        "site:blob.core.windows.net \"{domain}\"",
        "site:storage.googleapis.com \"{domain}\"",
        "site:digitaloceanspaces.com \"{domain}\"",
    ],
    "Admin & Management Surfaces": [
        "site:{domain} (inurl:admin OR inurl:login OR inurl:dashboard)",
        "site:{domain} (inurl:wp-admin OR inurl:phpmyadmin OR inurl:cpanel)",
        "site:{domain} (inurl:jenkins OR inurl:grafana OR inurl:kibana)",
        "site:{domain} (inurl:swagger OR inurl:api-docs OR inurl:redoc)",
    ],
    "Error, Debug & Log Leakage": [
        "site:{domain} (\"SQL syntax\" OR \"stack trace\" OR \"Traceback\")",
        "site:{domain} (\"Exception\" OR \"Unhandled\" OR \"Fatal error\")",
        "site:{domain} \"Index of /\" (inurl:logs OR inurl:debug)",
        "site:{domain} (filetype:log OR filetype:txt) (error OR exception OR warning)",
    ],
    "Documents & Sensitive Terms": [
        "site:{domain} (ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:csv)",
        "site:{domain} filetype:pdf (\"confidential\" OR \"internal use\" OR \"do not distribute\")",
        "site:{domain} (\"private key\" OR \"internal only\" OR \"restricted\") filetype:pdf",
        "site:{domain} filetype:xlsx (salary OR payroll OR invoice)",
    ],
    "CI/CD & DevOps Exposure": [
        "site:{domain} (.gitlab-ci.yml OR Jenkinsfile OR docker-compose.yml)",
        "site:github.com \"{domain}\" (\"workflow\" OR \"actions\") (secret OR token)",
        "site:{domain} (inurl:.git OR inurl:.svn)",
        "site:{domain} (\"npmrc\" OR \"pypirc\" OR \"pip.conf\") (token OR password)",
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
    "shodan_recon": "SHODAN",
}

SHODAN_HOST_URL: str = "https://api.shodan.io/shodan/host/{ip}"

SHODAN_CRITICAL_PORTS: list[int] = [3306, 5432, 27017, 6379, 9200, 5984]

SHODAN_HIGH_PORTS: list[int] = [21, 23, 445, 135, 139, 512, 513, 514]

SHODAN_MEDIUM_PORTS: list[int] = [8080, 8443, 8888]

SHODAN_ADMIN_TITLES: list[str] = [
    "phpMyAdmin",
    "Kibana",
    "Grafana",
    "Jenkins",
    "Jupyter",
    "Portainer",
    "RabbitMQ",
]

SHODAN_LEGACY_PROTOCOLS: list[int] = [21, 23, 512, 513, 514]

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
