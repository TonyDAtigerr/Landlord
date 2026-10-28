#!/usr/bin/env python3
"""
bscope - a zero-dependency triage dashboard for BBOT scan output.

Feed it a BBOT results file (output.csv, output.json, or output.ndjson) and it
serves a dark, searchable web UI that:

  * groups everything into a readable Findings view, prioritised by severity
  * explains each finding in plain English and suggests what a tester can DO next
    (with copy-paste recon/verification commands tailored to the host/port/url)
  * lets you triage each item (new / triaging / confirmed / false positive /
    not exploitable / reviewed / reported) with free-text notes - all persisted
    to a sidecar JSON file so your work survives restarts
  * shows the full attack surface (subdomains, ports, URLs, tech, emails...) in
    an Assets view, the GUI version of bbot_organizer
  * embeds a shotview-style screenshot gallery as its own tab

Usage:
    python3 bscope.py ~/.bbot/scans/<scan>/output.ndjson
    python3 bscope.py output.csv --shots ~/.bbot/scans/<scan>/gowitness/screenshots
    python3 bscope.py output.ndjson --port 8899
    python3 bscope.py output.csv --host 0.0.0.0        # expose on LAN (careful)

Triage state is saved next to the input as <input>.bscope.json unless you pass
--state. Stdlib only, Python 3.7+. Ctrl-C to stop.
"""

import argparse
import csv
import hashlib
import html
import ipaddress
import json
import os
import posixpath
import re
import socket
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# raise the CSV field cap - BBOT descriptions / http responses can be huge
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2 ** 31 - 1)

# --------------------------------------------------------------------------- #
#  Config: severities, statuses, screenshot handling
# --------------------------------------------------------------------------- #

SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
SEV_COLOR = {
    "critical": "#ff4d6d", "high": "#ff7b3d", "medium": "#ffc93c",
    "low": "#4a9eff", "info": "#8b98a9", "unknown": "#5c6b7e",
}

# triage workflow states (key, label, color). Keep in sync with the JS.
STATUSES = [
    {"key": "new",            "label": "New",            "color": "#5c6b7e"},
    {"key": "triaging",       "label": "Triaging",       "color": "#4a9eff"},
    {"key": "confirmed",      "label": "Confirmed vuln", "color": "#ff4d6d"},
    {"key": "false_positive", "label": "False positive", "color": "#6b7684"},
    {"key": "not_exploitable","label": "Not exploitable","color": "#ffc93c"},
    {"key": "reviewed",       "label": "Reviewed",       "color": "#38c172"},
    {"key": "reported",       "label": "Reported",       "color": "#a66bff"},
]
STATUS_KEYS = {s["key"] for s in STATUSES}

# lightweight review states for the Screenshots tab
SHOT_STATUSES = [
    {"key": "new",     "label": "Unmarked", "color": "#5c6b7e"},
    {"key": "viewed",  "label": "Viewed",   "color": "#38c172"},
    {"key": "revisit", "label": "Revisit",  "color": "#ff7b3d"},
]
SHOT_STATUS_KEYS = {s["key"] for s in SHOT_STATUSES}

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
MIME = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".webp": "image/webp", ".gif": "image/gif", ".bmp": "image/bmp",
}
WEB_EXTS = {"htm", "html", "php", "asp", "aspx", "ashx", "jsp", "jspx", "do",
            "action", "cgi", "pl", "py", "rb", "cfm", "shtml", "json", "xml",
            "txt", "js", "css"}

# Event types that belong in the "Findings" lane rather than "Assets".
FINDING_TYPES = {"VULNERABILITY", "FINDING"}

# Base interest level per event type (used when there's no explicit severity).
TYPE_INTEREST = {
    "VULNERABILITY": "high", "FINDING": "medium",
    "STORAGE_BUCKET": "medium", "SECRET": "high", "PASSWORD": "high",
    "HASHED_PASSWORD": "medium",
    "OPEN_TCP_PORT": "low", "URL": "info", "URL_UNVERIFIED": "info",
    "TECHNOLOGY": "info", "DNS_NAME": "info", "DNS_NAME_UNRESOLVED": "info",
    "IP_ADDRESS": "info", "EMAIL_ADDRESS": "low", "SOCIAL": "info",
    "CODE_REPOSITORY": "low", "WAF": "info", "HTTP_RESPONSE": "info",
    "PROTOCOL": "info", "ASN": "info", "AZURE_TENANT": "info",
}

# "Juicy" tokens - hosts/urls worth a closer look get auto-flagged with a star.
JUICY_PATTERNS = [
    (re.compile(r"(?<![a-z0-9])(dev|development|stage|staging|uat|qa|test|testing|sandbox|demo|beta|preprod|pre-prod)(?![a-z0-9])", re.I), "non-prod"),
    (re.compile(r"(?<![a-z0-9])(admin|manage|manager|console|portal|dashboard|backend|internal|intranet|corp|private|secure)(?![a-z0-9])", re.I), "admin/internal"),
    (re.compile(r"(?<![a-z0-9])(vpn|citrix|rdp|owa|exchange|webmail|cpanel|whm|plesk)(?![a-z0-9])", re.I), "remote-access"),
    (re.compile(r"(jenkins|gitlab|gitea|bitbucket|jira|confluence|grafana|kibana|prometheus|phpmyadmin|adminer|sonar|nexus|artifactory|rancher|kubernetes|k8s|consul|vault|airflow|jupyter|elastic)", re.I), "devops/app"),
    (re.compile(r"(\.git|\.env|\.svn|/actuator|/swagger|/api-docs|/graphql|/debug|/metrics|/server-status|backup|\.bak|\.old|\.sql|\.zip|wp-admin|wp-config|phpinfo)", re.I), "exposed-path"),
    (re.compile(r"(?<![a-z0-9])(api|auth|sso|oauth|login|signin|idp|saml)(?![a-z0-9])", re.I), "auth/api"),
    (re.compile(r"(?<![a-z0-9])(old|legacy|deprecated|archive)(?![a-z0-9])", re.I), "legacy"),
]


def juicy_tags(host, url):
    url_path = (url or "").split("?")[0].split("#")[0]   # ignore query/fragment noise
    blob = ((host or "") + " " + url_path).lower()
    tags = []
    for rx, label in JUICY_PATTERNS:
        if rx.search(blob) and label not in tags:
            tags.append(label)
    return tags


# --------------------------------------------------------------------------- #
#  Knowledge base: descriptions + "what a tester can do" playbooks
# --------------------------------------------------------------------------- #
# Each rule is (name, predicate(ev)->bool, description, playbook[list of str]).
# ev is a normalized dict: type, text (searchable blob), host, url, port,
# scheme, module, tags(list), severity.

def _has(ev, *words):
    t = ev["text"].lower()
    return any(w in t for w in words)


def _mod(ev, *names):
    """Match on the BBOT source module (exact-ish, substring-tolerant)."""
    m = (ev.get("module") or "").lower()
    return any(n in m for n in names)


def _tag(ev, *names):
    """Match on any of the event's tags."""
    tl = [str(t).lower() for t in ev.get("tags", [])]
    return any(n in t for t in tl for n in names)


def _nuclei_name(ev):
    """Pull the real template name/id out of a BBOT nuclei FINDING so the
    finding is titled by what it actually is ("Missing Cookie SameSite Strict")
    instead of a generic "Nuclei template match". BBOT formats the description
    as 'template: [<id>], name: [<name>] Extracted Data: [...]'."""
    blob = (ev.get("data_str", "") or "") + " " + (ev.get("desc", "") or "")
    m = re.search(r"name:\s*\[([^\]]+)\]", blob)
    if m:
        return re.sub(r"^Nuclei Vuln - ", "", m.group(1).strip())
    m = re.search(r"template:\s*\[([^\]]+)\]", blob)
    if m:
        return m.group(1).strip()
    return ""


def _nuclei_template_id(ev):
    """The nuclei template id (e.g. 'missing-cookie-samesite-strict') for a
    targeted re-run command. Falls back to empty when it can't be parsed."""
    blob = (ev.get("data_str", "") or "") + " " + (ev.get("desc", "") or "")
    m = re.search(r"template:\s*\[([^\]]+)\]", blob)
    return m.group(1).strip() if m else ""


RULES = [
    # --- module-keyed rules first: a BBOT module name is the least ambiguous
    #     signal, and these findings often carry no CVE/keyword text to match on.
    ("Vulnerable JavaScript library (retirejs)",
     lambda ev: _mod(ev, "retirejs") or _has(ev, "vulnerable javascript library"),
     "A JavaScript library loaded by this page is a version with publicly known "
     "vulnerabilities (flagged by Retire.js). BBOT hardcodes every retirejs finding "
     "to severity INFO regardless of real risk, so read the 'Severity:' and 'CVE(s):' "
     "text in the finding - a HIGH/CRITICAL retire.js entry is not informational.",
     ["Read the finding text for the library, version, advisory summary and CVE IDs; "
      "the true severity is the 'Severity:' value, not the INFO band shown here.",
      "Confirm the library is actually used (not dead/bundled code): load the page, "
      "check DevTools > Network/Sources for the script and whether the vulnerable sink is reached.",
      "Map each CVE/advisory to a PoC (Snyk, GitHub advisory, Exploit-DB, nuclei -tags cve); "
      "many retire.js hits are DOM-XSS or prototype pollution reachable from the page.",
      "Impact is reachability-driven: a vulnerable jQuery/Angular fed attacker-influenced "
      "input can be client-side XSS/RCE. Note the loading page (parent URL), not just the script URL."]),

    ("Known framework secret / signing key (badsecrets)",
     lambda ev: _mod(ev, "badsecrets") or _has(ev, "machine key", "machinekey", "viewstate",
                     "secret_key_base", "django secret", "known secret", "cryptographic"),
     "A hardcoded or publicly-known framework secret / signing key was detected "
     "(e.g. ASP.NET MachineKey / ViewState, Django SECRET_KEY, Flask session key, "
     "Rails secret_key_base, Express cookie secret, or a known Telerik/JWT key). These "
     "keys let an attacker forge data the server trusts - frequently a critical, not info, finding.",
     ["Identify which framework and key type the finding names - the exploit path differs per framework.",
      "ASP.NET ViewState / MachineKey: forge a malicious __VIEWSTATE with ysoserial.net for RCE.",
      "Django / Flask / Rails / Express: forge or decrypt session cookies for auth bypass / admin "
      "escalation (Flask: flask-unsign; Rails: the secret_key_base + Marshal/JWT).",
      "Report for immediate key rotation - a leaked signing key is exploitable until rotated."]),

    ("Telerik UI (deserialization / weak-key RCE)",
     lambda ev: _mod(ev, "telerik") or _has(ev, "telerik"),
     "A Telerik UI for ASP.NET component was detected; these are commonly vulnerable to "
     "insecure deserialization and cryptographic weaknesses that lead to RCE.",
     ["Probe the RadAsyncUpload / Telerik.Web.UI.DialogHandler.aspx endpoints and read the version.",
      "CVE-2017-11317 / CVE-2017-11357: known/weak encryption keys allow arbitrary file upload.",
      "CVE-2019-18935: insecure deserialization in RadAsyncUpload -> RCE; recover the key "
      "(often via badsecrets) then use the public PoC to upload a mixed-mode DLL.",
      "Confirmed cases are critical - capture a benign PoC (e.g. DNS callback) before command execution."]),

    ("AjaxPro deserialization (RCE)",
     lambda ev: _mod(ev, "ajaxpro") or _has(ev, "ajaxpro"),
     "AjaxPro endpoints were detected; this .NET library is vulnerable to insecure "
     "deserialization (CVE-2021-23758 and related) leading to remote code execution.",
     ["Confirm the AjaxPro handler path (e.g. /ajaxpro/) and the version in use.",
      "CVE-2021-23758: send a JSON payload with a dangerous .NET type to the AjaxPro "
      "converter endpoint to achieve RCE - authorised targets only.",
      "Prove it safely first (trigger an interactsh/DNS callback) before any command execution."]),

    ("DotNetNuke / DNN CMS",
     lambda ev: _mod(ev, "dotnetnuke") or _has(ev, "dotnetnuke", "dnn "),
     "A DotNetNuke (DNN) CMS instance was detected; older versions carry high-impact CVEs.",
     ["Fingerprint the exact version (/js/dnn.js, Default.aspx headers, /Install/InstallWizard.aspx).",
      "CVE-2017-9822 (DNNPersonalization cookie deserialization) -> RCE on 9.1.0 and earlier.",
      "Check for an exposed install/upgrade wizard (re-install takeover) and default host/admin creds."]),

    ("GraphQL introspection enabled",
     lambda ev: _mod(ev, "graphql_introspection") or _has(ev, "introspection", "graphql"),
     "A GraphQL endpoint has introspection enabled, exposing the full schema (types, "
     "queries, mutations) - a complete map of the API's attack surface.",
     ["Dump and browse the schema (GraphQL Voyager / InQL / graphql-cop) for sensitive "
      "queries and mutations (user lookup, password reset, admin ops).",
      "Test authorization on each sensitive field (IDOR / broken access control).",
      "Check alias/batching brute force and query-depth DoS, and field-level auth."]),

    ("Host header injection",
     lambda ev: _mod(ev, "host_header") or _has(ev, "host header", "x-forwarded-host"),
     "The application reflects or trusts an attacker-controlled Host (or X-Forwarded-Host) "
     "header, enabling password-reset poisoning, web-cache poisoning and routing-based SSRF.",
     ["Reproduce: resend with Host: evil.example (and X-Forwarded-Host) and see where it is "
      "reflected - links, redirects, absolute URLs.",
      "Password-reset poisoning: trigger a reset and check the email link uses your injected host.",
      "Cache poisoning: if a cacheable response reflects the header, confirm the cache key, then "
      "poison it for other users."]),

    ("NTLM endpoint - internal name disclosure",
     lambda ev: _mod(ev, "ntlm") or _has(ev, "ntlm"),
     "An endpoint accepts NTLM authentication and leaks internal names in its NTLM type-2 "
     "challenge - typically the NetBIOS/DNS domain and host name.",
     ["Decode the challenge for the internal domain and hostname: "
      "nmap --script http-ntlm-info -p<port> <host> (or a curl Type-1 Authorization header).",
      "Feed the internal domain/host into AD recon and your target naming model.",
      "Externally-exposed NTLM-over-HTTP (OWA/Autodiscover/RPC) is a password-spray surface - "
      "authorised, low-and-slow only."]),

    ("Interesting / reflected parameter",
     lambda ev: _mod(ev, "hunt", "reflected_parameters", "paramminer")
                or _has(ev, "reflected parameter", "interesting parameter", "hidden parameter"),
     "Parameters were flagged as interesting (names historically tied to a vuln class) or "
     "shown to reflect their value into the response - leads for manual testing, not confirmed bugs.",
     ["Match each parameter to its likely class: url/redirect -> open redirect/SSRF; "
      "file/path/template -> LFI/traversal/SSTI; id/user -> IDOR; q/search -> XSS/SQLi.",
      "For reflected params, test the reflection context (HTML / attribute / JS) for XSS and open redirect.",
      "Fuzz each parameter manually with class-appropriate payloads and capture a clean PoC."]),

    ("403 / WAF bypass",
     lambda ev: _mod(ev, "bypass403", "waf_bypass")
                or _has(ev, "403 bypass", "forbidden bypass", "waf bypass"),
     "A path that returned 403/401 (or was WAF-blocked) became reachable via a bypass "
     "technique (path / verb / header tampering), so an access-control or WAF rule can be evaded.",
     ["Reproduce the exact bypass shown (trailing / . // %2e, X-Original-URL / X-Rewrite-URL, "
      "verb change) and confirm you receive the protected content.",
      "Enumerate what the now-reachable endpoint exposes (admin, API, files) and chain from there.",
      "Report the specific bypass primitive and the restricted resource it unlocks."]),

    ("Exposed ASP.NET /bin assemblies",
     lambda ev: _mod(ev, "aspnet_bin") or _has(ev, "bin exposure", "aspnet_bin"),
     "The ASP.NET application's /bin directory (compiled .NET assemblies) is web-reachable, "
     "exposing the app's DLLs for download and reverse-engineering.",
     ["Download the exposed assemblies and decompile them (dnSpy / ILSpy) for source, "
      "connection strings, API keys and hardcoded secrets.",
      "Review the logic for auth bypasses, deserialization sinks and crypto keys you can reuse "
      "(pair with badsecrets).",
      "Flag the directory exposure itself as an information-disclosure finding."]),

    ("Self-hosted GitLab instance",
     lambda ev: _mod(ev, "gitlab") or _has(ev, "gitlab"),
     "A self-hosted GitLab instance was identified - a high-value target that often leaks "
     "source, CI/CD secrets and credentials.",
     ["Read the version (/help, /api/v4/version, HTTP headers) and map it to GitLab CVEs "
      "(e.g. CVE-2021-22205 unauthenticated RCE, plus account-takeover / path-traversal CVEs).",
      "Check whether open registration is enabled; enumerate public/internal projects and "
      "snippets for secrets.",
      "Look for exposed CI/CD variables and runner registration; never brute credentials unauthorised."]),

    ("Nuclei template match",
     lambda ev: _mod(ev, "nuclei"),
     "A Nuclei template matched on this asset. Severity and meaning come entirely from the "
     "template. Most info/low hits are fingerprinting - tech, CDN, WAF, TLS and DNS detection "
     "(e.g. 'microsoft/cdn/cloud' tags) - which is context, not a vulnerability. The real "
     "findings are the medium+ ones: CVEs, exposures and misconfigurations.",
     ["Triage by severity first: info/low nuclei matches are usually detection noise - "
      "uncheck 'info' (and 'low') in the severity bar and work the medium+ list. Mark the "
      "detection ones 'not exploitable' or 'reviewed' in bulk.",
      "For anything medium+, open the template id to see what it checked and its matcher "
      "(github.com/projectdiscovery/nuclei-templates).",
      "Re-run just that template to confirm and capture the request/response: "
      "nuclei -id <template-id> -u <url> -debug.",
      "If it maps to a CVE, pull a PoC and assess real impact and reachability before "
      "reporting; rule out a false match from the matcher."]),

    # --- specific vulnerability classes (most actionable, least ambiguous) ---
    ("Subdomain takeover",
     lambda ev: _mod(ev, "baddns") or _has(ev, "takeover", "dangling", "can be taken over", "unclaimed"),
     "A DNS record points at a de-provisioned third-party service, so an attacker "
     "can register that service and serve attacker-controlled content from your domain.",
     ["Confirm the dangling record: dig CNAME <host> / dig A <host>.",
      "Identify the service from the fingerprint and check if it's claimable "
      "(see github.com/EdOverflow/can-i-take-over-xyz).",
      "If claimable, register it and host a harmless proof file.",
      "Impact to report: phishing from a trusted domain, cookie/session theft, "
      "OAuth redirect abuse, bypassing domain allowlists."]),

    ("Injection (SQLi / XSS / RCE / SSTI)",
     lambda ev: _has(ev, "sql injection", "sqli", "cross-site scripting", "xss",
                     "remote code execution", " rce", "template injection", "ssti",
                     "command injection"),
     "An injection flaw was reported - these are typically high impact.",
     ["Reproduce manually with a minimal, safe payload before any tooling.",
      "For SQLi: confirm with boolean/time-based probes, then enumerate read-only.",
      "For XSS: prove execution with a harmless alert/DOM write and note the context.",
      "Capture a clean request/response PoC for the report; avoid destructive payloads."]),

    ("CORS misconfiguration",
     lambda ev: _has(ev, "cors", "access-control-allow-origin", "cross-origin"),
     "The server reflects arbitrary Origins and/or allows credentials, enabling "
     "cross-origin theft of authenticated data.",
     ["Test: curl -H 'Origin: https://evil.example' -I <url> and inspect "
      "Access-Control-Allow-Origin / -Allow-Credentials.",
      "If the Origin is reflected with credentials allowed, build a PoC page that "
      "reads an authenticated endpoint cross-origin."]),

    ("Open redirect",
     lambda ev: _has(ev, "open redirect", "unvalidated redirect"),
     "A redirect parameter accepts attacker-controlled destinations.",
     ["Confirm: load the URL with the redirect param set to an external host.",
      "Chain it: OAuth/SAML token theft, phishing from a trusted domain, or SSRF filter bypass."]),

    ("SSRF",
     lambda ev: _mod(ev, "generic_ssrf") or _has(ev, "ssrf", "server-side request forgery"),
     "The application can be coerced into making server-side requests to a "
     "target of the attacker's choosing.",
     ["Point it at a collaborator host (interactsh) to confirm egress.",
      "Pivot to cloud metadata (169.254.169.254) and internal services; map internal ranges."]),

    ("Default / weak credentials or exposed login",
     lambda ev: _has(ev, "default credential", "default password", "weak password",
                     "login panel", "admin panel", "default login"),
     "An authentication surface was found, possibly with default or weak credentials.",
     ["Try documented default creds for the product/version.",
      "Check for account lockout, MFA, and auth-bypass (e.g. forced browsing to post-auth paths).",
      "Candidate for an authorised, low-and-slow password spray - confirm it's in scope first."]),

    # --- exposed data / files ---
    ("Open cloud storage bucket",
     lambda ev: ev["type"] == "STORAGE_BUCKET" or _mod(ev, "bucket_")
                or _has(ev, "open bucket", "public bucket",
                        "publicly listable", "world-readable"),
     "A cloud storage bucket (S3/GCS/Azure) is publicly listable or readable, "
     "potentially exposing files and enabling tampering if writable.",
     ["List it: aws s3 ls --no-sign-request s3://<bucket> (or gsutil ls / az).",
      "Pull and review interesting objects: backups, .sql dumps, configs, PII, keys.",
      "Test write access (upload a benign marker) - writable buckets allow "
      "malware hosting, supply-chain tampering, or defacement.",
      "Grep retrieved files for credentials and internal hostnames."]),

    ("Exposed .git directory",
     lambda ev: (_mod(ev, "git") and not _mod(ev, "gitlab"))
                or _has(ev, "/.git", "git exposure", ".git/head", "git directory"),
     "A web-accessible .git directory lets anyone reconstruct source code and "
     "read the full commit history.",
     ["Dump it: git-dumper http://<host>/.git/ ./loot (or GitTools).",
      "Review history for secrets, API keys, DB creds, internal URLs, dev comments.",
      "Note that deleted-but-committed secrets are still recoverable from history."]),

    ("Leaked secret / credential",
     lambda ev: ev["type"] in ("SECRET", "PASSWORD", "HASHED_PASSWORD")
                or _mod(ev, "trufflehog", "gitleaks")
                or _has(ev, "trufflehog", "gitleaks", "api key", "secret key",
                        "access key", "bearer token", "private key"),
     "A credential or high-entropy secret was found (code repo, JS bundle, "
     "response body, or leak source).",
     ["Classify the provider (AWS / Slack / GitHub / Stripe ...) and the scope it grants.",
      "Validate it with a read-only API call only - never anything destructive.",
      "Report for immediate rotation; note where it was exposed and since when if known."]),

    ("Exposed sensitive file",
     lambda ev: _has(ev, ".env", "backup file", ".bak", "config file", "web.config",
                     "id_rsa", ".sql", "database dump", "wp-config", "directory listing",
                     "directory indexing"),
     "A sensitive file or directory listing appears to be reachable without auth.",
     ["Download it and grep for API keys, DB strings, secret keys, tokens.",
      "Validate any live credential non-destructively, then flag for rotation.",
      "Check whether the leak exposes further infrastructure (DB host, internal URLs)."]),

    ("Known-CVE / outdated technology",
     lambda ev: ev["type"] == "TECHNOLOGY" or _has(ev, "cve-", "outdated", "end of life",
                                                   "end-of-life", "deprecated version"),
     "A specific technology/version was fingerprinted; known CVEs may apply.",
     ["Map the version to CVEs: searchsploit <product>, or nuclei -tags cve -u <url>.",
      "Flag end-of-life software (no patches) as a finding in its own right.",
      "Chain version intel with the open-port / URL data for this same host."]),

    ("WAF / CDN present",
     lambda ev: ev["type"] == "WAF" or _has(ev, "web application firewall", "cloudflare",
                                            "akamai", "imperva"),
     "A WAF/CDN sits in front of this asset - useful context, not a vuln by itself.",
     ["Note the vendor to tune payloads / evasion later.",
      "A WAF often fronts something worth protecting - prioritise origin-IP discovery."]),

    ("Email address exposed",
     lambda ev: ev["type"] == "EMAIL_ADDRESS",
     "A corporate email address was discovered - useful for OSINT and auth attacks.",
     ["Derive the username convention and build a user list for the engagement.",
      "Check breach exposure (HIBP) for credential-stuffing candidates.",
      "Candidate for authorised phishing / password spray - confirm rules of engagement first."]),
]

# Port-specific guidance for OPEN_TCP_PORT events.
PORT_PLAYBOOK = {
    21:   ("FTP", ["Check anonymous login (ftp <host>, user: anonymous).",
                   "nmap --script ftp-anon,ftp-syst -p21 <host>."]),
    22:   ("SSH", ["Grab banner/version for CVEs; check weak algos.",
                   "Note for key/credential reuse; never brute without authorisation."]),
    23:   ("Telnet", ["Cleartext protocol - capture banner, try default creds.",
                      "Flag the cleartext exposure itself as a finding."]),
    25:   ("SMTP", ["Test open relay and VRFY/EXPN user enumeration.",
                    "nmap --script smtp-open-relay,smtp-enum-users -p25 <host>."]),
    53:   ("DNS", ["Attempt zone transfer: dig AXFR @<host> <domain>.",
                   "Check for DNS cache snooping / recursion."]),
    110:  ("POP3", ["Cleartext auth - capture banner, check STARTTLS support."]),
    135:  ("MSRPC", ["Enumerate endpoints; pair with 445 for AD recon."]),
    139:  ("NetBIOS", ["enum4linux-ng <host>; look for null sessions."]),
    143:  ("IMAP", ["Check STARTTLS; cleartext auth is a finding."]),
    161:  ("SNMP", ["Try public/private community strings: snmpwalk -v2c -c public <host>.",
                    "Can leak interfaces, routes, ARP, running processes."]),
    389:  ("LDAP", ["Test anonymous bind: ldapsearch -x -H ldap://<host> -b '' -s base.",
                    "Anonymous bind can dump the directory."]),
    445:  ("SMB", ["List shares: smbclient -L //<host> -N; enum4linux-ng <host>.",
                   "Check null session, guest access, and SMB signing.",
                   "nmap --script smb-vuln* -p445 <host> for EternalBlue-class bugs."]),
    1433: ("MSSQL", ["Test default/weak sa creds; check for xp_cmdshell (authorised)."]),
    1521: ("Oracle", ["Enumerate SIDs; check default accounts."]),
    2049: ("NFS", ["showmount -e <host>; look for world-exported shares."]),
    3306: ("MySQL", ["Banner-grab version; test for anonymous / weak root.",
                     "mysql -h <host> -u root (authorised only)."]),
    3389: ("RDP", ["Check NLA; screenshot the login; note for credential attacks.",
                   "nmap --script rdp-ntlm-info -p3389 <host> leaks hostname/domain."]),
    5432: ("PostgreSQL", ["Test default postgres/postgres; check trust auth."]),
    5900: ("VNC", ["Check for no-auth VNC: nmap --script vnc-info -p5900 <host>.",
                   "No-auth VNC = instant interactive access."]),
    6379: ("Redis", ["Unauth Redis is common: redis-cli -h <host> info.",
                     "If unauth, it often leads to RCE (cron/module/SSH key write)."]),
    8080: ("HTTP-alt", ["Treat as a web app; screenshot + fingerprint + content discovery."]),
    9200: ("Elasticsearch", ["curl http://<host>:9200/_cat/indices - often unauth.",
                             "Exposed indices can leak entire datasets."]),
    11211:("Memcached", ["Check unauth access + UDP amplification exposure."]),
    27017:("MongoDB", ["Test unauth: mongo --host <host> then show dbs.",
                       "Legacy exposed Mongo = full DB read/write."]),
}


def enrich(ev):
    """Return (title, description, playbook_list) for a normalized event."""
    for name, pred, desc, play in RULES:
        try:
            if pred(ev):
                if name == "Nuclei template match":
                    # title the finding by its real template name, not generically
                    nm = _nuclei_name(ev)
                    if nm:
                        name = nm
                return name, desc, list(play)
        except Exception:
            continue

    if ev["type"] == "OPEN_TCP_PORT" and ev["port"] in PORT_PLAYBOOK:
        svc, play = PORT_PLAYBOOK[ev["port"]]
        return (f"Open port {ev['port']} ({svc})",
                f"{svc} is reachable on {ev['host']}:{ev['port']}.",
                list(play))

    if ev["type"] == "OPEN_TCP_PORT":
        return (f"Open port {ev['port']}",
                f"Port {ev['port']} is open on {ev['host']}.",
                ["Banner-grab and version-scan: nmap -sCV -p%s %s." % (ev["port"], ev["host"]),
                 "Map the service to known CVEs and default-credential checks."])

    if ev["type"] in ("DNS_NAME", "DNS_NAME_UNRESOLVED"):
        return ("Subdomain",
                "A subdomain in scope. Non-prod names (dev/stage/uat/test) are "
                "often weaker and less monitored.",
                ["Resolve, port-scan, screenshot and fingerprint it.",
                 "Prioritise dev/staging/admin/vpn/legacy naming patterns."])

    if ev["type"] in ("URL", "URL_UNVERIFIED"):
        return ("URL / endpoint",
                "A discovered web endpoint - a candidate for content discovery and testing.",
                ["Screenshot + fingerprint (httpx/whatweb).",
                 "Run content discovery (ffuf/feroxbuster) and nuclei against it."])

    # generic fallback for findings that matched no playbook: stay finding-oriented
    # and name the producing module so the tester knows where to look it up.
    if ev["lane"] == "finding":
        mod = ev.get("module") or ""
        title = "%s%s" % (ev["type"].replace("_", " ").title(),
                          (" (%s)" % mod) if mod else "")
        desc = ("A finding was reported%s that matches no built-in playbook. Read the "
                "finding text below for the exact issue it reports." %
                (" by BBOT's '%s' module" % mod if mod else ""))
        steps = ["Read the raw finding text/description for the exact issue, parameter, "
                 "URL or header it reports.",
                 "Reproduce it manually against the target and capture a clean "
                 "request/response PoC.",
                 "Judge real impact and reachability before reporting; rule out a false positive."]
        steps.append("Look up what BBOT's '%s' module checks for to interpret this result."
                     % mod if mod else "Correlate with other findings on the same host.")
        return (title, desc, steps)

    # generic fallback (assets)
    return (ev["type"].replace("_", " ").title(),
            "Discovered during the scan; review in context of the surrounding assets.",
            ["Correlate with other findings on the same host.",
             "Decide if it widens the attack surface or confirms an existing lead."])


# Per-service commands for an OPEN_TCP_PORT finding ({h}=host, {p}=port).
PORT_CMDS = {
    21:   [("FTP anon login", "nmap --script ftp-anon,ftp-syst -p21 {h}")],
    22:   [("SSH banner/algos", "nmap --script ssh2-enum-algos,ssh-hostkey -p22 {h}")],
    23:   [("Telnet banner", "nmap --script telnet-encryption,banner -p23 {h}")],
    25:   [("SMTP relay/users", "nmap --script smtp-open-relay,smtp-commands,smtp-enum-users -p25 {h}")],
    53:   [("DNS zone transfer", "dig AXFR @{h} <domain>")],
    110:  [("POP3 caps", "nmap --script pop3-capabilities,banner -p110 {h}")],
    135:  [("MSRPC endpoints", "rpcdump.py @{h}")],
    139:  [("NetBIOS enum", "enum4linux-ng {h}")],
    143:  [("IMAP caps", "nmap --script imap-capabilities,banner -p143 {h}")],
    161:  [("SNMP walk", "snmpwalk -v2c -c public {h}")],
    389:  [("LDAP anon bind", "ldapsearch -x -H ldap://{h} -b '' -s base")],
    445:  [("SMB shares", "smbclient -L //{h} -N"),
           ("SMB enum", "enum4linux-ng {h}"),
           ("SMB vulns", "nmap --script 'smb-vuln*' -p445 {h}")],
    1433: [("MSSQL info", "nmap --script ms-sql-info,ms-sql-ntlm-info -p1433 {h}")],
    1521: [("Oracle SID", "nmap --script oracle-sid-brute -p1521 {h}")],
    2049: [("NFS exports", "showmount -e {h}")],
    3306: [("MySQL info", "nmap --script mysql-info,mysql-empty-password -p3306 {h}")],
    3389: [("RDP NTLM info", "nmap --script rdp-ntlm-info -p3389 {h}")],
    5432: [("Postgres probe", "nmap --script pgsql-brute -p5432 {h}")],
    5900: [("VNC auth check", "nmap --script vnc-info,realvnc-auth-bypass -p5900 {h}")],
    6379: [("Redis unauth", "redis-cli -h {h} info")],
    8080: [("Web check", "httpx -u http://{h}:8080 -sc -title -tech-detect")],
    9200: [("ES indices", "curl -s http://{h}:9200/_cat/indices")],
    11211:[("Memcached info", "nmap --script memcached-info -p11211 {h}")],
    27017:[("MongoDB dbs", "nmap --script mongodb-info,mongodb-databases -p27017 {h}")],
}


def suggest_commands(ev):
    """Build copy-paste commands tailored to what the finding actually is:
    a targeted verification for known finding types (nuclei template re-run,
    .git dump, bucket listing, takeover dig, per-service port probes), then
    generic recon as context. Falls back to recon when nothing specific fits."""
    cmds = []
    host, url, port, scheme = ev["host"], ev["url"], ev["port"], ev["scheme"]
    typ = ev.get("type", "")
    # a concrete web target: a real URL, else a scheme+host we actually saw
    web = url or (("%s://%s" % (scheme, host)) if (scheme and host) else "")
    webroot = web.rstrip("/") if web else ""
    t = ((ev.get("title", "") or "") + " " + (ev.get("text", "") or "")).lower()
    targeted = False

    def add(label, cmd):
        if cmd and (label, cmd) not in cmds:
            cmds.append((label, cmd))

    # ---- finding-specific verification (most relevant first) ----
    if _mod(ev, "nuclei"):
        tid = _nuclei_template_id(ev)
        if tid and web:
            add("Re-run this template", "nuclei -id %s -u '%s' -debug" % (tid, web))
            targeted = True
    if _mod(ev, "baddns") or _has(ev, "takeover", "dangling", "unclaimed", "can be taken over"):
        if host:
            add("Check dangling DNS", "dig +noall +answer CNAME %s ; dig +noall +answer A %s" % (host, host))
            targeted = True
    if _mod(ev, "git") or "/.git" in t or ".git/" in t:
        if webroot:
            base = re.sub(r"/\.git(/.*)?$", "", webroot)  # avoid /.git/.git when the URL is already the .git dir
            add("Confirm .git exposure", "curl -sSIk '%s/.git/HEAD'" % base)
            add("Dump the repo", "git-dumper '%s/.git/' ./gitdump" % base)
            targeted = True
    if _mod(ev, "bucket") or "bucket" in t or "s3://" in t or " s3 " in t:
        if host:
            add("List bucket (S3)", "aws s3 ls s3://%s --no-sign-request" % host)
            targeted = True
    if _mod(ev, "trufflehog") or "leaked" in t or "secret" in t or "credential" in t or "api key" in t:
        add("Verify the secret", "# test the leaked credential read-only against its own service; do not reuse elsewhere")
        targeted = True
    if _mod(ev, "host_header") or "host header" in t:
        if web:
            add("Host-header injection", "curl -sSIk -H 'Host: evil.example' '%s'" % web)
            targeted = True
    if _mod(ev, "ntlm") or "ntlm" in t:
        if web:
            add("NTLM info leak", "curl -sSIk -H 'Authorization: NTLM TlRMTVNTUAABAAAAB4IIAA==' '%s'" % web)
            targeted = True
    if _mod(ev, "graphql") or "graphql" in t or "introspection" in t:
        if web:
            add("GraphQL introspection",
                "curl -sSk '%s' -H 'Content-Type: application/json' "
                "-d '{\"query\":\"{__schema{types{name}}}\"}'" % web)
            targeted = True
    if "cors" in t:
        if web:
            add("CORS misconfig", "curl -sSIk -H 'Origin: https://evil.example' '%s'" % web)
            targeted = True
    if _has(ev, "sql injection", "sqli"):
        if web:
            add("Confirm SQLi", "sqlmap -u '%s' --batch --level 2 --risk 2" % web)
            targeted = True
    if _has(ev, "cross-site scripting", "xss"):
        if web:
            add("Probe XSS context", "curl -sSk '%s'   # inject a benign marker and inspect the reflection context" % web)
            targeted = True
    if _mod(ev, "telerik", "ajaxpro", "dotnetnuke") or "telerik" in t or "dotnetnuke" in t or "ajaxpro" in t:
        if web:
            add("Targeted template scan", "nuclei -tags telerik,dotnetnuke,aspx -u '%s'" % web)
            targeted = True
    if _mod(ev, "retirejs") or ("vulnerable" in t and ("javascript" in t or ".js" in t)):
        if web:
            add("Re-check JS libraries", "nuclei -tags tech,javascript -u '%s'" % web)
            targeted = True

    # ---- service-specific commands for an open port ----
    if typ == "OPEN_TCP_PORT" and host:
        for label, tmpl in PORT_CMDS.get(port, []):
            add(label, tmpl.format(h=host, p=port))
        if port not in PORT_CMDS:
            add("Service scan", "nmap -sCV -p%s %s" % (port, host))
        targeted = True

    # ---- asset recon when there is no specific finding to verify ----
    if typ in ("DNS_NAME", "DNS_NAME_UNRESOLVED") and host:
        add("Resolve", "dig +short %s A ; dig +short %s CNAME" % (host, host))
        add("Port scan", "nmap -sCV --top-ports 1000 %s" % host)
        add("Quick web check", "httpx -u %s -sc -title -tech-detect" % host)

    # ---- generic web context (after the tailored commands) ----
    if web:
        add("Response headers", "curl -sSIk '%s'" % web)
        add("Fingerprint", "httpx -u '%s' -sc -title -tech-detect -server" % web)
        if not targeted:
            add("Nuclei scan", "nuclei -u '%s'" % web)
            add("Content discovery",
                "ffuf -u '%s/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/common.txt" % webroot)
    elif host and not port and typ not in ("DNS_NAME", "DNS_NAME_UNRESOLVED"):
        add("Port scan", "nmap -sCV --top-ports 1000 %s" % host)
        add("Quick web check", "httpx -u %s -sc -title -tech-detect" % host)

    if host:
        add("Screenshot", "gowitness single https://%s" % host)

    return cmds[:7]


# --------------------------------------------------------------------------- #
#  Parsing BBOT output (ndjson / json / csv)
# --------------------------------------------------------------------------- #

def _sev_from(blob, tags):
    low = (blob or "").lower()
    for t in (tags or []):
        tl = str(t).lower().strip()
        if tl in SEV_RANK:
            return tl
        # BBOT / nuclei tag forms carry the real severity: "severity-info",
        # "severity_medium", "severity:high". Without this, info/low nuclei
        # findings fall through to the FINDING default (medium) and flood the view.
        m = re.match(r"severity[-_: ]?\s*(critical|high|medium|low|info)$", tl)
        if m:
            return m.group(1)
    for sev in ("critical", "high", "medium", "low", "info"):
        if re.search(r"\[%s\]" % sev, low) or ("severity: " + sev) in low:
            return sev
    return None


def _embedded_severity(text):
    """A real severity stated inside a finding's text, e.g. retire.js writes
    'Severity: CRITICAL' in the description while BBOT hardcodes the event
    severity to INFO. Requires the literal 'severity: <level>' form so it can't
    false-match an unrelated bracketed word. Returns the level or None."""
    m = re.search(r"severity[:=]\s*\[?\s*(critical|high|medium|low|info)\b",
                  (text or "").lower())
    return m.group(1) if m else None


def _target_bits(type_, data_str, host_hint, url_hint):
    """Extract host / url / port / scheme from an event."""
    host = host_hint or ""
    url = url_hint or ""
    port = 0
    scheme = ""

    if url:
        try:
            p = urllib.parse.urlparse(url)
            scheme = p.scheme
            host = host or p.hostname or ""
            if p.port:
                port = p.port
        except Exception:
            pass

    if not url and type_ in ("URL", "URL_UNVERIFIED") and data_str.startswith(("http://", "https://")):
        url = data_str.split()[0]
        try:
            p = urllib.parse.urlparse(url)
            scheme, host, port = p.scheme, (host or p.hostname or ""), (p.port or 0)
        except Exception:
            pass

    if type_ == "OPEN_TCP_PORT":
        m = re.match(r"^\[?([^\]]+)\]?:(\d+)$", data_str.strip()) or \
            re.match(r"^(.+):(\d+)$", data_str.strip())
        if m:
            host = m.group(1)            # the data's host wins over the resolved-IP hint
            try:
                port = int(m.group(2))
            except ValueError:
                pass

    # for name/IP events the data itself is the target, not the resolved-IP hint
    if type_ in ("DNS_NAME", "DNS_NAME_UNRESOLVED", "IP_ADDRESS") and data_str.strip():
        host = data_str.strip().split()[0]

    return host, url, port, scheme


def _normalize(type_, data, module, tags, ip="", resolved=None):
    """Turn a raw event into the normalized dict the UI/knowledge-base use."""
    desc = ""
    host = ip or ""
    url = ""
    severity = None

    if isinstance(data, dict):
        desc = data.get("description", "") or ""
        host = data.get("host", "") or host
        url = data.get("url", "") or ""
        severity = (data.get("severity") or "").lower() or None
        data_str = desc or url or host or json.dumps(data, ensure_ascii=False)
    else:
        data_str = str(data)

    tags = list(tags or [])
    if severity is None:
        severity = _sev_from(data_str + " " + " ".join(map(str, tags)), tags)

    # honor a higher severity stated in the finding text (retirejs et al. pin the
    # event severity to INFO but put the real one in the description) - upgrade only
    embedded = _embedded_severity(data_str)
    if embedded and SEV_RANK.get(embedded, 0) > SEV_RANK.get(severity or "", 0):
        severity = embedded

    host, url, port, scheme = _target_bits(type_, data_str, host, url)

    text_blob = " ".join([type_, data_str, desc, module or "", " ".join(map(str, tags))])

    # resolved IPs for this event (used to map an IP-only host back to a hostname)
    res = [str(r).strip() for r in (resolved if resolved is not None
                                    else ([ip] if ip else [])) if str(r).strip()]

    ev = {
        "type": type_, "module": module or "", "tags": tags,
        "data_str": data_str, "desc": desc,
        "host": host, "url": url, "port": port, "scheme": scheme,
        "severity": severity, "text": text_blob, "resolved": res,
    }

    # final priority band
    if severity in SEV_RANK and severity != "unknown":
        band = severity
    elif type_ in TYPE_INTEREST:
        band = TYPE_INTEREST[type_]
    else:
        band = "info"
    ev["priority"] = band
    ev["lane"] = "finding" if (type_ in FINDING_TYPES or SEV_RANK.get(band, 0) >= 3) else "asset"

    # clean technology / WAF label for the Screenshots tech chips and host pivot
    tech_name = ""
    if type_ == "TECHNOLOGY":
        if isinstance(data, dict):
            tech_name = str(data.get("technology") or data.get("name") or "").strip()
        if not tech_name and not data_str.lower().startswith("http"):
            tech_name = data_str.strip()
    elif type_ == "WAF":
        waf = ""
        if isinstance(data, dict):
            waf = str(data.get("waf") or data.get("WAF") or data.get("name") or "").strip()
        if not waf and not data_str.lower().startswith("http"):
            waf = data_str.strip()
        if waf:
            tech_name = "WAF: " + waf
    ev["tech"] = tech_name

    ev["juicy"] = juicy_tags(host, url or data_str if type_ in ("URL", "URL_UNVERIFIED") else url)
    title, description, playbook = enrich(ev)
    ev["title"] = title
    ev["description"] = desc or description
    ev["why"] = description
    ev["playbook"] = playbook
    ev["commands"] = suggest_commands(ev)
    ev["id"] = hashlib.sha1(
        ("%s|%s" % (type_, data_str)).encode("utf-8", "replace")
    ).hexdigest()[:12]
    return ev


def parse_ndjson(path):
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        blob = f.read().strip()
    # support either one-object-per-line (ndjson) or a single JSON array
    records = []
    if blob.startswith("["):
        try:
            records = json.loads(blob)
        except Exception:
            records = []
    else:
        for line in blob.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                continue
    for r in records:
        if not isinstance(r, dict):
            continue
        rh = r.get("resolved_hosts") if isinstance(r.get("resolved_hosts"), list) else []
        ev = _normalize(
            r.get("type", "UNKNOWN"), r.get("data", ""),
            r.get("module", ""), r.get("tags", []),
            ip=(rh[0] if rh else ""), resolved=rh,
        )
        ev["raw"] = r                      # keep the full BBOT record for the Metadata tab
        events.append(ev)
    return events


def parse_csv(path):
    events = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            type_ = (row.get("Event type") or row.get("type") or "UNKNOWN").strip()
            data = (row.get("Event data") or row.get("data") or "").strip()
            module = (row.get("Source Module") or row.get("module") or "").strip()
            ip = (row.get("IP Address") or "").strip()
            tags_raw = (row.get("Event Tags") or row.get("tags") or "").strip()
            tags = [t for t in re.split(r"[,\s]+", tags_raw) if t]
            ev = _normalize(type_, data, module, tags, ip=ip)
            ev["raw"] = dict(row)          # keep the original row for the Metadata tab
            events.append(ev)
    return events


def is_ip(s):
    """True if s is an IPv4 or IPv6 literal (i.e. not a hostname)."""
    try:
        ipaddress.ip_address(str(s).strip())
        return True
    except ValueError:
        return False


def attach_display_hosts(events):
    """Give every event a 'dhost' (display host): the hostname when we have one,
    otherwise the IP. BBOT events discovered against a bare IP carry no hostname,
    so we learn IP->hostname from the events that do (DNS names, URLs, findings
    with a host field) and back-fill the IP-only ones. The shortest hostname for
    an IP wins, which prefers the apex/canonical name over long CDN labels."""
    ip2name = {}
    for ev in events:
        h = ev.get("host") or ""
        if h and not is_ip(h):
            for rip in ev.get("resolved", []):
                if is_ip(rip):
                    cur = ip2name.get(rip)
                    if cur is None or len(h) < len(cur):
                        ip2name[rip] = h
    for ev in events:
        h = ev.get("host") or ""
        ev["dhost"] = ip2name[h] if (h and is_ip(h) and h in ip2name) else h
    return events


def dedupe_events(events):
    """Drop exact-duplicate events so the same finding/asset appears once. Two
    events are duplicates only when type, target (host/url/port) and data all
    match, so the same issue reported twice on one target collapses while the
    same issue on different hosts stays separate. The most-severe copy of a
    duplicate is the one kept (so a low-severity twin can never swallow a
    critical), at the position of the first occurrence. Exact duplicates share
    the same event id (type|data_str), so triage carries over regardless."""
    seen = {}            # dedupe key -> index into out
    out = []
    for ev in events:
        key = (ev.get("type", ""), ev.get("host", ""), ev.get("url", ""),
               ev.get("port", 0), ev.get("data_str", ""))
        if key in seen:
            i = seen[key]
            if SEV_RANK.get(ev.get("priority"), 0) > SEV_RANK.get(out[i].get("priority"), 0):
                out[i] = ev            # keep the most severe of exact duplicates
            continue
        seen[key] = len(out)
        out.append(ev)
    return out


def _read_events(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in (".ndjson", ".jsonl", ".json"):
        return parse_ndjson(path)               # handles array or ndjson
    if ext in (".csv", ".tsv"):
        return parse_csv(path)
    # try to sniff
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        head = f.read(2048).lstrip()
    if head.startswith("{") or head.startswith("["):
        return parse_ndjson(path)
    return parse_csv(path)


def load_events(path):
    return dedupe_events(attach_display_hosts(_read_events(path)))


# --------------------------------------------------------------------------- #
#  Screenshot gallery (adapted from shotview)
# --------------------------------------------------------------------------- #

def _is_octet(t):
    return t.isdigit() and 0 <= int(t) <= 255


def guess_url(filename):
    orig_stem = os.path.splitext(os.path.basename(filename))[0]
    stem = orig_stem
    scheme = ""
    for pfx in ("https", "http"):
        if stem.lower().startswith(pfx + "-") or stem.lower().startswith(pfx + "_"):
            scheme = pfx
            stem = stem[len(pfx) + 1:]
            break
    tokens = [t for t in re.split(r"[-_]", stem) if t != ""]
    if not tokens:
        return orig_stem
    host_tokens, idx = [], 0
    if len(tokens) >= 4 and all(_is_octet(tokens[i]) for i in range(4)):
        host_tokens, idx = tokens[:4], 4
    else:
        while idx < len(tokens):
            t = tokens[idx]
            if idx >= 1 and t.isdigit() and 1 <= int(t) <= 65535:
                break
            host_tokens.append(t)
            idx += 1
    host = ".".join(host_tokens)
    port = ""
    if idx < len(tokens) and tokens[idx].isdigit() and 1 <= int(tokens[idx]) <= 65535:
        port = tokens[idx]; idx += 1
    path_tokens = tokens[idx:]
    if len(path_tokens) >= 2 and path_tokens[-1].lower() in WEB_EXTS:
        path_tokens = path_tokens[:-2] + [path_tokens[-2] + "." + path_tokens[-1]]
    path = "/".join(path_tokens)
    if not host:
        return orig_stem
    label = f"{scheme}://{host}" if scheme else host
    default = (scheme == "http" and port == "80") or (scheme == "https" and port == "443")
    if port and not default:
        label += f":{port}"
    if path:
        label += "/" + path
    return label


def collect_images(root):
    items = []
    if not root or not os.path.isdir(root):
        return items
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if ext not in IMAGE_EXTS:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            items.append({"file": name, "rel": rel.replace(os.sep, "/"),
                          "label": guess_url(name), "size": size})
    items.sort(key=lambda x: x["label"].lower())
    return items


def load_gowitness(path):
    """Read a gowitness results store and return (by_file, by_url): dicts mapping a
    screenshot basename / URL to its list of detected technologies. Supports the
    SQLite DB (v2 'urls'+technologies.url_id, or v3 'results'+technologies.result_id)
    and the --write-jsonl output. Best-effort and schema-tolerant."""
    by_file, by_url = {}, {}

    def base(p):
        return os.path.basename(str(p).replace("\\", "/")) if p else ""

    def add(fn, url, value):
        value = (value or "").strip()
        if not value:
            return
        bn = base(fn)
        if bn:
            by_file.setdefault(bn, [])
            if value not in by_file[bn]:
                by_file[bn].append(value)
        if url:
            by_url.setdefault(url, [])
            if value not in by_url[url]:
                by_url[url].append(value)

    ext = os.path.splitext(path)[1].lower()
    if ext in (".jsonl", ".ndjson", ".json"):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            blob = f.read().strip()
        recs = []
        if blob.startswith("["):
            try:
                recs = json.loads(blob)
            except Exception:
                recs = []
        else:
            for line in blob.splitlines():
                line = line.strip()
                if line:
                    try:
                        recs.append(json.loads(line))
                    except Exception:
                        pass
        for r in recs:
            if not isinstance(r, dict):
                continue
            fn = r.get("file_name") or r.get("filename") or r.get("screenshot") or r.get("file") or ""
            url = r.get("url") or r.get("final_url") or ""
            techs = r.get("technologies") or r.get("technology") or []
            if isinstance(techs, str):
                techs = [techs]
            for t in techs:
                if isinstance(t, dict):
                    add(fn, url, t.get("value") or t.get("name") or t.get("technology") or "")
                else:
                    add(fn, url, str(t))
        return by_file, by_url

    # SQLite
    import sqlite3
    con = None
    try:
        con = sqlite3.connect(path)
        cur = con.cursor()
        tables = {r[0].lower() for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "technologies" not in tables:
            return by_file, by_url
        def cols(t):
            return [r[1].lower() for r in cur.execute("PRAGMA table_info(%s)" % t)]
        tcols = cols("technologies")
        fk = "result_id" if "result_id" in tcols else ("url_id" if "url_id" in tcols else None)
        valcol = "value" if "value" in tcols else next((c for c in tcols if c not in ("id", fk)), None)
        res_table = "results" if "results" in tables else ("urls" if "urls" in tables else None)
        if not (fk and valcol and res_table):
            return by_file, by_url
        rcols = cols(res_table)
        file_col = next((c for c in ("file_name", "filename", "screenshot",
                                     "screenshot_path", "file") if c in rcols), None)
        url_col = "url" if "url" in rcols else ("final_url" if "final_url" in rcols else None)
        sel_file = "r." + file_col if file_col else "''"
        sel_url = "r." + url_col if url_col else "''"
        query = "SELECT %s, %s, t.%s FROM %s r JOIN technologies t ON t.%s = r.id" % (
            sel_file, sel_url, valcol, res_table, fk)
        for fn, url, val in cur.execute(query):
            add(fn, url, val)
    finally:
        if con:
            con.close()
    return by_file, by_url


# --------------------------------------------------------------------------- #
#  Triage state store (JSON sidecar, thread-safe)
# --------------------------------------------------------------------------- #

class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {}
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception:
                self.data = {}

    def get(self, fid):
        return self.data.get(fid, {"status": "new", "notes": "", "updated": ""})

    def set(self, fid, status=None, notes=None, allowed=None):
        allowed = allowed if allowed is not None else STATUS_KEYS
        with self.lock:
            cur = self.data.get(fid, {"status": "new", "notes": "", "updated": ""})
            if status is not None and status in allowed:
                cur["status"] = status
            if notes is not None:
                cur["notes"] = notes
            cur["updated"] = datetime.now().isoformat(timespec="seconds")
            self.data[fid] = cur
            self._flush()
            return cur

    def _flush(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)


# --------------------------------------------------------------------------- #
#  Export (markdown report of triaged findings)
# --------------------------------------------------------------------------- #

def meta_row(ev):
    """Compact descriptor + the full captured record for the Metadata tab."""
    tgt = ev.get("url") or ""
    if not tgt:
        h = ev.get("dhost") or ev.get("host") or ""
        tgt = ("%s:%s" % (h, ev["port"])) if (h and ev.get("port")) else h
    return {
        "id": ev.get("id", ""), "type": ev.get("type", ""),
        "module": ev.get("module", ""), "tags": ev.get("tags", []),
        "target": tgt, "priority": ev.get("priority", ""),
        "title": ev.get("title", ""),
        "raw": ev.get("raw") if ev.get("raw") is not None else {
            "type": ev.get("type", ""), "data": ev.get("data_str", ""),
            "module": ev.get("module", ""), "tags": ev.get("tags", []),
        },
    }


def collect_emails(events):
    """Unique, lowercased email addresses discovered in the scan (BBOT
    EMAIL_ADDRESS events), sorted. Intended to be exported and fed into
    user-enumeration tools (onedrive_user_enum, o365enum, etc.)."""
    rx = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
    seen = {}
    for ev in events:
        if ev.get("type") != "EMAIL_ADDRESS":
            continue
        blob = (ev.get("data_str", "") or "") + " " + (ev.get("host", "") or "")
        for m in rx.findall(blob):
            seen[m.strip().lower()] = True
    return sorted(seen)


def build_markdown(events, store):
    by_sev = {}
    for ev in events:
        st = store.get(ev["id"])
        if st["status"] in ("new",):          # skip untouched noise
            continue
        if ev["lane"] != "finding" and st["status"] not in ("confirmed", "reported"):
            continue
        by_sev.setdefault(ev["priority"], []).append((ev, st))
    out = ["# bscope triage report",
           "", "_Generated %s_" % datetime.now().strftime("%Y-%m-%d %H:%M"), ""]
    order = sorted(by_sev.keys(), key=lambda s: -SEV_RANK.get(s, 0))
    if not order:
        out.append("_No findings have been triaged yet._")
    for sev in order:
        out.append("## %s" % sev.upper())
        for ev, st in by_sev[sev]:
            _h = ev.get("dhost") or ev["host"]
            target = ev["url"] or (f"{_h}:{ev['port']}" if ev["port"] else _h) or ev["data_str"][:80]
            out.append("")
            out.append("### [%s] %s" % (st["status"].replace("_", " "), ev["title"]))
            out.append("- **Target:** %s" % target)
            out.append("- **Type / module:** %s / %s" % (ev["type"], ev["module"] or "-"))
            if ev["why"]:
                out.append("- **What it is:** %s" % ev["why"])
            if st["notes"]:
                out.append("- **Tester notes:** %s" % st["notes"])
            if ev["playbook"]:
                out.append("- **Next steps:**")
                for step in ev["playbook"]:
                    out.append("  - %s" % step)
        out.append("")
    return "\n".join(out)


def _target_of(ev):
    h = ev.get("dhost") or ev["host"]
    return ev["url"] or (f"{h}:{ev['port']}" if ev["port"] else h) or ev["data_str"][:120]


def build_json_export(events, store):
    rows = []
    for ev in events:
        st = store.get(ev["id"])
        rows.append({
            "id": ev["id"], "lane": ev["lane"], "type": ev["type"],
            "priority": ev["priority"], "severity": ev["severity"],
            "title": ev["title"], "target": _target_of(ev),
            "host": ev["host"], "url": ev["url"], "port": ev["port"],
            "module": ev["module"], "tags": ev["tags"], "juicy": ev["juicy"],
            "status": st["status"], "notes": st["notes"], "updated": st["updated"],
            "description": ev["why"],
        })
    return json.dumps(rows, indent=2, ensure_ascii=False)


def build_csv_export(events, store):
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "lane", "type", "priority", "severity", "title", "target",
                "host", "url", "port", "module", "tags", "juicy",
                "status", "notes", "updated"])
    for ev in events:
        st = store.get(ev["id"])
        w.writerow([ev["id"], ev["lane"], ev["type"], ev["priority"], ev["severity"] or "",
                    ev["title"], _target_of(ev), ev["host"], ev["url"], ev["port"] or "",
                    ev["module"], " ".join(ev["tags"]), " ".join(ev["juicy"]),
                    st["status"], st["notes"], st["updated"]])
    return buf.getvalue()


# --------------------------------------------------------------------------- #
#  Web UI
# --------------------------------------------------------------------------- #

PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>bscope - __TITLE__</title>
<style>
:root{--bg:#0d1017;--panel:#161b26;--panel2:#1d2431;--line:#2a3342;--text:#e6edf3;
--muted:#8b98a9;--accent:#4a9eff;--accent2:#2d7dd2;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
header{position:sticky;top:0;z-index:20;background:var(--panel);border-bottom:1px solid var(--line);
padding:12px 18px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;}
.brand{font-weight:700;font-size:16px;letter-spacing:.3px;}
.brand span{color:var(--accent);}
.tabs{display:flex;gap:6px;}
.tab{background:var(--panel2);border:1px solid var(--line);color:var(--muted);border-radius:8px;
padding:7px 13px;cursor:pointer;font-size:13px;}
.tab.active{color:var(--text);border-color:var(--accent2);}
.search{flex:1;min-width:180px;max-width:480px;margin-left:auto;background:var(--panel2);
border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px 11px;outline:none;}
.search:focus{border-color:var(--accent2);}
.btn{background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:8px;
padding:8px 11px;cursor:pointer;font-size:13px;text-decoration:none;}
.btn:hover{border-color:var(--accent2);}
main{padding:16px 18px;}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px;}
.chip{background:var(--panel2);border:1px solid var(--line);color:var(--muted);border-radius:20px;
padding:5px 11px;cursor:pointer;font-size:12px;user-select:none;}
.chip.on{color:#07101f;font-weight:600;}
.sev-dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle;}
.muted{color:var(--muted);}
/* findings */
.card{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;
padding:12px 14px;margin-bottom:10px;}
.card.sel{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent2);}
.card h3{margin:0 0 3px;font-size:15px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.sevtag{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
padding:2px 7px;border-radius:5px;color:#07101f;}
.statustag{font-size:11px;padding:2px 8px;border-radius:5px;color:#fff;}
.tgt{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--accent);
cursor:pointer;word-break:break-all;}
.tgt:hover{text-decoration:underline;}
.why{margin:7px 0;color:var(--text);}
.sub{font-size:12px;color:var(--muted);}
details{margin-top:8px;}
summary{cursor:pointer;color:var(--muted);font-size:13px;}
.play li{margin:3px 0;}
.cmd{display:flex;align-items:center;gap:8px;margin:4px 0;}
.cmd code{flex:1;background:#0a0e15;border:1px solid var(--line);border-radius:6px;padding:5px 8px;
font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;overflow-x:auto;white-space:pre;}
.copy{background:var(--panel2);border:1px solid var(--line);color:var(--muted);border-radius:6px;
padding:3px 8px;font-size:11px;cursor:pointer;}
.statusrow{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;align-items:center;}
.sbtn{border:1px solid var(--line);background:var(--panel2);color:var(--muted);border-radius:6px;
padding:4px 9px;font-size:12px;cursor:pointer;transition:box-shadow .1s,background .1s,color .1s;}
.sbtn:hover{border-color:var(--accent);color:var(--text);}
.sbtn.on{color:#07101f;font-weight:700;border-color:transparent;
box-shadow:0 0 0 2px var(--panel),0 0 0 4px rgba(255,255,255,.92);}
.sbtn.on::before{content:"\2713\00a0";}
.notes{width:100%;margin-top:8px;background:#0a0e15;border:1px solid var(--line);border-radius:6px;
color:var(--text);padding:7px 9px;font-size:13px;resize:vertical;min-height:34px;outline:none;}
.notes:focus{border-color:var(--accent2);}
/* overview */
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:18px;}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;}
.tile .n{font-size:26px;font-weight:700;}
.tile .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;}
.progress{height:10px;background:var(--panel2);border-radius:6px;overflow:hidden;display:flex;margin:6px 0 2px;}
.progress i{display:block;height:100%;}
/* assets table */
table{width:100%;border-collapse:collapse;font-size:13px;}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top;}
th{color:var(--muted);font-weight:600;position:sticky;top:57px;background:var(--bg);}
td.mono{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all;}
/* screenshots */
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));}
.shot{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;transition:border-color .12s;}
.shot .thumb{cursor:pointer;}
.shotbtns{display:flex;gap:6px;margin-top:8px;}
.techrow{display:flex;flex-wrap:wrap;gap:4px;margin-top:7px;}
.techchip{font-size:10px;background:var(--panel2);border:1px solid var(--line);border-radius:5px;padding:1px 6px;color:var(--muted);}
.techchip.more{color:var(--accent);}
.lbtech{display:flex;flex-wrap:wrap;gap:5px;justify-content:center;margin-bottom:10px;}
.lbtech .techchip{font-size:12px;padding:2px 9px;}
.shot:hover{border-color:var(--accent2);}
.shot .thumb{aspect-ratio:16/10;background:#000;overflow:hidden;}
.shot img{width:100%;height:100%;object-fit:cover;object-position:top;display:block;}
.shot .m{padding:9px 11px;}
.shot .lbl{font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.lb{position:fixed;inset:0;background:rgba(0,0,0,.93);z-index:100;display:none;flex-direction:column;}
.lb.open{display:flex;}
.lb-bar{padding:11px 16px;display:flex;gap:12px;align-items:center;border-bottom:1px solid var(--line);background:var(--panel);}
.lb-body{flex:1;overflow:auto;padding:16px;text-align:center;}
.lb-body img{max-width:100%;border:1px solid var(--line);border-radius:6px;}
.empty{color:var(--muted);text-align:center;padding:50px;}
.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--panel2);
border:1px solid var(--accent2);border-radius:8px;padding:8px 16px;font-size:13px;opacity:0;
transition:opacity .2s;pointer-events:none;z-index:200;}
.toast.show{opacity:1;}
.rawjson{white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,monospace;font-size:12px;line-height:1.45;margin:8px 0;padding:10px;max-height:460px;overflow:auto;background:var(--panel2);border:1px solid var(--line);border-radius:6px;}
.kbd{font-family:ui-monospace,monospace;font-size:11px;background:var(--panel2);border:1px solid var(--line);
border-radius:4px;padding:1px 5px;color:var(--muted);}
.star{color:#ffc93c;font-size:13px;}
.newbadge{font-size:10px;font-weight:700;background:#38c172;color:#07101f;border-radius:5px;padding:2px 6px;letter-spacing:.3px;}
.juicytag{font-size:10px;color:#ffc93c;border:1px solid #4a3f1a;background:#231d0d;border-radius:5px;padding:1px 6px;}
.cardthumb{float:right;width:120px;height:72px;object-fit:cover;object-position:top;border:1px solid var(--line);
border-radius:6px;margin:0 0 6px 10px;cursor:pointer;background:#000;}
.exwrap{position:relative;}
.exmenu{position:absolute;right:0;top:38px;background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:6px;display:none;flex-direction:column;gap:4px;z-index:30;min-width:150px;}
.exmenu.open{display:flex;}
.exmenu a{color:var(--text);text-decoration:none;padding:6px 10px;border-radius:6px;font-size:13px;}
.exmenu a:hover{background:var(--panel2);}
/* host pivot */
.host{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;margin-bottom:10px;overflow:hidden;}
.host>summary{list-style:none;cursor:pointer;padding:11px 14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.host>summary::-webkit-details-marker{display:none;}
/* rotating disclosure caret so host / section rows read as expandable */
.caret{display:inline-block;flex:0 0 auto;color:var(--muted);font-size:11px;line-height:1;transition:transform .15s ease;transform:rotate(0deg);}
details[open]>summary>.caret{transform:rotate(90deg);}
summary:hover>.caret{color:var(--accent);}
.host .hname{font-weight:600;font-size:15px;word-break:break-all;}
.host .hmeta{color:var(--muted);font-size:12px;margin-left:auto;}
.host .body{padding:0 14px 12px;}
.host .sec{margin-top:8px;}
.host .sec h4{margin:0 0 4px;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;}
.host .row{font-size:13px;padding:2px 0;word-break:break-all;}
.host .fchip{display:inline-block;font-size:11px;padding:1px 7px;border-radius:5px;color:#07101f;margin-right:6px;}
.hthumb{width:150px;height:92px;object-fit:cover;object-position:top;border:1px solid var(--line);border-radius:6px;cursor:pointer;background:#000;}
.inst{display:flex;align-items:center;gap:8px;flex-wrap:wrap;border-top:1px solid var(--line);padding:5px 0;}
.inst .it{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--accent);word-break:break-all;flex:1;min-width:160px;}
.sbtn.mini{padding:2px 6px;font-size:11px;}
.sdot{display:inline-block;width:9px;height:9px;border-radius:50%;flex:0 0 auto;}
.statustag.mini{font-size:10px;padding:0 6px;opacity:.9;}
.inst details.rowtri{flex:1 1 100%;margin:3px 0 1px;}
.inst details.rowtri>summary{list-style:none;cursor:pointer;color:var(--muted);font-size:11px;display:inline-block;padding:1px 7px;border:1px solid var(--line);border-radius:5px;}
.inst details.rowtri>summary::-webkit-details-marker{display:none;}
.inst details.rowtri[open]>summary{margin-bottom:6px;color:var(--accent);}
.inst .statusrow{margin:4px 0;}
.gsum{font-size:11px;color:var(--muted);margin-left:2px;}
.gsum b{color:var(--text);font-weight:600;}
.gmore{margin-top:8px;background:var(--panel);border:1px solid var(--line);color:var(--accent);padding:5px 12px;border-radius:6px;cursor:pointer;font-size:12px;}
.gmore:hover{border-color:var(--accent);}
.host details.sec>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;}
.host details.sec>summary::-webkit-details-marker{display:none;}
.h4lbl{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-weight:600;}
.host details.sec[open]>summary{margin-bottom:4px;}
</style></head><body>
<header>
  <div class="brand">b<span>scope</span></div>
  <div class="tabs">
    <button class="tab active" data-tab="overview">Overview</button>
    <button class="tab" data-tab="hosts">Hosts</button>
    <button class="tab" data-tab="findings">Findings</button>
    <button class="tab" data-tab="assets">Assets</button>
    <button class="tab" data-tab="emails">Emails</button>
    <button class="tab" data-tab="shots">Screenshots</button>
    <button class="tab" data-tab="meta">Metadata</button>
  </div>
  <input class="search" id="search" placeholder="filter (host, text, module, type)...  press /" autocomplete="off">
  <div class="exwrap">
    <button class="btn" id="exBtn">Export &#9662;</button>
    <div class="exmenu" id="exMenu">
      <a href="/api/export?fmt=md" target="_blank">Report (Markdown)</a>
      <a href="/api/export?fmt=csv" target="_blank">All events (CSV)</a>
      <a href="/api/export?fmt=json" target="_blank">All events (JSON)</a>
      <a href="/api/export?fmt=emails" target="_blank">Emails (.txt)</a>
    </div>
  </div>
</header>
<main>
  <section id="view-overview"></section>
  <section id="view-hosts" style="display:none"></section>
  <section id="view-findings" style="display:none"></section>
  <section id="view-assets" style="display:none"></section>
  <section id="view-emails" style="display:none"></section>
  <section id="view-shots" style="display:none"></section>
  <section id="view-meta" style="display:none"></section>
</main>
<div class="lb" id="lb">
  <div class="lb-bar"><button class="btn" id="lbPrev">&larr;</button>
  <button class="btn" id="lbNext">&rarr;</button>
  <div id="lbLabel" style="word-break:break-all"></div>
  <span id="lbMark" style="display:none;margin-left:auto">
    <button class="btn" id="lb_viewed" onclick="lbMark('viewed')" title="key v">viewed</button>
    <button class="btn" id="lb_revisit" onclick="lbMark('revisit')" title="key r">revisit</button>
  </span>
  <button class="btn" id="lbClose" style="margin-left:auto">close &times;</button></div>
  <div class="lb-body"><div id="lbTech" class="lbtech"></div><img id="lbImg" src="" alt=""></div>
</div>
<div class="toast" id="toast"></div>
<script>
const CFG = __CONFIG__;
const SEVC = CFG.sevColor, SEVR = CFG.sevRank, STATUSES = CFG.statuses;
const COMPARE = CFG.compareActive;
const SMAP = {}; STATUSES.forEach(s=>SMAP[s.key]=s);
const SHOTST = CFG.shotStatuses||[]; const SHOTSMAP = {}; SHOTST.forEach(s=>SHOTSMAP[s.key]=s);
let shotFilter='all';
const BANDS = ['info','low','medium','high','critical'];  // index 1..5 via rank
let DATA={findings:[],assets:[],emails:[],removed:[]}, SHOTS=[], SHOTMAP={}, TECHMAP={}, TAB='overview';
let sevFilter=new Set(), statusFilter=new Set(), typeFilter='';
let juicyOnly=false, newOnly=false, groupSimilar=false, selIdx=-1;
const GROUP_LIMIT=40;              // affected targets shown before "show all"
const expandedGroups=new Set();    // group signatures the user expanded
function expandGroup(sig){expandedGroups.add(sig);renderFindings();}
let HOSTCMDS={};  // host -> deduped recon command list, for "copy all"

function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function hx(js){return esc(js);}  // html-escape a JS expression for use inside a "double-quoted" onclick
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');
  clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove('show'),1400);}
function copy(txt){navigator.clipboard.writeText(txt).then(()=>toast('copied'),()=>toast('copy failed'));}
function q(){return document.getElementById('search').value.toLowerCase().trim();}
function setSearch(v){const el=document.getElementById('search');el.value=v;rerender();}
function rankBand(r){return BANDS[Math.max(0,Math.min(5,r)-1)]||'info';}
function fmt(n){if(!n)return'';const u=['B','KB','MB'];let i=0,v=n;while(v>=1024&&i<2){v/=1024;i++;}return v.toFixed(v<10&&i>0?1:0)+u[i];}

/* display host: hostname when BBOT resolved one, else the IP */
function H(ev){return (ev&&(ev.dhost||ev.host))||'';}

function matchQ(ev){const s=q();if(!s)return true;
  return (ev.text||'').toLowerCase().includes(s)||H(ev).toLowerCase().includes(s)
    ||(ev.host||'').toLowerCase().includes(s)
    ||(ev.title||'').toLowerCase().includes(s)||(ev.type||'').toLowerCase().includes(s)
    ||(ev.module||'').toLowerCase().includes(s);}

/* screenshot <-> host linking */
function shotHostOf(it){let s=(it.label||it.file||'').replace(/^https?:\/\//,'');
  return s.split('/')[0].split(':')[0].toLowerCase();}
function thumbFor(ev){const h=H(ev);if(!h)return null;return SHOTMAP[h.toLowerCase()]||SHOTMAP[(ev.host||'').toLowerCase()]||null;}
function techFor(host){return (host&&TECHMAP[host.toLowerCase()])||[];}
function shotTechs(it){return (it.gwtech&&it.gwtech.length)?it.gwtech:techFor(shotHostOf(it));}
function techChips(techs,limit){if(!techs||!techs.length)return'';limit=limit||8;
  let h='<div class="techrow">';
  techs.slice(0,limit).forEach(t=>h+=`<span class="techchip">${esc(t)}</span>`);
  if(techs.length>limit)h+=`<span class="techchip more">+${techs.length-limit}</span>`;
  return h+'</div>';}

function filteredFindings(){
  return DATA.findings.filter(ev=>{
    if(sevFilter.size&&!sevFilter.has(ev.priority))return false;
    if(statusFilter.size&&!statusFilter.has(ev.triage.status))return false;
    if(juicyOnly&&!(ev.juicy&&ev.juicy.length))return false;
    if(newOnly&&!ev.is_new)return false;
    if(!matchQ(ev))return false;
    return true;
  }).sort((a,b)=>(b.is_new-a.is_new)||(SEVR[b.priority]||0)-(SEVR[a.priority]||0));
}

/* ---------------- OVERVIEW ---------------- */
function renderOverview(){
  const all=[...DATA.findings,...DATA.assets];
  const sevCount={},statCount={};
  DATA.findings.forEach(ev=>{sevCount[ev.priority]=(sevCount[ev.priority]||0)+1;
    statCount[ev.triage.status]=(statCount[ev.triage.status]||0)+1;});
  const typeCount={};all.forEach(ev=>typeCount[ev.type]=(typeCount[ev.type]||0)+1);
  const modCount={};all.forEach(ev=>{if(ev.module)modCount[ev.module]=(modCount[ev.module]||0)+1;});
  const juicyN=all.filter(ev=>ev.juicy&&ev.juicy.length).length;
  const newN=all.filter(ev=>ev.is_new).length;
  const triaged=DATA.findings.filter(ev=>ev.triage.status!=='new').length;
  const total=DATA.findings.length||1;

  let h='<div class="tiles">';
  ['critical','high','medium','low','info'].forEach(s=>{
    h+=`<div class="tile" style="border-left:4px solid ${SEVC[s]}"><div class="n">${sevCount[s]||0}</div><div class="l">${s}</div></div>`;});
  h+=`<div class="tile"><div class="n">${all.length}</div><div class="l">total events</div></div>`;
  h+=`<div class="tile" style="border-left:4px solid #ffc93c"><div class="n">${juicyN}</div><div class="l">&#9733; juicy</div></div>`;
  if(COMPARE){h+=`<div class="tile" style="border-left:4px solid #38c172"><div class="n">${newN}</div><div class="l">new</div></div>`;
    h+=`<div class="tile" style="border-left:4px solid #6b7684"><div class="n">${CFG.removedCount}</div><div class="l">removed</div></div>`;}
  h+='</div>';

  h+=`<h3>Triage progress <span class="muted">(${triaged}/${DATA.findings.length} findings)</span></h3><div class="progress">`;
  STATUSES.forEach(s=>{const c=statCount[s.key]||0;if(c)h+=`<i style="width:${c/total*100}%;background:${s.color}" title="${s.label}: ${c}"></i>`;});
  h+='</div><div class="bar" style="margin-top:8px">';
  STATUSES.forEach(s=>{const c=statCount[s.key]||0;h+=`<span class="sub"><span class="sev-dot" style="background:${s.color}"></span>${s.label}: ${c}</span>&nbsp;&nbsp;`;});
  h+='</div>';

  const top=(obj,n)=>Object.entries(obj).sort((a,b)=>b[1]-a[1]).slice(0,n);
  h+='<div class="tiles" style="margin-top:18px"><div class="tile"><div class="l">Event types</div>';
  top(typeCount,10).forEach(([k,v])=>h+=`<div class="sub">${esc(k)} <span class="muted">x${v}</span></div>`);
  h+='</div><div class="tile"><div class="l">Top modules</div>';
  top(modCount,10).forEach(([k,v])=>h+=`<div class="sub">${esc(k)} <span class="muted">x${v}</span></div>`);
  h+='</div></div>';

  if(COMPARE&&DATA.removed&&DATA.removed.length){
    h+='<h3 style="margin-top:18px">Removed since previous scan <span class="muted">('+DATA.removed.length+')</span></h3>';
    DATA.removed.slice(0,60).forEach(r=>h+=`<div class="sub"><span class="fchip" style="background:${SEVC[r.priority]||'#5c6b7e'}">${r.priority}</span>${esc(r.title)} &middot; <span class="muted">${esc(r.target)}</span></div>`);
    if(DATA.removed.length>60)h+=`<div class="muted">...and ${DATA.removed.length-60} more</div>`;
  }
  h+='<p class="muted" style="margin-top:16px">Shortcuts: <span class="kbd">/</span> search &middot; '
    +'<span class="kbd">j</span>/<span class="kbd">k</span> move &middot; '
    +'<span class="kbd">1</span>-<span class="kbd">7</span> set status (ungrouped Findings)</p>';
  document.getElementById('view-overview').innerHTML=h;
}

/* ---------------- HOSTS (pivot) ---------------- */
function buildHosts(){
  const m={};
  function slot(h){if(!m[h])m[h]={host:h,findings:[],ports:[],urls:[],tech:[],other:[],
    juicy:new Set(),maxsev:0,anyNew:false,shot:null};return m[h];}
  [...DATA.findings,...DATA.assets].forEach(ev=>{
    const h=H(ev).toLowerCase();if(!h)return;const s=slot(h);
    (ev.juicy||[]).forEach(j=>s.juicy.add(j));
    if(ev.is_new)s.anyNew=true;
    if(!s.shot)s.shot=SHOTMAP[h]||null;
    if(ev.lane==='finding'){s.findings.push(ev);s.maxsev=Math.max(s.maxsev,SEVR[ev.priority]||0);}
    else if(ev.type==='OPEN_TCP_PORT')s.ports.push(ev);
    else if(ev.type==='URL'||ev.type==='URL_UNVERIFIED')s.urls.push(ev);
    else if(ev.type==='TECHNOLOGY')s.tech.push(ev);
    else s.other.push(ev);
  });
  return Object.values(m).sort((a,b)=>b.maxsev-a.maxsev||b.juicy.size-a.juicy.size
    ||(b.anyNew-a.anyNew)||a.host.localeCompare(b.host));
}
function hostMatches(s){const qq=q();
  if(juicyOnly&&!s.juicy.size)return false;
  if(newOnly&&!s.anyNew)return false;
  if(!qq)return true;
  if(s.host.includes(qq))return true;
  return [...s.findings,...s.ports,...s.urls,...s.tech,...s.other]
    .some(ev=>matchQ(ev));
}
function renderHosts(){
  flushNotes();
  HOSTCMDS={};
  const hosts=buildHosts().filter(hostMatches);
  let h='<div class="bar">';
  h+=`<span class="chip ${juicyOnly?'on':''}" style="${juicyOnly?'background:#ffc93c':''}" onclick="toggleJuicy()">&#9733; juicy only</span>`;
  if(COMPARE)h+=`<span class="chip ${newOnly?'on':''}" style="${newOnly?'background:#38c172':''}" onclick="toggleNew()">new only</span>`;
  h+=`<span class="muted">${hosts.length} hosts</span></div>`;
  if(!hosts.length){h+='<div class="empty">No hosts match.</div>';document.getElementById('view-hosts').innerHTML=h;return;}
  hosts.forEach(s=>{
    const band=rankBand(s.maxsev),acc=s.maxsev?SEVC[band]:'#2a3342';
    const open=(s.maxsev>=3||s.juicy.size||(COMPARE&&s.anyNew))?' open':'';
    h+=`<details class="host"${open} style="border-left-color:${acc}"><summary>`;
    h+=`<span class="caret">&#9656;</span>`;
    if(s.maxsev)h+=`<span class="sev-dot" style="background:${acc}"></span>`;
    h+=`<span class="hname">${esc(s.host)}</span>`;
    if(s.juicy.size)h+=`<span class="star" title="${esc([...s.juicy].join(', '))}">&#9733;</span>`;
    if(COMPARE&&s.anyNew)h+=`<span class="newbadge">NEW</span>`;
    h+=`<span class="hmeta">${s.findings.length} findings &middot; ${s.ports.length} ports &middot; ${s.urls.length} urls &middot; ${s.tech.length} tech</span></summary>`;
    h+='<div class="body" style="overflow:hidden">';
    const hc=hostCommands(s);HOSTCMDS[s.host]=hc;
    if(s.shot)h+=`<img class="hthumb" style="float:right;margin:0 0 8px 10px" src="${s.shot.src}" onclick="${hx('openImg('+JSON.stringify(s.shot.src)+','+JSON.stringify(s.host)+')')}">`;
    if(s.findings.length){h+='<div class="sec"><h4>Findings</h4>';
      s.findings.sort((a,b)=>(SEVR[b.priority]||0)-(SEVR[a.priority]||0)).forEach(ev=>{
        const st=SMAP[ev.triage.status]||STATUSES[0];
        h+=`<div class="row" style="cursor:pointer" onclick="${hx('jumpHost('+JSON.stringify(s.host)+')')}">
          <span class="fchip" style="background:${SEVC[ev.priority]}">${ev.priority}</span>${esc(ev.title)}
          <span class="statustag" style="background:${st.color}">${st.label}</span></div>`;});
      h+='</div>';}
    if(hc.length){
      h+=`<details class="sec"><summary><span class="caret">&#9656;</span><span class="h4lbl">Recon commands (${hc.length})</span> <button class="copy" onclick="${hx('event.stopPropagation();copyAllHost('+JSON.stringify(s.host)+')')}">copy all</button></summary>`;
      hc.forEach(c=>h+=`<div class="cmd"><code>${esc(c[1])}</code><button class="copy" onclick="${hx('copy('+JSON.stringify(c[1])+')')}">copy</button></div>`);
      h+='</details>';}
    if(s.ports.length){h+='<div class="sec"><h4>Open ports</h4>';
      s.ports.sort((a,b)=>a.port-b.port).forEach(ev=>h+=`<div class="row mono"><span class="tgt" onclick="${hx('copy('+JSON.stringify(s.host+':'+ev.port)+')')}">${s.host}:${ev.port}</span> <span class="muted">${esc(ev.tags.join(' '))}</span></div>`);
      h+='</div>';}
    if(s.urls.length){h+='<div class="sec"><h4>URLs</h4>';
      s.urls.slice(0,40).forEach(ev=>h+=`<div class="row mono"><span class="tgt" onclick="${hx('copy('+JSON.stringify(ev.url||ev.data_str)+')')}">${esc(ev.url||ev.data_str)}</span></div>`);
      if(s.urls.length>40)h+=`<div class="muted">...and ${s.urls.length-40} more</div>`;h+='</div>';}
    if(s.tech.length){h+='<div class="sec"><h4>Technology</h4>';
      s.tech.forEach(ev=>h+=`<div class="row">${esc(ev.tech||ev.data_str)}</div>`);h+='</div>';}
    if(s.other.length){h+=`<div class="sec"><h4>Other</h4><div class="muted">${s.other.map(e=>esc(e.type)).join(', ')}</div></div>`;}
    h+='</div></details>';
  });
  document.getElementById('view-hosts').innerHTML=h;
}
function jumpHost(host){document.getElementById('search').value=host;show('findings');}

/* aggregate a deduped, ordered recon command set for one host */
function hostCommands(s){
  const out=[],seen=new Set();
  const add=(label,cmd)=>{if(cmd&&!seen.has(cmd)){seen.add(cmd);out.push([label,cmd]);}};
  // one consolidated service scan across every open port, else a top-ports sweep
  const ports=[...new Set(s.ports.map(p=>p.port).filter(Boolean))].sort((a,b)=>a-b);
  if(ports.length)add('Service scan (all ports)','nmap -sCV -p'+ports.join(',')+' '+s.host);
  else add('Port scan','nmap -sCV --top-ports 1000 '+s.host);
  // pull every event's web/recon commands, minus per-port nmap and repeated screenshots
  [...s.findings,...s.urls,...s.other,...s.tech,...s.ports].forEach(ev=>(ev.commands||[]).forEach(c=>{
    if(/^nmap /.test(c[1])||/^gowitness /.test(c[1]))return;
    add(c[0],c[1]);
  }));
  add('Screenshot','gowitness single https://'+s.host);
  return out;
}
function copyAllHost(host){const hc=HOSTCMDS[host]||[];if(!hc.length)return;
  const txt=hc.map(c=>c[1]).join('\n');
  navigator.clipboard.writeText(txt).then(()=>toast('copied '+hc.length+' commands'),()=>toast('copy failed'));}

/* ---------------- FINDINGS ---------------- */
function statusButtons(ev,mini){
  return STATUSES.map((s,i)=>{const on=ev.triage.status===s.key;
    return `<button class="sbtn ${mini?'mini':''} ${on?'on':''}" data-eid="${ev.id}" data-sk="${s.key}" style="${on?('background:'+s.color):''}"
      onclick="setStatus('${ev.id}','${s.key}')" title="key ${i+1}">${s.label}</button>`;}).join('');
}
function badges(ev){let b='';
  if(COMPARE&&ev.is_new)b+='<span class="newbadge">NEW</span> ';
  if(ev.juicy&&ev.juicy.length)ev.juicy.forEach(j=>b+=`<span class="juicytag">&#9733; ${esc(j)}</span> `);
  return b;}
function playbookHTML(ev){let h='';
  if(ev.playbook&&ev.playbook.length){
    h+=`<details open><summary>What a tester can do</summary><ul class="play">`;
    ev.playbook.forEach(p=>h+=`<li>${esc(p)}</li>`);h+=`</ul>`;
    if(ev.commands&&ev.commands.length){h+='<div style="margin-top:6px">';
      ev.commands.forEach(c=>h+=`<div class="cmd"><code>${esc(c[1])}</code><button class="copy" onclick="${hx('copy('+JSON.stringify(c[1])+')')}">copy</button></div>`);
      h+='</div>';}
    h+=`</details>`;}
  return h;}
function cardHTML(ev,idx){
  const sc=SEVC[ev.priority]||'#5c6b7e',st=SMAP[ev.triage.status]||STATUSES[0];
  const tgt=ev.url||(ev.port?`${H(ev)}:${ev.port}`:H(ev))||ev.data_str.slice(0,90);
  const thumb=thumbFor(ev);
  let h=`<div class="card ${idx===selIdx?'sel':''}" style="border-left-color:${sc}" id="card-${ev.id}" data-eid="${ev.id}" data-idx="${idx}">`;
  if(thumb)h+=`<img class="cardthumb" src="${thumb.src}" onclick="${hx('event.stopPropagation();openImg('+JSON.stringify(thumb.src)+','+JSON.stringify(tgt)+')')}">`;
  h+=`<h3><span class="sevtag" style="background:${sc}">${ev.priority}</span>${esc(ev.title)}
      <span class="statustag" style="background:${st.color}">${st.label}</span></h3>`;
  h+=`<div>${badges(ev)}</div>`;
  h+=`<div class="tgt" onclick="${hx('copy('+JSON.stringify(tgt)+')')}" title="click to copy">${esc(tgt)}</div>`;
  h+=`<div class="sub">${esc(ev.type)} &middot; ${esc(ev.module||'-')}${ev.tags.length?' &middot; '+esc(ev.tags.join(', ')):''}</div>`;
  if(ev.why)h+=`<div class="why">${esc(ev.why)}</div>`;
  h+=playbookHTML(ev);
  h+=`<div class="statusrow">${statusButtons(ev,false)}</div>`;
  h+=`<textarea class="notes" placeholder="tester notes (autosaves)..." oninput="noteInput('${ev.id}',this.value)" onblur="saveNotes('${ev.id}',this.value)">${esc(ev.triage.notes||'')}</textarea>`;
  h+=`</div>`;return h;
}
function groupHTML(sig,items){
  const rep=items[0],sc=SEVC[rep.priority]||'#5c6b7e';
  const anyNew=COMPARE&&items.some(i=>i.is_new);
  const juicy=new Set();items.forEach(i=>(i.juicy||[]).forEach(j=>juicy.add(j)));
  // status breakdown across the group, in workflow order
  const cnt={};items.forEach(ev=>{const k=ev.triage.status||'new';cnt[k]=(cnt[k]||0)+1;});
  let h=`<div class="card" style="border-left-color:${sc}">`;
  h+=`<h3><span class="sevtag" style="background:${sc}">${rep.priority}</span>${esc(rep.title)}
      <span class="muted">x${items.length}</span></h3>`;
  let b='';if(anyNew)b+='<span class="newbadge">NEW</span> ';
  [...juicy].forEach(j=>b+=`<span class="juicytag">&#9733; ${esc(j)}</span> `);
  if(b)h+=`<div>${b}</div>`;
  h+=`<div class="sub">${esc(rep.type)} &middot; ${esc(rep.module||'-')}</div>`;
  if(rep.why)h+=`<div class="why">${esc(rep.why)}</div>`;
  h+=playbookHTML(rep);
  // --- affected targets: compact, scannable, paginated, drill-down per row ---
  const expanded=expandedGroups.has(sig);
  const shown=expanded?items:items.slice(0,GROUP_LIMIT);
  let sum='';STATUSES.forEach(s=>{if(cnt[s.key])sum+=`<span class="gsum"><span class="sev-dot" style="background:${s.color}"></span><b>${cnt[s.key]}</b> ${esc(s.label.toLowerCase())}</span>&nbsp; `;});
  h+=`<div class="sec" style="margin-top:8px"><h4 style="margin:0 0 4px;font-size:12px;color:var(--muted)">Affected targets (${items.length})</h4>`;
  if(sum)h+=`<div style="margin:2px 0 6px">${sum}</div>`;
  shown.forEach(ev=>{const tgt=ev.url||(ev.port?`${H(ev)}:${ev.port}`:H(ev))||ev.data_str.slice(0,120);
    const st=SMAP[ev.triage.status]||STATUSES[0];
    h+=`<div class="inst" data-eid="${ev.id}">
      <span class="sdot" style="background:${st.color}" title="${esc(st.label)}"></span>
      <span class="it" onclick="${hx('copy('+JSON.stringify(tgt)+')')}" title="click to copy">${esc(tgt)}</span>
      <span class="statustag mini" style="background:${st.color}">${esc(st.label)}</span>
      <details class="rowtri"><summary>triage</summary>
        <div class="statusrow">${statusButtons(ev,true)}</div>
        <input class="notes" style="min-height:28px;width:100%" placeholder="notes..." value="${esc(ev.triage.notes||'')}" oninput="noteInput('${ev.id}',this.value)" onblur="saveNotes('${ev.id}',this.value)">
      </details></div>`;});
  if(!expanded&&items.length>GROUP_LIMIT)
    h+=`<button class="gmore" onclick="${hx('expandGroup('+JSON.stringify(sig)+')')}">show all ${items.length} targets</button>`;
  h+='</div></div>';return h;
}
function renderFindings(){
  flushNotes();                 // persist any in-progress notes before rebuilding the DOM
  const list=filteredFindings();
  let h='<div class="bar">severity:';
  ['critical','high','medium','low','info'].forEach(s=>{
    h+=`<span class="chip ${sevFilter.has(s)?'on':''}" style="${sevFilter.has(s)?('background:'+SEVC[s]):''}"
      onclick="toggleSev('${s}')"><span class="sev-dot" style="background:${SEVC[s]}"></span>${s}</span>`;});
  h+='</div><div class="bar">status:';
  STATUSES.forEach(s=>{h+=`<span class="chip ${statusFilter.has(s.key)?'on':''}"
    style="${statusFilter.has(s.key)?('background:'+s.color):''}" onclick="toggleStatus('${s.key}')">${s.label}</span>`;});
  h+='</div><div class="bar">';
  h+=`<span class="chip ${juicyOnly?'on':''}" style="${juicyOnly?'background:#ffc93c':''}" onclick="toggleJuicy()">&#9733; juicy only</span>`;
  if(COMPARE)h+=`<span class="chip ${newOnly?'on':''}" style="${newOnly?'background:#38c172':''}" onclick="toggleNew()">new only</span>`;
  h+=`<span class="chip ${groupSimilar?'on':''}" style="${groupSimilar?'background:#4a9eff':''}" onclick="toggleGroup()">group similar</span>`;
  h+=`<span class="muted">${list.length} shown</span></div>`;

  if(!list.length){h+='<div class="empty">No findings match the current filters.</div>';
    document.getElementById('view-findings').innerHTML=h;window._flist=[];return;}

  if(groupSimilar){
    const groups={};list.forEach(ev=>{const sig=ev.title+'|'+ev.priority+'|'+ev.module;(groups[sig]=groups[sig]||[]).push(ev);});
    Object.entries(groups).sort((a,b)=>(SEVR[b[1][0].priority]||0)-(SEVR[a[1][0].priority]||0)||b[1].length-a[1].length)
      .forEach(([sig,items])=>h+=groupHTML(sig,items));
    window._flist=[];
  }else{
    list.forEach((ev,i)=>h+=cardHTML(ev,i));window._flist=list;
  }
  document.getElementById('view-findings').innerHTML=h;
}

/* ---------------- ASSETS ---------------- */
function renderAssets(){
  flushNotes();
  let rows=DATA.assets.filter(matchQ).filter(ev=>!typeFilter||ev.type===typeFilter);
  if(juicyOnly)rows=rows.filter(ev=>ev.juicy&&ev.juicy.length);
  if(newOnly)rows=rows.filter(ev=>ev.is_new);
  rows.sort((a,b)=>a.type.localeCompare(b.type)||H(a).localeCompare(H(b)));
  const types={};DATA.assets.forEach(ev=>types[ev.type]=(types[ev.type]||0)+1);
  let h='<div class="bar"><span class="chip '+(typeFilter?'':'on')+'" onclick="setType(\'\')">all</span>';
  Object.entries(types).sort((a,b)=>b[1]-a[1]).forEach(([t,c])=>
    h+=`<span class="chip ${typeFilter===t?'on':''}" onclick="setType('${t}')">${esc(t)} <span class="muted">${c}</span></span>`);
  h+='</div><div class="bar">';
  h+=`<span class="chip ${juicyOnly?'on':''}" style="${juicyOnly?'background:#ffc93c':''}" onclick="toggleJuicy()">&#9733; juicy only</span>`;
  if(COMPARE)h+=`<span class="chip ${newOnly?'on':''}" style="${newOnly?'background:#38c172':''}" onclick="toggleNew()">new only</span>`;
  h+=`<span class="muted">${rows.length} shown</span></div>`;
  h+='<p class="muted" style="margin:-4px 0 10px">Click a row for the tester playbook.</p>';
  h+='<table><thead><tr><th></th><th>Type</th><th>Target</th><th>Module</th><th>Tags</th></tr></thead><tbody>';
  rows.forEach(ev=>{const tgt=ev.url||(ev.port?`${H(ev)}:${ev.port}`:H(ev))||ev.data_str;
    const star=(ev.juicy&&ev.juicy.length)?'<span class="star" title="'+esc(ev.juicy.join(', '))+'">&#9733;</span>':'';
    const nb=(COMPARE&&ev.is_new)?' <span class="newbadge">NEW</span>':'';
    h+=`<tr style="cursor:pointer" onclick="toggleAsset('${ev.id}')"><td>${star}</td><td>${esc(ev.type)}</td>
      <td class="mono">${esc(tgt)}${nb}</td><td class="muted">${esc(ev.module||'-')}</td><td class="muted">${esc(ev.tags.join(', '))}</td></tr>`;
    let d=`<tr id="ax-${ev.id}" style="display:none"><td></td><td colspan="4" style="background:var(--panel)">`;
    if(ev.why)d+=`<div class="why">${esc(ev.why)}</div>`;
    d+=`<div class="tgt" onclick="${hx('copy('+JSON.stringify(tgt)+')')}" title="copy target">${esc(tgt)} &#128203;</div>`;
    if(ev.playbook&&ev.playbook.length){d+='<ul class="play">';ev.playbook.forEach(p=>d+=`<li>${esc(p)}</li>`);d+='</ul>';}
    if(ev.commands&&ev.commands.length)ev.commands.forEach(c=>d+=`<div class="cmd"><code>${esc(c[1])}</code><button class="copy" onclick="${hx('copy('+JSON.stringify(c[1])+')')}">copy</button></div>`);
    d+='</td></tr>';h+=d;});
  h+='</tbody></table>';
  document.getElementById('view-assets').innerHTML=h;
}

/* ---------------- SCREENSHOTS ---------------- */
let shotView=[],shotCur=-1;
function shotButtons(it){
  return SHOTST.filter(s=>s.key!=='new').map(s=>{const on=(it.status||'new')===s.key;
    return `<button class="sbtn mini ${on?'on':''}" style="${on?('background:'+s.color):''}"
      onclick="${hx('event.stopPropagation();setShotStatus('+JSON.stringify(it.rel)+','+JSON.stringify(s.key)+')')}">${s.label}</button>`;}).join(' ');
}
function renderShots(){
  const s=q();
  let view=SHOTS.filter(it=>{
    if(shotFilter!=='all'&&(it.status||'new')!==shotFilter)return false;
    if(!s)return true;
    const techs=shotTechs(it);
    return it.label.toLowerCase().includes(s)||it.file.toLowerCase().includes(s)
      ||techs.some(t=>t.toLowerCase().includes(s));});
  shotView=view;
  if(!SHOTS.length){document.getElementById('view-shots').innerHTML=
    '<div class="empty">No screenshots loaded. Start bscope with <span class="kbd">--shots &lt;folder&gt;</span> pointing at your gowitness/screenshots dir.</div>';return;}
  const cnt={};SHOTS.forEach(it=>{const k=it.status||'new';cnt[k]=(cnt[k]||0)+1;});
  let h='<div class="bar">';
  h+=`<span class="chip ${shotFilter==='all'?'on':''}" onclick="setShotFilter('all')">all ${SHOTS.length}</span>`;
  SHOTST.forEach(st=>h+=`<span class="chip ${shotFilter===st.key?'on':''}" style="${shotFilter===st.key?('background:'+st.color):''}" onclick="setShotFilter('${st.key}')">${st.label} ${cnt[st.key]||0}</span>`);
  h+=`<span class="muted">${shotView.length} shown</span></div>`;
  if(!Object.keys(TECHMAP).length&&!SHOTS.some(it=>it.gwtech&&it.gwtech.length))
    h+='<p class="muted" style="margin:-4px 0 10px">No tech data &mdash; run bbot with the <span class="kbd">wappalyzer</span> module, or pass <span class="kbd">--gowitness-db</span> for per-URL tech stacks.</p>';
  if(!shotView.length){h+='<div class="empty">No screenshots matched.</div>';document.getElementById('view-shots').innerHTML=h;return;}
  h+='<div class="grid">';
  shotView.forEach((it,i)=>{const st=SHOTSMAP[it.status||'new']||SHOTST[0];
    const acc=(it.status&&it.status!=='new')?st.color:'var(--line)';
    h+=`<div class="shot" style="border-color:${acc}">
      <div class="thumb" onclick="openLb(${i})"><img loading="lazy" src="${it.src}"></div>
      <div class="m"><div class="lbl" title="${esc(it.label)}">${esc(it.label)}</div>
      <div class="sub">${esc(it.file)}${it.size?(' &middot; '+fmt(it.size)):''}</div>
      ${techChips(shotTechs(it))}
      <div class="shotbtns">${shotButtons(it)}</div></div></div>`;});
  h+='</div>';
  document.getElementById('view-shots').innerHTML=h;
}
function setShotFilter(k){shotFilter=k;renderShots();}
function setShotStatus(rel,status){
  const it=SHOTS.find(x=>x.rel===rel);if(!it)return;
  const next=((it.status||'new')===status)?'new':status;
  fetch('/api/shot_triage',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({rel,status:next})}).then(r=>r.json()).then(res=>{
    it.status=res.status;
    toast('screenshot: '+((SHOTSMAP[res.status]||{}).label||res.status));
    if(TAB==='shots'&&!lbOpen())renderShots();
    updateLbMark();
  });
}
function lbOpen(){return document.getElementById('lb').classList.contains('open');}
function setLbTech(list){const box=document.getElementById('lbTech');if(box)box.innerHTML=techChips(list,20);}
function openImg(src,label){shotCur=-1;document.getElementById('lbImg').src=src;
  document.getElementById('lbLabel').textContent=label||'';
  const h=(label||'').replace(/^https?:\/\//,'').split('/')[0].split(':')[0];setLbTech(techFor(h));
  document.getElementById('lb').classList.add('open');updateLbMark();}
function openLb(i){shotCur=i;const it=shotView[i];if(!it)return;
  document.getElementById('lbImg').src=it.src;
  document.getElementById('lbLabel').textContent=it.label+'  ('+it.file+')';
  setLbTech(shotTechs(it));
  document.getElementById('lb').classList.add('open');updateLbMark();}
function closeLb(){document.getElementById('lb').classList.remove('open');shotCur=-1;
  if(TAB==='shots')renderShots();}
function lbStep(d){if(shotCur<0)return;const n=shotCur+d;if(n>=0&&n<shotView.length)openLb(n);}
function lbMark(status){if(shotCur<0)return;const it=shotView[shotCur];if(it)setShotStatus(it.rel,status);}
function updateLbMark(){const box=document.getElementById('lbMark');if(!box)return;
  if(shotCur<0||!shotView[shotCur]){box.style.display='none';return;}
  box.style.display='';const it=shotView[shotCur];
  SHOTST.filter(s=>s.key!=='new').forEach(s=>{const b=document.getElementById('lb_'+s.key);if(!b)return;
    const on=(it.status||'new')===s.key;b.classList.toggle('on',on);b.style.background=on?s.color:'';});
}

/* ---------------- triage ---------------- */
/* debounced, coalesced re-renders so a click or keystroke never rebuilds the
   whole list synchronously more than once per frame-ish */
const _rq={};
function schedule(name,fn,ms){clearTimeout(_rq[name]);_rq[name]=setTimeout(fn,ms||120);}

/* --- note autosave: survives re-renders, tab switches and page unload --- */
const noteDrafts={}, noteTimers={};
function noteInput(id,val){
  noteDrafts[id]=val;
  clearTimeout(noteTimers[id]);
  noteTimers[id]=setTimeout(()=>saveNotes(id,val,true),600);
}
function flushNotes(){                 // save every pending draft immediately
  Object.keys(noteDrafts).forEach(id=>{
    clearTimeout(noteTimers[id]);
    saveNotes(id,noteDrafts[id],true);
  });
}
window.addEventListener('beforeunload',flushNotes);
document.addEventListener('visibilitychange',()=>{if(document.hidden)flushNotes();});

/* update only the status visuals for one finding, in place (no list rebuild) */
function paintStatus(id){
  const ev=findEv(id);if(!ev)return;
  const st=SMAP[ev.triage.status]||STATUSES[0];
  document.querySelectorAll('[data-eid="'+id+'"]').forEach(box=>{
    box.querySelectorAll('.statustag').forEach(t=>{t.style.background=st.color;t.textContent=st.label;});
    box.querySelectorAll('.sdot').forEach(d=>{d.style.background=st.color;d.title=st.label;});
    box.querySelectorAll('.sbtn[data-sk]').forEach(b=>{const on=b.getAttribute('data-sk')===ev.triage.status;
      b.classList.toggle('on',on);b.style.background=on?st.color:'';});
  });
}
function setStatus(id,status){
  const ev0=findEv(id);if(ev0)ev0.triage={...ev0.triage,status};  // optimistic
  paintStatus(id);
  toast('status: '+(SMAP[status]?SMAP[status].label:status));
  fetch('/api/triage',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id,status})}).then(r=>r.json()).then(res=>{
    const ev=findEv(id);if(ev)ev.triage=res;paintStatus(id);
    // the item may now fall outside an active status filter -> re-render (debounced)
    if(TAB==='findings'&&statusFilter.size)schedule('find',renderFindings,150);
    schedule('ov',renderOverview,200);
    if(TAB==='hosts')schedule('hosts',renderHosts,250);
  }).catch(()=>toast('status save failed'));
}
function saveNotes(id,notes,quiet){
  fetch('/api/triage',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id,notes})}).then(r=>r.json()).then(res=>{
    const ev=findEv(id);if(ev)ev.triage=res;
    if(noteDrafts[id]===notes)delete noteDrafts[id];   // draft is now persisted
    if(!quiet)toast('notes saved');
  }).catch(()=>toast('notes save failed'));
}
function findEv(id){return DATA.findings.find(e=>e.id===id)||DATA.assets.find(e=>e.id===id);}

/* ---------------- filters/tabs ---------------- */
function toggleSev(s){sevFilter.has(s)?sevFilter.delete(s):sevFilter.add(s);renderFindings();}
function toggleStatus(s){statusFilter.has(s)?statusFilter.delete(s):statusFilter.add(s);renderFindings();}
function setType(t){typeFilter=t;renderAssets();}
function toggleAsset(id){const r=document.getElementById('ax-'+id);if(r)r.style.display=(r.style.display==='none'?'':'none');}
function toggleJuicy(){juicyOnly=!juicyOnly;rerender();}
function toggleNew(){newOnly=!newOnly;rerender();}
function toggleGroup(){groupSimilar=!groupSimilar;selIdx=-1;renderFindings();}
/* ---------------- METADATA (raw BBOT records) ---------------- */
let META=null, METALOADED=false;
function toggleMeta(i){const r=document.getElementById('mx-'+i);if(r)r.style.display=(r.style.display==='none'?'':'none');}
function renderMeta(){
  const el=document.getElementById('view-meta');
  if(!METALOADED){
    el.innerHTML='<div class="empty">Loading metadata&hellip;</div>';
    fetch('/api/raw').then(r=>r.json()).then(d=>{META=d;METALOADED=true;if(TAB==='meta')renderMeta();})
      .catch(()=>{el.innerHTML='<div class="empty">Failed to load metadata.</div>';});
    return;}
  const s=q();
  let list=META;
  if(s)list=META.filter(m=>(m.type||'').toLowerCase().includes(s)||(m.module||'').toLowerCase().includes(s)
    ||(m.target||'').toLowerCase().includes(s)||JSON.stringify(m.raw).toLowerCase().includes(s));
  const byType={};META.forEach(m=>byType[m.type]=(byType[m.type]||0)+1);
  let h='<div class="bar"><span class="muted">'+META.length+' events'+(s?(' &middot; '+list.length+' shown'):'')+'</span>';
  h+='<a class="chip" href="/api/export?fmt=json" target="_blank" style="text-decoration:none">&#11015; full JSON</a></div>';
  h+='<div class="bar">';Object.entries(byType).sort((a,b)=>b[1]-a[1]).forEach(([t,c])=>
    h+=`<span class="chip" onclick="setSearch(${JSON.stringify(t)})">${esc(t)} <span class="muted">${c}</span></span>`);
  h+='</div>';
  h+='<p class="muted" style="margin:-4px 0 10px">Every field BBOT captured for each event, after dedupe. Click a row to expand the full raw record.</p>';
  if(!list.length){h+='<div class="empty">No events matched.</div>';el.innerHTML=h;return;}
  h+='<table><thead><tr><th>Type</th><th>Target</th><th>Module</th><th>Tags</th></tr></thead><tbody>';
  list.forEach((m,i)=>{
    h+=`<tr style="cursor:pointer" onclick="toggleMeta(${i})"><td>${esc(m.type)}</td>`
      +`<td class="mono">${esc(m.target||'')}</td><td class="muted">${esc(m.module||'-')}</td>`
      +`<td class="muted">${esc((m.tags||[]).join(', '))}</td></tr>`;
    h+=`<tr id="mx-${i}" style="display:none"><td colspan="4" style="background:var(--panel)">`
      +`<pre class="rawjson">${esc(JSON.stringify(m.raw,null,2))}</pre></td></tr>`;
  });
  h+='</tbody></table>';
  el.innerHTML=h;
}

/* ---------------- EMAILS ---------------- */
function copyEmails(){copy((DATA.emails||[]).join('\n'));toast((DATA.emails||[]).length+' emails copied');}
function renderEmails(){
  const all=DATA.emails||[];const s=q();
  const list=s?all.filter(e=>e.toLowerCase().includes(s)):all;
  let h='<div class="bar">';
  h+=`<span class="muted">${all.length} email${all.length===1?'':'s'} found${s?(' &middot; '+list.length+' shown'):''}</span>`;
  if(all.length){
    h+=`<span class="chip" onclick="copyEmails()">&#128203; copy all</span>`;
    h+=`<a class="chip" href="/api/export?fmt=emails" download="emails.txt" style="text-decoration:none">&#11015; download .txt</a>`;}
  h+='</div>';
  if(!all.length){
    h+='<div class="empty">No emails discovered. Run bbot with email modules '
      +'(<span class="kbd">emailformat</span>, <span class="kbd">pgp</span>, '
      +'<span class="kbd">skymem</span>, <span class="kbd">hunterio</span>, '
      +'<span class="kbd">dehashed</span>&hellip;) to populate this.</div>';
    document.getElementById('view-emails').innerHTML=h;return;}
  h+='<p class="muted" style="margin:-4px 0 10px">Deduplicated addresses. Export the .txt and feed it into user-enumeration tools (onedrive_user_enum, o365enum, &hellip;).</p>';
  const byDom={};all.forEach(e=>{const d=(e.split('@')[1]||'?');byDom[d]=(byDom[d]||0)+1;});
  h+='<div class="bar">';Object.entries(byDom).sort((a,b)=>b[1]-a[1]).forEach(([d,c])=>
    h+=`<span class="chip" onclick="setSearch('@'+${JSON.stringify(d)})">${esc(d)} <span class="muted">${c}</span></span>`);
  h+='</div>';
  if(!list.length){h+='<div class="empty">No emails matched.</div>';document.getElementById('view-emails').innerHTML=h;return;}
  h+='<table><thead><tr><th>#</th><th>Email</th><th>Domain</th></tr></thead><tbody>';
  list.forEach((e,i)=>{const dom=e.split('@')[1]||'';
    h+=`<tr><td class="muted">${i+1}</td><td class="mono" style="cursor:pointer" title="copy" onclick="${hx('copy('+JSON.stringify(e)+')')}">${esc(e)} &#128203;</td><td class="muted">${esc(dom)}</td></tr>`;});
  h+='</tbody></table>';
  document.getElementById('view-emails').innerHTML=h;
}

function rerender(){if(TAB==='findings')renderFindings();else if(TAB==='assets')renderAssets();else if(TAB==='hosts')renderHosts();else if(TAB==='emails')renderEmails();else if(TAB==='shots')renderShots();else if(TAB==='meta')renderMeta();}

function show(tab){TAB=tab;selIdx=-1;
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));
  ['overview','hosts','findings','assets','emails','shots','meta'].forEach(t=>
    document.getElementById('view-'+t).style.display=(t===tab?'':'none'));
  if(tab==='overview')renderOverview();else if(tab==='hosts')renderHosts();
  else if(tab==='findings')renderFindings();else if(tab==='assets')renderAssets();
  else if(tab==='emails')renderEmails();
  else if(tab==='shots')renderShots();
  else if(tab==='meta')renderMeta();
}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>show(b.dataset.tab));
document.getElementById('search').addEventListener('input',()=>{
  // Overview has no searchable list; jump to Findings so a query always shows results.
  if(q()&&TAB==='overview'){show('findings');return;}
  schedule('search',rerender,180);
});

/* export menu */
const exBtn=document.getElementById('exBtn'),exMenu=document.getElementById('exMenu');
exBtn.onclick=e=>{e.stopPropagation();exMenu.classList.toggle('open');};
document.addEventListener('click',()=>exMenu.classList.remove('open'));

/* lightbox */
document.getElementById('lbClose').onclick=closeLb;
document.getElementById('lbPrev').onclick=()=>lbStep(-1);
document.getElementById('lbNext').onclick=()=>lbStep(1);
document.getElementById('lb').addEventListener('click',e=>{if(e.target.id==='lb')closeLb();});

/* keyboard */
document.addEventListener('keydown',e=>{
  if(document.getElementById('lb').classList.contains('open')){
    if(e.key==='Escape')closeLb();else if(e.key==='ArrowLeft')lbStep(-1);
    else if(e.key==='ArrowRight')lbStep(1);
    else if(e.key==='v')lbMark('viewed');else if(e.key==='r')lbMark('revisit');return;}
  const tag=(e.target.tagName||'').toLowerCase();
  if(tag==='input'||tag==='textarea'){if(e.key==='Escape')e.target.blur();return;}
  if(e.key==='/'){e.preventDefault();document.getElementById('search').focus();return;}
  if(TAB!=='findings'||groupSimilar)return;
  const list=window._flist||[];
  if(e.key==='j'){selIdx=Math.min(selIdx+1,list.length-1);renderFindings();scrollSel();}
  else if(e.key==='k'){selIdx=Math.max(selIdx-1,0);renderFindings();scrollSel();}
  else if(/^[1-7]$/.test(e.key)&&selIdx>=0&&list[selIdx]){const s=STATUSES[parseInt(e.key)-1];if(s)setStatus(list[selIdx].id,s.key);}
});
function scrollSel(){const el=document.querySelector('.card.sel');if(el)el.scrollIntoView({block:'nearest'});}

/* load */
Promise.all([
  fetch('/api/findings').then(r=>r.json()),
  fetch('/api/screenshots').then(r=>r.json()).catch(()=>[])
]).then(([d,shots])=>{
  DATA=d;DATA.removed=d.removed||[];DATA.emails=d.emails||[];
  SHOTS=shots.map(it=>({...it,status:it.status||'new',src:'/img/'+it.rel.split('/').map(encodeURIComponent).join('/')}));
  SHOTMAP={};SHOTS.forEach(it=>{const h=shotHostOf(it);if(h&&!SHOTMAP[h])SHOTMAP[h]=it;});
  TECHMAP={};[...DATA.findings,...DATA.assets].forEach(ev=>{
    if(ev.tech&&H(ev)){const h=H(ev).toLowerCase();(TECHMAP[h]=TECHMAP[h]||[]);
      if(!TECHMAP[h].includes(ev.tech))TECHMAP[h].push(ev.tech);}});
  show('overview');
});
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    events = []
    findings = []
    assets = []
    store = None
    shots = []
    shots_root = ""
    gw_by_file = {}           # gowitness: screenshot basename -> [tech]
    gw_by_url = {}            # gowitness: url -> [tech]
    prev_ids = set()          # ids present in the --compare scan (diff mode)
    removed = []              # events in the previous scan that are gone now
    compare_active = False

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---- client view of an event (+ live triage state) ----
    def _client_event(self, ev):
        d = {k: ev[k] for k in ("id", "type", "module", "tags", "data_str", "host",
                                "dhost", "url", "port", "scheme", "priority", "title", "why",
                                "playbook", "commands", "text", "lane", "juicy", "tech")}
        d["triage"] = self.store.get(ev["id"])
        d["is_new"] = self.compare_active and ev["id"] not in self.prev_ids
        return d

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            cfg = json.dumps({"sevColor": SEV_COLOR, "sevRank": SEV_RANK,
                              "statuses": STATUSES, "shotStatuses": SHOT_STATUSES,
                              "compareActive": self.compare_active,
                              "removedCount": len(self.removed)})
            page = PAGE.replace("__CONFIG__", cfg).replace(
                "__TITLE__", html.escape(os.path.basename(getattr(self, "src_name", "scan"))))
            return self._send(200, page)

        if path == "/api/findings":
            payload = {
                "findings": [self._client_event(e) for e in self.findings],
                "assets": [self._client_event(e) for e in self.assets],
                "emails": collect_emails(self.events),
                "removed": self.removed,
            }
            return self._send(200, json.dumps(payload), ctype="application/json; charset=utf-8")

        if path == "/api/raw":
            rows = [meta_row(e) for e in self.events]
            return self._send(200, json.dumps(rows), ctype="application/json; charset=utf-8")

        if path == "/api/screenshots":
            out = []
            for it in self.shots:
                gw = self.gw_by_file.get(it["file"]) or self.gw_by_url.get(it.get("label", "")) or []
                out.append(dict(it, status=self.store.get("shot:" + it["rel"])["status"], gwtech=gw))
            return self._send(200, json.dumps(out), ctype="application/json; charset=utf-8")

        if path == "/api/export":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            fmt = (qs.get("fmt", ["md"])[0]).lower()
            if fmt == "json":
                body = build_json_export(self.events, self.store)
                return self._send(200, body, ctype="application/json; charset=utf-8",
                                  extra={"Content-Disposition": "attachment; filename=bscope-export.json"})
            if fmt == "csv":
                body = build_csv_export(self.events, self.store)
                return self._send(200, body, ctype="text/csv; charset=utf-8",
                                  extra={"Content-Disposition": "attachment; filename=bscope-export.csv"})
            if fmt in ("emails", "email", "txt"):
                body = "\n".join(collect_emails(self.events))
                if body:
                    body += "\n"
                return self._send(200, body, ctype="text/plain; charset=utf-8",
                                  extra={"Content-Disposition": "attachment; filename=emails.txt"})
            md = build_markdown(self.events, self.store)
            return self._send(200, md, ctype="text/markdown; charset=utf-8",
                              extra={"Content-Disposition": "attachment; filename=bscope-report.md"})

        if path.startswith("/img/"):
            return self._serve_image(path[len("/img/"):])

        return self._send(404, "not found", ctype="text/plain; charset=utf-8")

    do_HEAD = do_GET

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path not in ("/api/triage", "/api/shot_triage"):
            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, "bad request", ctype="text/plain; charset=utf-8")

        if path == "/api/shot_triage":
            rel = body.get("rel")
            if not rel:
                return self._send(400, "missing rel", ctype="text/plain; charset=utf-8")
            res = self.store.set("shot:" + rel, status=body.get("status"),
                                 allowed=SHOT_STATUS_KEYS)
            return self._send(200, json.dumps(res), ctype="application/json; charset=utf-8")

        fid = body.get("id")
        if not fid:
            return self._send(400, "missing id", ctype="text/plain; charset=utf-8")
        res = self.store.set(fid, status=body.get("status"), notes=body.get("notes"))
        return self._send(200, json.dumps(res), ctype="application/json; charset=utf-8")

    def _serve_image(self, rel_encoded):
        if not self.shots_root:
            return self._send(404, "no screenshots", ctype="text/plain; charset=utf-8")
        rel = urllib.parse.unquote(rel_encoded)
        safe = posixpath.normpath("/" + rel).lstrip("/")
        full = os.path.realpath(os.path.join(self.shots_root, safe))
        root_real = os.path.realpath(self.shots_root)
        if not (full == root_real or full.startswith(root_real + os.sep)):
            return self._send(403, "forbidden", ctype="text/plain; charset=utf-8")
        if not os.path.isfile(full):
            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        ctype = MIME.get(os.path.splitext(full)[1].lower(), "application/octet-stream")
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        self._send(200, data, ctype=ctype, extra={"Cache-Control": "max-age=3600"})


def main():
    ap = argparse.ArgumentParser(
        description="Triage dashboard for BBOT scan output (findings + assets + screenshots).")
    ap.add_argument("infile", help="BBOT results file (output.ndjson / output.json / output.csv)")
    ap.add_argument("--shots", default="", metavar="DIR",
                    help="folder of screenshots to show in the Screenshots tab")
    ap.add_argument("--gowitness-db", default="", metavar="PATH", dest="gowitness_db",
                    help="gowitness results (gowitness.sqlite3 or --write-jsonl output) "
                         "for precise per-URL tech stacks on screenshots")
    ap.add_argument("--state", default="", metavar="PATH",
                    help="triage state JSON (default: <infile>.bscope.json)")
    ap.add_argument("--compare", default="", metavar="PATH",
                    help="a previous BBOT results file; diff mode flags what's NEW since then")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; 0.0.0.0 to expose on LAN)")
    ap.add_argument("--port", type=int, default=7373, help="port (default 7373)")
    args = ap.parse_args()

    if not os.path.isfile(args.infile):
        sys.exit("error: no such file: %s" % args.infile)

    events = load_events(args.infile)
    if not events:
        sys.stderr.write("warning: no events parsed from %s\n" % args.infile)
    findings = [e for e in events if e["lane"] == "finding"]
    assets = [e for e in events if e["lane"] == "asset"]

    state_path = args.state or (args.infile + ".bscope.json")
    store = Store(state_path)

    shots_root = os.path.realpath(os.path.expanduser(args.shots)) if args.shots else ""
    shots = collect_images(shots_root) if shots_root else []

    gw_by_file, gw_by_url = {}, {}
    if args.gowitness_db:
        gw_path = os.path.expanduser(args.gowitness_db)
        if not os.path.isfile(gw_path):
            sys.exit("error: --gowitness-db file not found: %s" % gw_path)
        try:
            gw_by_file, gw_by_url = load_gowitness(gw_path)
            print("gowitness: tech for %d screenshots / %d urls from %s"
                  % (len(gw_by_file), len(gw_by_url), gw_path))
        except Exception as e:
            sys.stderr.write("warning: could not read gowitness db (%s): %s\n" % (gw_path, e))

    prev_ids, removed, compare_active = set(), [], False
    if args.compare:
        if not os.path.isfile(args.compare):
            sys.exit("error: --compare file not found: %s" % args.compare)
        prev_events = load_events(args.compare)
        prev_ids = {e["id"] for e in prev_events}
        cur_ids = {e["id"] for e in events}
        removed = [{"type": e["type"], "title": e["title"], "priority": e["priority"],
                    "target": _target_of(e), "lane": e["lane"]}
                   for e in prev_events if e["id"] not in cur_ids]
        compare_active = True
        new_count = sum(1 for e in events if e["id"] not in prev_ids)
        print("diff vs %s: %d new, %d removed" % (args.compare, new_count, len(removed)))

    Handler.events = events
    Handler.findings = findings
    Handler.assets = assets
    Handler.store = store
    Handler.shots = shots
    Handler.shots_root = shots_root
    Handler.gw_by_file = gw_by_file
    Handler.gw_by_url = gw_by_url
    Handler.src_name = os.path.basename(args.infile)
    Handler.prev_ids = prev_ids
    Handler.removed = removed
    Handler.compare_active = compare_active

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    shown = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    print("bscope  -  %d events  (%d findings / %d assets)  from %s"
          % (len(events), len(findings), len(assets), args.infile))
    if shots:
        print("          %d screenshots from %s" % (len(shots), shots_root))
    print("          triage state: %s" % state_path)
    print("serving at http://%s:%d   (Ctrl-C to stop)" % (shown, args.port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
        httpd.server_close()


if __name__ == "__main__":
    main()