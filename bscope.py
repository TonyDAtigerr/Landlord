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
  * collects every URL BBOT found into one copy-ready list (URLs tab) for
    feeding feroxbuster/ffuf or Burp's target scope
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
import base64
import csv
import gzip
import hashlib
import html
import io
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
import zipfile
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


def _nuclei_enrich(ev):
    """Build a finding-specific title / description / playbook for a nuclei hit
    from what it actually matched (template id, name, extracted data, CVE,
    severity, URL) - never the generic 'a nuclei template matched' blurb."""
    blob = (ev.get("data_str", "") or "") + " " + (ev.get("desc", "") or "")
    tid = _nuclei_template_id(ev)
    name = _nuclei_name(ev)
    mx = re.search(r"Extracted Data:\s*\[([^\]]*)\]", blob, re.I)
    extracted = (mx.group(1).strip() if mx else "")
    cves = list(dict.fromkeys(c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", blob, re.I)))
    sev = (ev.get("severity") or ev.get("priority") or "info")
    url = ev.get("url") or ev.get("dhost") or ev.get("host") or "the asset"
    title = name or tid or "Nuclei template match"

    lead = name or tid or "a nuclei template"
    idpart = (" (template %s)" % tid) if (tid and name) else ""
    parts = ["Nuclei matched %s%s on %s." % (lead, idpart, url)]
    if extracted:
        parts.append("Matched/extracted value: %s" %
                     (extracted if len(extracted) <= 300 else extracted[:300] + "…"))
    if cves:
        parts.append("Linked CVE(s): %s." % ", ".join(cves))
    parts.append("Reported severity: %s." % sev)
    desc = " ".join(parts)

    play = []
    play.append("What it checked: open template '%s' on github.com/projectdiscovery/nuclei-templates "
                "(search the id) to read its matcher and what it proves." % (tid or name or "<template>"))
    if tid and (ev.get("url") or url):
        play.append("Reproduce and capture evidence: nuclei -id %s -u '%s' -debug."
                    % (tid, ev.get("url") or url))
    if extracted:
        play.append("Verify the match is real: check the extracted value above against %s and "
                    "rule out a loose matcher / false positive." % url)
    if cves:
        play.append("For %s: pull a public PoC, confirm the affected version is actually running, "
                    "and assess reachability and real impact before reporting." % ", ".join(cves))
    elif SEV_RANK.get(str(sev).lower(), 0) <= 2:
        play.append("This is a %s-severity detection - usually fingerprinting or low-impact exposure. "
                    "Confirm it has concrete security impact before reporting; otherwise mark it "
                    "reviewed / not exploitable." % sev)
    else:
        play.append("Treat as a real finding: confirm the impact on %s and document a clean "
                    "request/response PoC." % url)
    return title, desc, play


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
                    # replace the generic nuclei blurb with finding-specific detail
                    return _nuclei_enrich(ev)
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
        fname = ev.get("fname") or ""
        title = fname or ("%s%s" % (ev["type"].replace("_", " ").title(),
                                    (" (%s)" % mod) if mod else ""))
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


# --------------------------------------------------------------------------- #
#  Remediation: DERIVED from the finding itself, never a fixed per-target table.
# --------------------------------------------------------------------------- #
# BBOT findings carry no remediation field, but their name/description embed
# machine-readable signals: nuclei template ids, CVEs, CWEs, vulnerable library
# names and affected version ranges. We pull references and a fix directive out
# of those, so the guidance adapts to whatever BBOT returns for any target.

def _finding_references(ev):
    """References the finding ITSELF points to - CVE->NVD, CWE->MITRE and the
    nuclei template it matched (where the real remediation/refs live). Scan-
    agnostic: whatever identifiers the finding carries are what you get."""
    text = ev.get("text", "") or ""
    sources = []
    def add(label, url):
        pair = [label, url]
        if url and pair not in sources:
            sources.append(pair)
    for cve in sorted({c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)}):
        add(cve, "https://nvd.nist.gov/vuln/detail/" + cve)
    for cwe in sorted({c for c in re.findall(r"CWE-(\d{1,5})", text, re.I)}, key=int):
        add("CWE-" + cwe, "https://cwe.mitre.org/data/definitions/%s.html" % cwe)
    tid = _nuclei_template_id(ev)
    if tid:
        add("nuclei template: " + tid,
            "https://github.com/search?q=repo%3Aprojectdiscovery%2Fnuclei-templates+"
            + urllib.parse.quote(tid) + "&type=code")
    return sources


def remediation(ev):
    """Return (remediation_text, [[label, url], ...]) derived from this finding.
    The fix directive is chosen from the finding's own signals (vulnerable
    library + affected range, CVE, nuclei template, else the named issue)."""
    if ev.get("lane") != "finding":
        return "", []
    desc = ev.get("desc", "") or ev.get("data_str", "") or ""
    text = ev.get("text", "") or ""
    name = (ev.get("title") or ev.get("fname") or "this finding").strip()
    sources = _finding_references(ev)
    cves = sorted({c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)})
    msg = []

    lib_m = re.search(r"library detected:\s*(.+?)\s+v?([0-9][\w.\-]*)", desc, re.I)
    aff_m = re.search(r"affected versions?:\s*(.+)$", desc, re.I | re.M)
    if _mod(ev, "retirejs") or ("vulnerable" in text.lower() and "librar" in text.lower()):
        lib = ("%s %s" % (lib_m.group(1).strip(), lib_m.group(2).strip())) if lib_m else "the affected library"
        extra = (" (affected range %s)" % aff_m.group(1).strip()) if aff_m else ""
        msg.append("Upgrade %s to a version outside the vulnerable range%s and redeploy; "
                   "remove the bundled vulnerable copy." % (lib, extra))
    elif cves:
        msg.append("Patch the affected software to a release that fixes %s, after "
                   "confirming the deployed version is actually in the affected range."
                   % ", ".join(cves))
    elif _mod(ev, "nuclei"):
        tid = _nuclei_template_id(ev)
        msg.append("Open the matched nuclei template%s (linked) to see exactly what it "
                   "checks and its recommended fix, then remediate at the source and rule "
                   "out a false positive." % ((" '%s'" % tid) if tid else ""))
    else:
        msg.append("Confirm \"%s\" on the affected URL, assess its real impact, and apply "
                   "the standard server/application fix for this issue class." % name)

    if sources:
        msg.append("Use the reference%s below for the authoritative fix and to verify it."
                   % ("s" if len(sources) > 1 else ""))
    else:
        # nothing machine-readable to cite: derive a lookup from this finding's name
        sources.append(["Look up: " + name,
                        "https://duckduckgo.com/?q="
                        + urllib.parse.quote(name + " vulnerability remediation")])
        sources.append(["OWASP Web Security Testing Guide",
                        "https://owasp.org/www-project-web-security-testing-guide/"])
    return " ".join(msg), sources


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


def _js_library(ev):
    """Pull library name, version and source URL out of a retire.js
    'Vulnerable JavaScript Library' finding so a manual check can target it."""
    d = ev.get("desc", "") or ev.get("text", "") or ""
    m = re.search(r"detected:\s*([A-Za-z0-9_.\-]+)\s+v([0-9][\w.\-]*)", d, re.I)
    lib = m.group(1).strip() if m else ""
    ver = m.group(2).strip() if m else ""
    u = re.search(r"JavaScript URL:\s*(\S+)", d, re.I)
    return lib, ver, (u.group(1).strip() if u else "")


def _console_js_lib(lib, ver):
    """A one-line DevTools-console check: prints the library's live version
    (when it exposes a global) and any <script> whose src names the library -
    manual confirmation that the flagged version is really loaded in the page."""
    key = (lib or "").lower()
    flagged = ("%s v%s" % (lib, ver)) if ver else lib
    return (
        "(()=>{const V={jquery:()=>window.jQuery&&jQuery.fn&&jQuery.fn.jquery,"
        "angular:()=>window.angular&&angular.version&&angular.version.full,"
        "react:()=>window.React&&React.version,vue:()=>window.Vue&&Vue.version,"
        "bootstrap:()=>window.bootstrap&&bootstrap.Tooltip&&bootstrap.Tooltip.VERSION,"
        "moment:()=>window.moment&&moment.version,lodash:()=>window._&&_.VERSION,"
        "underscore:()=>window._&&_.VERSION,"
        "swiper:()=>window.Swiper&&(Swiper.version||(Swiper.prototype||{}).version),"
        "dompurify:()=>window.DOMPurify&&DOMPurify.version,d3:()=>window.d3&&d3.version,"
        "handlebars:()=>window.Handlebars&&Handlebars.VERSION};"
        "const k=%s;const f=V[k];"
        "console.log('live version of '+k+':',(f&&f())||'(no global - likely bundled/minified; read the script source)');"
        "console.log('matching <script> src:',[...document.scripts].map(s=>s.src).filter(s=>s&&new RegExp(k,'i').test(s)));"
        "console.log('scan flagged:',%s);})()"
    ) % (json.dumps(key), json.dumps(flagged))


def _console_reflect(web, param):
    """Console check that shows exactly where a parameter value lands in the
    response, so the tester can judge the XSS context (HTML / attribute / JS)."""
    sep = "&" if "?" in web else "?"
    url = "%s%s%s=bscopeMARK7E" % (web, sep, param)
    return ("fetch(%s).then(r=>r.text()).then(h=>{"
            "const m=[...h.matchAll(/.{0,60}bscopeMARK7E.{0,60}/g)];"
            "console.log(m.length+' reflection(s) of the marker:');"
            "m.forEach(x=>console.log(x[0]));"
            "console.log('context key: inside a tag => attribute XSS, inside <script> => JS XSS, "
            "between tags => HTML XSS');})") % json.dumps(url)


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

    def add(label, cmd, kind="shell"):
        if cmd and not any(c[1] == cmd for c in cmds):
            cmds.append((label, cmd, kind))

    # ---- finding-specific verification (most relevant first) ----
    # structured bits BBOT embeds in the description, e.g. "Name: [param]",
    # "Categories: [SQL Injection]", "template: [id]".
    def field(key):
        m = re.search(r"%s:\s*\[([^\]]+)\]" % re.escape(key), ev.get("desc", "") or "", re.I)
        return m.group(1).strip() if m else ""
    param = field("Name") if _mod(ev, "hunt", "reflected_parameters") or "parameter" in t else ""
    categories = field("Categories").lower()

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
    if _mod(ev, "bucket") or typ == "STORAGE_BUCKET" or "bucket" in t or "s3://" in t or " s3 " in t:
        burl = (url or web or "").rstrip("/")
        try:
            bhost = urllib.parse.urlparse(burl).hostname or ""
        except Exception:
            bhost = ""
        if "amazonaws.com" in bhost or bhost.startswith("s3") or ".s3" in bhost:
            bucket = bhost.split(".s3")[0] if ".s3" in bhost else (host or bhost)
            add("List bucket (S3)", "aws s3 ls s3://%s --no-sign-request" % bucket)
        elif "blob.core.windows.net" in bhost:
            add("List container (Azure)", "curl -s '%s?restype=container&comp=list'" % burl)
        elif "storage.googleapis.com" in bhost or ".storage." in bhost:
            bucket = bhost.split(".storage")[0] if ".storage" in bhost else bhost
            add("List bucket (GCS)", "gsutil ls -r gs://%s" % bucket)
        elif burl:
            add("List bucket contents", "curl -s '%s'" % burl)
        targeted = True
    if typ == "CODE_REPOSITORY" or _mod(ev, "github", "gitlab", "git_clone", "code_repository") or "repositor" in t:
        repo = url or web
        if repo:
            add("Clone the repo", "git clone --depth 1 '%s'" % repo)
            add("Scan it for secrets", "trufflehog git '%s' --only-verified" % repo)
            targeted = True
    if _mod(ev, "trufflehog", "secretsdb") or "leaked" in t or "secret" in t or "credential" in t or "api key" in t:
        add("Verify the secret", "# test the leaked credential read-only against its own service; do not reuse elsewhere")
        targeted = True
    if _mod(ev, "host_header") or "host header" in t:
        if web:
            add("Host-header injection", "curl -sSIk -H 'Host: evil.example' '%s'" % web)
            add("X-Forwarded-Host probe", "curl -sSIk -H 'X-Forwarded-Host: evil.example' '%s'" % web)
            targeted = True
    if _mod(ev, "iis_shortnames") or "shortname" in t or "short name" in t:
        if web:
            add("IIS shortname scan", "shortscan '%s'" % web)
            targeted = True
    if _mod(ev, "bypass403") or "403 bypass" in t or "forbidden bypass" in t or "possible 403" in t:
        if webroot:
            add("403 bypass sweep", "byp4xx '%s'" % web)
            add("Path-trick probe", "curl -sSIk '%s/%%2e/' ; curl -sSIk '%s/..;/'" % (webroot, webroot))
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
            add("Manual: test CORS from another origin's console",
                ("/* open any other site (e.g. https://example.org), then run in its console */ "
                 "fetch(%s,{credentials:'include'}).then(r=>console.log("
                 "'Access-Control-Allow-Origin:',r.headers.get('access-control-allow-origin'),"
                 "'| Allow-Credentials:',r.headers.get('access-control-allow-credentials')))"
                 ".catch(e=>console.log('request blocked:',e.message))") % json.dumps(web),
                "console")
            targeted = True
    # parameter-level findings: target the EXACT parameter BBOT flagged
    if _has(ev, "sql injection", "sqli") or "sql injection" in categories:
        if web and param:
            add("Confirm SQLi on '%s'" % param, "sqlmap -u '%s' -p %s --batch --level 2 --risk 2" % (web, param))
        elif web:
            add("Confirm SQLi", "sqlmap -u '%s' --batch --level 2 --risk 2" % web)
        targeted = True
    if _mod(ev, "reflected_parameters") or "reflected" in t:
        if web and param:
            sep = "&" if "?" in web else "?"
            add("Test reflected '%s'" % param,
                "curl -sSk '%s%s%s=bscopeMARK7E' | grep -n bscopeMARK7E   # check how '%s' is reflected (HTML/JS/attr) for XSS"
                % (web, sep, param, param))
            add("Manual: inspect where '%s' reflects (browser console)" % param,
                _console_reflect(web, param), "console")
        targeted = True
    elif _has(ev, "cross-site scripting", "xss"):
        if web:
            add("Probe XSS context", "curl -sSk '%s'   # inject a benign marker and inspect the reflection context" % web)
            targeted = True
    if _mod(ev, "telerik", "ajaxpro", "dotnetnuke") or "telerik" in t or "dotnetnuke" in t or "ajaxpro" in t:
        if web:
            add("Targeted template scan", "nuclei -tags telerik,dotnetnuke,aspx -u '%s'" % web)
            targeted = True
    if _mod(ev, "retirejs") or ("vulnerable" in t and ("javascript" in t or ".js" in t)):
        if web:
            lib, ver, jsurl = _js_library(ev)
            if lib:
                add("Manual: confirm %s %s in the page's console" % (lib, ver or ""),
                    _console_js_lib(lib, ver), "console")
            if jsurl:
                add("Manual: read the version from the library source",
                    "curl -s '%s' | head -c 400" % jsurl)
            add("Re-check JS libraries", "nuclei -tags tech,javascript,cve -u '%s'" % web)
            targeted = True
    if _mod(ev, "excavate") or "verbose error" in t or "error message" in t:
        if web:
            add("View the error body", "curl -sSk '%s' | sed -n '1,60p'" % web)
            targeted = True
    if _mod(ev, "url_manipulation") or "url manipulation" in t:
        if webroot:
            add("Extension/response probe", "curl -sSIk '%s/' ; curl -sSIk '%s/?bscope=.jpg'" % (webroot, webroot))
            targeted = True

    if web and _has(ev, "security header", "missing header", "csp", "content security policy",
                    "hsts", "strict-transport", "x-content-type", "referrer-policy", "permissions-policy"):
        add("Manual: read response security headers (browser console)",
            ("fetch(location.href,{method:'HEAD'}).then(r=>['content-security-policy',"
             "'strict-transport-security','x-frame-options','x-content-type-options',"
             "'referrer-policy','permissions-policy'].forEach(k=>console.log(k+':',"
             "r.headers.get(k)||'(missing)')))"),
            "console")
        targeted = True
    if web and _has(ev, "clickjack", "x-frame", "frame options", "framing", "framable", "frameable"):
        add("Manual: clickjacking test (save as .html, open in a browser)",
            '<!doctype html><h3>If the page renders below, it is frameable:</h3>'
            '<iframe src="%s" width="800" height="600"></iframe>' % web,
            "manual")
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


def _summarize_dict(d):
    """A readable one-liner for a dict event that has no description or url of
    its own (PROTOCOL banners, storage buckets, socials, technologies...), so
    its distinguishing detail is kept instead of collapsing to just the host.
    Also what keeps two technologies on one url from sharing an identity."""
    if not isinstance(d, dict):
        return ""
    parts = []
    for k in ("name", "technology", "platform", "profile_name", "protocol",
              "port", "banner", "waf", "asn", "tenant-names", "tenant-id",
              "domain", "repository", "container", "bucket", "title", "http_title"):
        v = d.get(k)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v if str(x).strip())
        if str(v).strip():
            parts.append(str(v).strip())
    return " ".join(parts).strip()


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
        # desc for findings; a field summary for structured non-url events (so a
        # PROTOCOL banner or two distinct technologies on one url are preserved);
        # then url / host / raw json as last resorts.
        data_str = desc or _summarize_dict(data) or url or host             or json.dumps(data, ensure_ascii=False)
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
    # BBOT's own finding name ("Duplicate Host Header Tolerated", etc.) is the
    # ground-truth label; expose it so enrich() can title generic findings with it.
    ev["fname"] = (data.get("name", "") if isinstance(data, dict) else "").strip()
    title, description, playbook = enrich(ev)
    ev["title"] = title
    ev["description"] = desc or description
    ev["why"] = description
    ev["playbook"] = playbook
    ev["commands"] = suggest_commands(ev)
    ev["remediation"], ev["sources"] = remediation(ev)
    # identity = type + target (host/url/port) + data, matching dedupe_events()'s
    # key. This gives every distinct finding its own id and its own triage state;
    # only genuine duplicates (identical on all of these) share an id and collapse.
    ev["id"] = hashlib.sha1(
        ("%s|%s|%s|%s|%s" % (type_, host, url, port, data_str)).encode("utf-8", "replace")
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
        # BBOT serializes dict-valued event data under "data_json" and plain
        # string data under "data". Reading only "data" silently dropped every
        # rich event (URL, FINDING, TECHNOLOGY, SOCIAL, STORAGE_BUCKET,
        # PROTOCOL, URL_HINT...), which is why the URLs tab and most findings
        # came up empty. Prefer data_json, fall back to data.
        data = r.get("data_json")
        if data is None:
            data = r.get("data", "")
        ev = _normalize(
            r.get("type", "UNKNOWN"), data,
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
            # BBOT writes dict-valued event data into the CSV as a JSON object;
            # decode it so URL/FINDING/TECHNOLOGY etc. parse the same as NDJSON.
            if data[:1] == "{" and data[-1:] == "}":
                try:
                    data = json.loads(data)
                except Exception:
                    pass
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
    the same event id (built from the same type+target+data key), so triage
    carries over regardless."""
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
        rec = self.data.get(fid, {"status": "new", "notes": "", "updated": ""})
        rec.setdefault("evidence", [])      # list of evidence image filenames
        return rec

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

    def add_evidence(self, fid, fname):
        with self.lock:
            cur = self.data.get(fid, {"status": "new", "notes": "", "updated": ""})
            cur.setdefault("evidence", [])
            if fname not in cur["evidence"]:
                cur["evidence"].append(fname)
            cur["updated"] = datetime.now().isoformat(timespec="seconds")
            self.data[fid] = cur
            self._flush()
            return cur

    def remove_evidence(self, fid, fname):
        with self.lock:
            cur = self.data.get(fid)
            if cur and fname in cur.get("evidence", []):
                cur["evidence"].remove(fname)
                cur["updated"] = datetime.now().isoformat(timespec="seconds")
                self._flush()
            return cur or {"status": "new", "notes": "", "updated": "", "evidence": []}

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


# severity / status vocabulary used by pentest reporting platforms
REPORT_SEV = {"critical": "Critical", "high": "High", "medium": "Medium",
              "low": "Low", "info": "Informational", "unknown": "Informational"}
# triage states that mean the issue is still live (-> reported as Open)
REPORT_OPEN_STATES = {"new", "triaging", "confirmed", "reported"}
_REPORT_SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}


def build_report_json(events, store, src_name=""):
    """Findings grouped one-per-issue for import into pentest reporting platforms
    (AttackForge, PlexTrac, etc.). Each finding carries its affected assets (one
    row per target, de-duplicated), remediation, references, evidence and tags,
    using field names from the common reporting vocabulary so they map on import.
    Scan-agnostic: everything comes from the parsed findings, not any fixed list."""
    groups, order = {}, []
    for ev in events:
        if ev.get("lane") != "finding":
            continue
        st = store.get(ev["id"])
        sev = REPORT_SEV.get(ev.get("priority"), "Informational")
        key = (ev.get("title", ""), sev, ev.get("module", ""))
        g = groups.get(key)
        if g is None:
            g = {
                "title": ev.get("title") or ev.get("type") or "Finding",
                "severity": sev,
                "status": "Closed",                 # promoted to Open below if any asset is live
                "description": ev.get("why") or "",
                "evidence": ev.get("data_str") or "",
                "recommendations": ev.get("remediation") or "",
                "references": [],
                "tags": [],
                "source_tool": ("bbot:%s" % ev["module"]) if ev.get("module") else "bbot",
                "affected_assets": [],
                "_assets": set(), "_refs": set(), "_tags": set(),
            }
            groups[key] = g
            order.append(key)
        target = _target_of(ev)
        if target and target not in g["_assets"]:
            g["_assets"].add(target)
            g["affected_assets"].append({
                "asset": target,
                "host": ev.get("dhost") or ev.get("host") or "",
                "port": ev.get("port") or None,
                "status": st.get("status", "new"),
                "notes": st.get("notes", ""),
                "evidence": ev.get("data_str") or "",
                "evidence_screenshots": st.get("evidence", []),
            })
        for s in (ev.get("sources") or []):
            if isinstance(s, (list, tuple)) and len(s) > 1 and s[1] and s[1] not in g["_refs"]:
                g["_refs"].add(s[1])
                g["references"].append({"title": s[0], "url": s[1]})
        for tg in (ev.get("tags") or []):
            if tg not in g["_tags"]:
                g["_tags"].add(tg); g["tags"].append(tg)
        if st.get("status", "new") in REPORT_OPEN_STATES:
            g["status"] = "Open"
    findings = []
    for key in order:
        g = groups[key]
        for k in ("_assets", "_refs", "_tags"):
            g.pop(k, None)
        g["affected_asset_count"] = len(g["affected_assets"])
        findings.append(g)
    findings.sort(key=lambda f: (_REPORT_SEV_RANK.get(f["severity"], 0),
                                 f["affected_asset_count"]), reverse=True)
    payload = {
        "tool": "bscope",
        "format": "bscope-findings/1.0",
        "generated": datetime.now().isoformat(timespec="seconds"),
        "source": src_name,
        "finding_count": len(findings),
        "findings": findings,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
#  Native scanner-import exports.
#
#  AttackForge and PlexTrac both import *scanner output in the tool's own
#  format* - they do NOT read a bespoke "findings" schema. That is why the old
#  fmt=report file imported nothing: it was bscope's own JSON, which neither
#  platform has a parser for. Instead:
#
#   * AttackForge ships a native **Nuclei Scanner** parser. So we rebuild the
#     findings as nuclei's own JSON (projectdiscovery `-json-export` shape) and
#     the user imports it by choosing "Nuclei" on the Import Vulnerabilities
#     screen. Real nuclei hits keep their true template id / name / severity /
#     CVE-CWE classification; non-nuclei findings are expressed in the same
#     schema with a derived template id so they import too.
#   * PlexTrac has **no** nuclei parser, but it has a generic **Report Findings
#     CSV template**. So for PlexTrac we emit that CSV exactly (its documented
#     column order and vocabulary), grouped one row per issue.
#
#  Both are scan-agnostic: every value comes from the parsed findings.
# --------------------------------------------------------------------------- #

# triage states we never push into a report (the user dismissed them)
_EXPORT_SKIP_STATES = {"false_positive"}


def _slug(s):
    s = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")
    return s or "finding"


# --------------------------------------------------------------------------- #
#  Generic, reusable vulnerability writeups.
#
#  For each finding we produce a client-agnostic writeup in three short sections
#  - Description, Attack Scenario, Remediation Recommendations - written as a
#  pentester would for a reusable report/writeup library. It is keyed off the
#  vulnerability CLASS (the finding's title, which enrich() sets from RULES), so
#  it contains NO host / URL / IP / client specifics and can be reused verbatim
#  on future engagements. The specific location/evidence stays in the export's
#  own asset/evidence fields, not in the writeup.
# --------------------------------------------------------------------------- #

# key (matches enrich() class title) -> (description, attack_scenario, remediation)
GENERIC_WRITEUPS = {
 "Host header injection": (
  "The application uses the attacker-controllable HTTP Host header (or related headers such as X-Forwarded-Host) when building absolute URLs, links, or routing and caching decisions. Because this value can be set freely by the client, the application can be coerced into generating content that references an attacker-chosen domain.",
  "An attacker sends requests with a crafted Host header to poison password-reset or email-verification links, cached responses, or redirects. A victim who follows the resulting link, or who is served a poisoned cache entry, is directed to attacker-controlled infrastructure, enabling credential theft, account takeover, or web cache poisoning that affects other users.",
  "Do not derive absolute URLs or security decisions from the incoming Host header. Validate Host and X-Forwarded-Host against an allowlist of expected domains, set a canonical server name, and reject requests whose host does not match. Where links must be absolute, build them from server-side configuration rather than request headers."
 ),
 "Interesting / reflected parameter": (
  "A request parameter is reflected into the application's response, or otherwise influences it, without sufficient validation or output encoding. Reflected, attacker-influenced input is a common entry point for client-side and server-side injection issues.",
  "An attacker crafts a value for the parameter and delivers it to a victim or submits it directly. Depending on where the value is used, this can lead to cross-site scripting, open redirection, content spoofing, or further injection, potentially compromising user sessions or the integrity of the response.",
  "Treat all request parameters as untrusted. Apply strict input validation, contextual output encoding, and allowlisting for values used in HTML, URLs, headers, or queries. Add a Content-Security-Policy as defense in depth and confirm the fix with targeted retesting."
 ),
 "Injection (SQLi / XSS / RCE / SSTI)": (
  "User-supplied input is incorporated into an interpreter context - such as a database query, HTML response, operating-system command, or server-side template - without adequate separation of code and data. This class of flaw lets an attacker alter the intended logic of that context.",
  "An attacker submits specially crafted input that breaks out of the data context and is executed as code. Impact ranges from reading or modifying database contents and hijacking user sessions to executing arbitrary commands on the server, and is frequently chained toward full compromise of the application or host.",
  "Use parameterised queries or prepared statements for data access, contextual output encoding for rendered content, safe APIs instead of shell execution, and sandboxed or logic-less templating. Enforce strict input validation and least privilege for the application's service accounts, and retest to confirm the injection is no longer possible."
 ),
 "CORS misconfiguration": (
  "The application returns permissive Cross-Origin Resource Sharing headers - for example reflecting arbitrary origins or allowing credentials with a wildcard - which relaxes the browser same-origin policy for its responses.",
  "An attacker hosts a malicious page that makes authenticated cross-origin requests to the application on behalf of a logged-in victim and reads the responses. This can expose sensitive data or allow actions in the victim's context that the same-origin policy would normally prevent.",
  "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins, never reflect the incoming Origin blindly, and only send Access-Control-Allow-Credentials with a specific origin (never with a wildcard). Return CORS headers only on endpoints that genuinely require cross-origin access."
 ),
 "Open redirect": (
  "The application redirects users to a URL taken from attacker-controllable input without validating the destination against an allowlist of permitted targets.",
  "An attacker crafts a link to the trusted application that redirects to an attacker-controlled site and distributes it in phishing. Because the link starts on a legitimate domain, victims are more likely to trust it, and the redirect can be used to steal credentials or OAuth tokens.",
  "Avoid using user input to determine redirect destinations. Where redirection is required, map user input to a server-side allowlist of permitted URLs or use relative paths only, and reject or sanitise any absolute or externally-pointing destination."
 ),
 "SSRF": (
  "The application fetches a resource from a URL that is influenced by user input, allowing an attacker to make the server issue requests to unintended destinations, including internal-only systems.",
  "An attacker supplies a URL pointing at internal services, cloud metadata endpoints, or other back-end systems not reachable from the internet. The server makes the request on the attacker's behalf, which can disclose internal data, credentials, or cloud tokens and can be pivoted toward deeper access.",
  "Validate and allowlist the hosts and schemes the application may request, resolve and verify destinations to block internal and link-local ranges, and disable unused URL schemes and redirects. Isolate outbound requests and remove or protect cloud metadata endpoints with defense-in-depth controls."
 ),
 "Default / weak credentials or exposed login": (
  "An administrative or application login interface is exposed, and either accepts default/weak credentials or offers no protection against credential-guessing. Exposed management interfaces materially increase the attack surface.",
  "An attacker discovers the login during reconnaissance and attempts default, weak, or previously-breached credentials, or brute-forces the interface. Successful authentication grants administrative or user access that can lead directly to data exposure or full compromise of the service.",
  "Remove or restrict access to management interfaces (for example by network ACL or VPN), change all default credentials, enforce a strong password policy and multi-factor authentication, and add rate-limiting and account-lockout to resist guessing. Monitor authentication attempts for abuse."
 ),
 "Open cloud storage bucket": (
  "A cloud storage container is configured to allow anonymous or overly-broad access to its contents or its listing. Misconfigured object storage is a frequent source of large-scale data exposure.",
  "An attacker enumerates the storage container and reads or lists its objects without authentication, harvesting any sensitive files it holds. Where write access is also open, the attacker can tamper with or plant content that other users or systems will trust.",
  "Set the storage container and its objects to private by default, remove public and authenticated-anyone grants, and enforce least-privilege access policies. Enable access logging and automated checks that flag any publicly-accessible storage."
 ),
 "Exposed .git directory": (
  "A version-control directory (such as .git) is served by the web server, exposing repository metadata from which the application's source code and history can often be reconstructed.",
  "An attacker downloads the exposed repository data and rebuilds the source code, revealing application logic, hardcoded secrets, and further vulnerabilities. Credentials or keys committed to history can then be used to access back-end systems.",
  "Block web access to version-control directories at the server or reverse proxy, and remove them from the deployed web root entirely. Rotate any secrets that may have been exposed, and deploy from build artifacts rather than a working copy that contains repository metadata."
 ),
 "Leaked secret / credential": (
  "A secret such as an API key, password, token, or private key is exposed where it can be retrieved by an unauthorised party. Exposed secrets provide a direct path to the systems they protect.",
  "An attacker who recovers the secret uses it to authenticate to the associated service or data store, bypassing normal access controls. Depending on the secret's scope, this can grant access to sensitive data, cloud infrastructure, or third-party services.",
  "Revoke and rotate the exposed secret immediately, and remove it from the exposed location and from any version-control history. Store secrets in a dedicated secrets manager, keep them out of source code and client-side assets, and add automated secret-scanning to prevent recurrence."
 ),
 "Exposed sensitive file": (
  "A file that should not be publicly accessible - such as a configuration file, backup, archive, or environment file - is served by the application, disclosing its contents to anyone who requests it.",
  "An attacker requests the file directly and reads its contents, which commonly include credentials, connection strings, internal paths, or other information that aids further attack. The disclosed material is often used to pivot toward authenticated access or deeper compromise.",
  "Remove sensitive files from the web root and block access to backup, configuration, and environment file patterns at the server. Store configuration and secrets outside the served directory, and review the deployment process so such files are never published."
 ),
 "Known-CVE / outdated technology": (
  "The service runs a software component whose version is affected by one or more publicly-documented vulnerabilities, or is end-of-life and no longer receiving security updates.",
  "An attacker fingerprints the component and matches its version to public advisories and, frequently, ready-made exploits. Exploitation can range from information disclosure to remote code execution, depending on the specific issue, with little custom effort required.",
  "Upgrade the affected component to a current, supported version that addresses the known issues, after confirming the deployed version really is in the vulnerable range. Establish a patch-management process and remove or replace end-of-life software that can no longer be updated."
 ),
 "Subdomain takeover": (
  "A DNS record points at a third-party service or resource that is no longer claimed, allowing an attacker to register it and serve content from the organisation's subdomain.",
  "An attacker claims the dangling resource and gains control of content served on the trusted subdomain. This can be used for convincing phishing, cookie or token theft within the parent domain, and bypass of controls that trust the organisation's own domains.",
  "Remove DNS records that point at decommissioned or unclaimed services, and verify that every CNAME or alias resolves to a resource the organisation actually controls. Add periodic checks for dangling DNS entries as part of asset management."
 ),
 "GraphQL introspection enabled": (
  "The GraphQL endpoint exposes its full schema through introspection, revealing all types, queries, and mutations the API supports.",
  "An attacker queries introspection to map the entire API, including hidden or administrative operations, and uses that map to find and exploit weakly-protected fields or mutations far more efficiently than by guessing.",
  "Disable introspection in production, enforce authentication and per-field authorisation on the API, and apply query depth and complexity limits. Expose introspection only in controlled non-production environments."
 ),
 "Telerik UI (deserialization / weak-key RCE)": (
  "The application exposes Telerik UI components whose handlers are affected by well-documented vulnerabilities, including insecure deserialisation and weak or default cryptographic keys that can lead to remote code execution.",
  "An attacker fingerprints the Telerik handlers and submits a crafted payload - for example forging an encrypted parameter using a known or weak key - to achieve file upload or deserialisation-based code execution on the server, often resulting in full host compromise.",
  "Upgrade Telerik UI to a current patched release, replace any default or weak encryption keys with strong secret values, and disable or restrict unused handlers. Confirm the deployed version is not affected by the known deserialisation and key-based issues."
 ),
 "Vulnerable JavaScript library (retirejs)": (
  "The page loads a client-side JavaScript library at a version with publicly-known vulnerabilities. The real severity depends on whether the vulnerable code path is actually reachable in the application.",
  "An attacker who can influence input reaching the vulnerable library sink exploits the known flaw - commonly DOM-based cross-site scripting or prototype pollution - to run code in victims' browsers and compromise their sessions.",
  "Upgrade the library to a fixed version, remove unused libraries, and verify no vulnerable sink is reachable from attacker-influenced input. Track third-party front-end dependencies and patch them as part of regular maintenance."
 ),
 "NTLM endpoint - internal name disclosure": (
  "An endpoint supports NTLM authentication and, when probed, discloses internal information such as the host, domain, or DNS names of the environment.",
  "An attacker queries the endpoint to harvest internal naming and domain details, which inform targeted password-spraying, phishing, and lateral-movement activity against the internal environment.",
  "Restrict access to NTLM-authenticating endpoints to trusted networks, and avoid exposing them to the internet. Where external access is required, front them with controls that do not leak internal names and prefer modern authentication protocols."
 ),
 "403 / WAF bypass": (
  "Access controls or a web application firewall that are intended to block certain requests can be circumvented through request manipulation, so protected content or functionality remains reachable.",
  "An attacker varies request paths, methods, headers, or encodings until a blocked resource returns successfully, reaching content or functionality the control was meant to protect and undermining reliance on that control.",
  "Enforce authorisation at the application layer rather than relying on perimeter filtering alone, and normalise requests before access decisions. Treat the WAF as defense in depth, and fix the underlying access-control gap so protected resources are not served regardless of the bypass technique."
 ),
 "WAF / CDN present": (
  "A web application firewall or content delivery network sits in front of the asset. This is contextual information about the environment rather than a vulnerability in itself.",
  "The presence of a WAF or CDN shapes how an attacker approaches the target - for example seeking the origin server to bypass protections - but does not by itself grant access. It is useful context when assessing other findings.",
  "No direct remediation is required. Ensure the origin server is not directly reachable in a way that bypasses the WAF/CDN, and keep the protective service's rule sets current."
 ),
 "Email address exposed": (
  "Employee or organisational email addresses are discoverable from public sources or the application, revealing valid address formats and potential targets.",
  "An attacker uses the harvested addresses and the inferred naming convention to conduct phishing, password-spraying, and social-engineering campaigns against the organisation's users.",
  "Minimise unnecessary public exposure of individual email addresses, prefer role-based or contact-form addresses where practical, and reinforce the controls that limit the impact of phishing and credential attacks, such as multi-factor authentication and user awareness training."
 ),
}

# keyword -> GENERIC_WRITEUPS key, for findings whose title is scanner-specific
# (e.g. nuclei template names) rather than one of the RULES class names.
_GENERIC_KW = [
 (("sql injection", "sqli", "xss", "cross-site scripting", "rce", "remote code",
   "command injection", "template injection", "ssti", "deserial"), "Injection (SQLi / XSS / RCE / SSTI)"),
 (("open redirect", "unvalidated redirect"), "Open redirect"),
 (("ssrf", "server-side request forgery"), "SSRF"),
 (("cors", "access-control-allow-origin", "cross-origin"), "CORS misconfiguration"),
 (("host header", "x-forwarded-host"), "Host header injection"),
 (("takeover", "dangling", "unclaimed"), "Subdomain takeover"),
 (("introspection", "graphql"), "GraphQL introspection enabled"),
 (("telerik",), "Telerik UI (deserialization / weak-key RCE)"),
 ((".git", "git config", "git directory"), "Exposed .git directory"),
 ((".env", "backup file", ".bak", "web.config", "config file", "appsettings"), "Exposed sensitive file"),
 (("default credential", "default password", "weak password", "admin panel",
   "login panel", "exposed panel", "exposed login"), "Default / weak credentials or exposed login"),
 (("storage bucket", "s3 bucket", "blob container", "open bucket"), "Open cloud storage bucket"),
 (("api key", "secret key", "private key", "token leak", "credential"), "Leaked secret / credential"),
 (("cve-", "outdated", "end of life", "end-of-life", "deprecated version"), "Known-CVE / outdated technology"),
]


def generic_writeup(ev):
    """Return {'description','attack_scenario','remediation'} - a generic,
    client-agnostic three-section writeup for the finding's vulnerability class."""
    title = (ev.get("title") or ev.get("type") or "Finding").strip()
    wu = GENERIC_WRITEUPS.get(title)
    if wu is None:
        text = (ev.get("text") or "").lower()
        for words, key in _GENERIC_KW:
            if any(w in text for w in words) or any(w in title.lower() for w in words):
                wu = GENERIC_WRITEUPS.get(key)
                if wu:
                    break
    if wu is None:
        name = title
        wu = (
            "%s is a security weakness identified during testing. Issues of this "
            "class commonly stem from insecure configuration, missing hardening, or "
            "outdated components, and expose information or functionality that was not "
            "intended to be available to untrusted users." % name,
            "An attacker performing reconnaissance against the target identifies this "
            "condition and uses it to advance their objectives - gathering sensitive "
            "information, expanding a foothold, or chaining it with other findings to "
            "reach a greater impact such as unauthorised access or disruption of the service.",
            "Remediate the underlying condition by applying vendor patches and secure-"
            "configuration guidance for the affected component, removing or restricting any "
            "data or functionality that does not need to be exposed, and validating the fix "
            "through retesting. Apply defense-in-depth so a single misconfiguration does not "
            "materially weaken the environment.",
        )
    return {"description": wu[0], "attack_scenario": wu[1], "remediation": wu[2]}


def _writeup_text(ev):
    """The three-section writeup as one plain-text block with headings - for a
    single destination field such as a nuclei description or a report cell."""
    wu = generic_writeup(ev)
    return ("Description\n%s\n\nAttack Scenario\n%s\n\nRemediation Recommendations\n%s"
            % (wu["description"], wu["attack_scenario"], wu["remediation"]))


def _exact_asset(ev):
    """The exact location a finding was observed at - the full URL when there is
    one, else host:port, else the host. Deliberately avoids 'dhost' (the display
    host, which back-fills a resolved/CDN/apex name for IP-only events): reports
    must point at where the vuln actually is, not at a shared CDN root that would
    collapse many distinct findings onto one asset."""
    url = (ev.get("url") or "").strip()
    if url:
        return url
    host = (ev.get("host") or ev.get("dhost") or "").strip()
    port = ev.get("port")
    if host and port:
        return "%s:%s" % (host, port)
    return host or (ev.get("data_str") or "").strip()[:200]


def _finding_cves_cwes(ev):
    blob = " ".join([ev.get("text", "") or "", ev.get("data_str", "") or "",
                     ev.get("desc", "") or "", ev.get("why", "") or "",
                     " ".join(map(str, ev.get("tags", []) or []))])
    cves = list(dict.fromkeys(c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", blob, re.I)))
    cwes = list(dict.fromkeys(("CWE-" + n) for n in re.findall(r"CWE-(\d{1,5})", blob, re.I)))
    return cves, cwes


def build_nuclei_export(events, store, src_name=""):
    """Rebuild the findings as nuclei-native JSON so the file imports straight
    into AttackForge via its native Nuclei Scanner parser. Output is a JSON
    array, matching `nuclei -json-export <file>`."""
    sevmap = {"critical": "critical", "high": "high", "medium": "medium",
              "low": "low", "info": "info", "informational": "info", "unknown": "info"}
    out = []
    for ev in events:
        if ev.get("lane") != "finding":
            continue
        st = store.get(ev["id"])
        if st.get("status") in _EXPORT_SKIP_STATES:
            continue
        is_nuclei = _mod(ev, "nuclei")
        tid = _nuclei_template_id(ev) if is_nuclei else ""
        name = ((_nuclei_name(ev) if is_nuclei else "") or ev.get("title")
                or ev.get("type") or "Finding")
        if not tid:
            tid = _slug(name)
        sev = sevmap.get((ev.get("priority") or ev.get("severity") or "info").lower(), "info")
        # Affected asset. matched-at/url carry the EXACT location (full URL with
        # path); host carries a clean scheme://host origin. Real nuclei `host` is
        # an origin, and AttackForge's Nuclei parser derives the affected asset
        # from `host` - feeding it a full URL-with-path makes AF fail to parse it
        # and fall back to the project's ROOT asset (the "www"/apex), which is the
        # CDN-root bug the user hit. A clean origin here keeps the real (sub)domain
        # and never the root; matched-at/url still show exactly where it was found.
        asset = _exact_asset(ev)
        u = (ev.get("url") or "").strip()
        if u:
            try:
                pu = urllib.parse.urlsplit(u)
                origin = ("%s://%s" % (pu.scheme, pu.netloc)) if (pu.scheme and pu.netloc) else asset
            except Exception:
                origin = asset
        else:
            origin = asset
        host = origin
        matched = asset
        cves, cwes = _finding_cves_cwes(ev)
        refs = [s[1] for s in (ev.get("sources") or [])
                if isinstance(s, (list, tuple)) and len(s) > 1 and s[1]]
        blob = (ev.get("data_str", "") or "") + " " + (ev.get("desc", "") or "")
        mx = re.search(r"Extracted Data:\s*\[([^\]]*)\]", blob, re.I)
        extracted = [x for x in re.split(r"\s*,\s*", mx.group(1).strip())
                     if x] if (mx and mx.group(1).strip()) else []

        # Generic, reusable 3-section writeup (Description / Attack Scenario /
        # Remediation Recommendations) goes in the description field; the exact
        # location/evidence stays in matched-at/url/extracted-results below.
        desc = _writeup_text(ev)

        info = {
            "name": name,
            "author": ["bbot"],
            "tags": [str(t) for t in (ev.get("tags") or [])],
            "description": desc,
            "reference": refs,
            "severity": sev,
        }
        classification = {}
        if cves:
            classification["cve-id"] = cves          # nuclei emits these uppercase
        if cwes:
            classification["cwe-id"] = cwes
        if classification:
            info["classification"] = classification

        rec = {
            "template-id": tid,
            "template-url": ("https://github.com/projectdiscovery/nuclei-templates"
                             if is_nuclei else ""),
            "info": info,
            "type": "http" if matched.startswith("http") else "network",
            "host": host,
            "matched-at": matched or host,
            "url": matched or host,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }
        if extracted:
            rec["extracted-results"] = extracted
        out.append(rec)
    return json.dumps(out, indent=2, ensure_ascii=False)


_PLEXTRAC_SEV = {"critical": "Critical", "high": "High", "medium": "Medium",
                 "low": "Low", "info": "Informational", "unknown": "Informational"}
_PLEXTRAC_COLUMNS = ["title", "severity", "status", "description", "recommendations",
                     "references", "affected_assets", "tags", "cvss_temporal",
                     "cwe", "cve", "category", "category value"]


def build_plextrac_csv(events, store, src_name=""):
    """PlexTrac Report Findings CSV template. Documented column order and
    vocabulary; one row per issue, assets/refs/tags/ids comma-joined in a
    quoted cell. Required columns are title, severity, description."""
    import io
    groups, order = {}, []
    for ev in events:
        if ev.get("lane") != "finding":
            continue
        st = store.get(ev["id"])
        if st.get("status") in _EXPORT_SKIP_STATES:
            continue
        sev = _PLEXTRAC_SEV.get((ev.get("priority") or "info").lower(), "Informational")
        key = (ev.get("title", ""), sev, ev.get("module", ""))
        g = groups.get(key)
        if g is None:
            wu = generic_writeup(ev)   # generic, reusable 3-section writeup
            g = {"title": ev.get("title") or ev.get("type") or "Finding", "severity": sev,
                 "status": "Closed",
                 "description": ("Description\n%s\n\nAttack Scenario\n%s"
                                 % (wu["description"], wu["attack_scenario"])),
                 "recommendations": wu["remediation"],
                 "_assets": [], "_aset": set(), "_refs": [], "_rset": set(),
                 "_tags": [], "_tset": set(), "_cve": [], "_cwe": []}
            groups[key] = g
            order.append(key)
        target = _exact_asset(ev)   # exact URL/location, never the CDN/display root
        if target and target not in g["_aset"]:
            g["_aset"].add(target); g["_assets"].append(target)
        for s in (ev.get("sources") or []):
            if isinstance(s, (list, tuple)) and len(s) > 1 and s[1] and s[1] not in g["_rset"]:
                g["_rset"].add(s[1]); g["_refs"].append(s[1])
        for tg in (ev.get("tags") or []):
            tg = str(tg)
            if tg not in g["_tset"]:
                g["_tset"].add(tg); g["_tags"].append(tg)
        cves, cwes = _finding_cves_cwes(ev)
        for c in cves:
            if c not in g["_cve"]:
                g["_cve"].append(c)
        for c in cwes:
            if c not in g["_cwe"]:
                g["_cwe"].append(c)
        if st.get("status", "new") in REPORT_OPEN_STATES:
            g["status"] = "Open"

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_PLEXTRAC_COLUMNS)
    order.sort(key=lambda k: _REPORT_SEV_RANK.get(groups[k]["severity"], 0), reverse=True)
    for key in order:
        g = groups[key]
        w.writerow([
            g["title"], g["severity"], g["status"], g["description"], g["recommendations"],
            ", ".join(g["_refs"]), ", ".join(g["_assets"]), ", ".join(g["_tags"]),
            "", ", ".join(g["_cwe"]), ", ".join(g["_cve"]), "", "",
        ])
    return buf.getvalue()


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
#  XLSX export (stdlib only: a styled .xlsx is a zip of XML parts). One sheet per
#  recon tab, with a styled header, frozen top row, autofilter, tuned column
#  widths, severity colour-coding and wrapped text.
# --------------------------------------------------------------------------- #

_XLSX_STYLES = (
'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
'<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
'<fonts count="5">'
'<font><sz val="11"/><color rgb="FF1A1A1A"/><name val="Calibri"/></font>'
'<font><b/><sz val="11"/><color rgb="FF1A1A1A"/><name val="Calibri"/></font>'
'<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
'<font><b/><sz val="16"/><color rgb="FF1F2A37"/><name val="Calibri"/></font>'
'<font><sz val="11"/><color rgb="FF6B7684"/><name val="Calibri"/></font>'
'</fonts>'
'<fills count="9">'
'<fill><patternFill patternType="none"/></fill>'
'<fill><patternFill patternType="gray125"/></fill>'
'<fill><patternFill patternType="solid"><fgColor rgb="FF1F2A37"/></patternFill></fill>'
'<fill><patternFill patternType="solid"><fgColor rgb="FFFF4D6D"/></patternFill></fill>'
'<fill><patternFill patternType="solid"><fgColor rgb="FFFF7B3D"/></patternFill></fill>'
'<fill><patternFill patternType="solid"><fgColor rgb="FFFFC93C"/></patternFill></fill>'
'<fill><patternFill patternType="solid"><fgColor rgb="FF4A9EFF"/></patternFill></fill>'
'<fill><patternFill patternType="solid"><fgColor rgb="FFE7ECF2"/></patternFill></fill>'
'<fill><patternFill patternType="solid"><fgColor rgb="FFF3F6F9"/></patternFill></fill>'
'</fills>'
'<borders count="2">'
'<border><left/><right/><top/><bottom/><diagonal/></border>'
'<border><left style="thin"><color rgb="FFD0D7DE"/></left><right style="thin"><color rgb="FFD0D7DE"/></right>'
'<top style="thin"><color rgb="FFD0D7DE"/></top><bottom style="thin"><color rgb="FFD0D7DE"/></bottom><diagonal/></border>'
'</borders>'
'<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
'<cellXfs count="12">'
'<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
'<xf numFmtId="0" fontId="2" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="left" vertical="center" wrapText="1"/></xf>'
'<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'
'<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top"/></xf>'
'<xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>'
'<xf numFmtId="0" fontId="2" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>'
'<xf numFmtId="0" fontId="1" fillId="5" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>'
'<xf numFmtId="0" fontId="2" fillId="6" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>'
'<xf numFmtId="0" fontId="0" fillId="7" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>'
'<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
'<xf numFmtId="0" fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
'<xf numFmtId="0" fontId="1" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1"><alignment vertical="top"/></xf>'
'</cellXfs>'
'<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
'</styleSheet>')

_XLSX_SEV_STYLE = {"critical": 4, "high": 5, "medium": 6, "low": 7, "info": 8, "unknown": 8}


def _xl_col(n):
    s = ""
    while n > 0:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _xl_text(v):
    if v is None:
        return ""
    s = str(v)
    s = "".join(c for c in s if c in "\t\n\r" or ord(c) >= 32)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _xl_cell(col, row, value, style=0, numeric=False):
    ref = "%s%d" % (_xl_col(col), row)
    if numeric:
        try:
            if value in (None, "", 0):
                return '<c r="%s" s="3"/>' % ref
            return '<c r="%s" s="3"><v>%s</v></c>' % (ref, int(value))
        except Exception:
            pass
    t = _xl_text(value)
    if t == "":
        return '<c r="%s" s="%d"/>' % (ref, style)
    return ('<c r="%s" s="%d" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>'
            % (ref, style, t))


def _xl_sheet(cols, rows, autofilter=True, freeze=True):
    """cols: list of {title, width, kind}. kind in text|num|sev|wrap|label."""
    p = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
         '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">']
    if freeze:
        p.append('<sheetViews><sheetView workbookViewId="0">'
                 '<pane ySplit="1" topLeftCell="A2" state="frozen" activePane="bottomLeft"/>'
                 '<selection pane="bottomLeft"/></sheetView></sheetViews>')
    p.append('<sheetFormatPr defaultRowHeight="15"/>')
    p.append('<cols>')
    for i, c in enumerate(cols, 1):
        p.append('<col min="%d" max="%d" width="%d" customWidth="1"/>' % (i, i, c.get("width", 16)))
    p.append('</cols><sheetData>')
    p.append('<row r="1" ht="20" customHeight="1">')
    for i, c in enumerate(cols, 1):
        p.append(_xl_cell(i, 1, c["title"], style=1))
    p.append('</row>')
    r = 2
    for row in rows:
        p.append('<row r="%d">' % r)
        for i, c in enumerate(cols, 1):
            val = row[i - 1] if i - 1 < len(row) else ""
            kind = c.get("kind", "text")
            if kind == "num":
                p.append(_xl_cell(i, r, val, numeric=True))
            elif kind == "sev":
                p.append(_xl_cell(i, r, str(val or "").title(),
                                  style=_XLSX_SEV_STYLE.get(str(val or "").lower(), 8)))
            elif kind == "wrap":
                p.append(_xl_cell(i, r, val, style=2))
            elif kind == "label":
                p.append(_xl_cell(i, r, val, style=11))
            else:
                p.append(_xl_cell(i, r, val, style=3))
        p.append('</row>')
        r += 1
    p.append('</sheetData>')
    if autofilter and rows:
        p.append('<autoFilter ref="A1:%s%d"/>' % (_xl_col(len(cols)), len(rows) + 1))
    p.append('</worksheet>')
    return "".join(p)


def _refs_text(ev):
    out = []
    for s in (ev.get("sources") or []):
        if isinstance(s, (list, tuple)) and len(s) > 1:
            out.append("%s: %s" % (s[0], s[1]))
    return "\n".join(out)


def _cmds_text(ev):
    out = []
    for c in (ev.get("commands") or []):
        if not (isinstance(c, (list, tuple)) and len(c) > 1):
            continue
        kind = c[2] if len(c) > 2 else "shell"
        tag = " [browser console]" if kind == "console" else (" [manual]" if kind == "manual" else "")
        out.append("# %s%s\n%s" % (c[0], tag, c[1]))
    return "\n".join(out)


def build_xlsx(events, findings, assets, store, shots, src_name=""):
    """A styled multi-sheet workbook mirroring the recon tabs. Stdlib only."""
    sheets = []                       # (name, xml)

    # ---- Overview ----
    sev_ct = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for e in findings:
        k = e.get("priority")
        if k in sev_ct:
            sev_ct[k] += 1
    stat_ct = {}
    for e in findings:
        s = store.get(e["id"])["status"]
        stat_ct[s] = stat_ct.get(s, 0) + 1
    tcount = {}
    for e in events:
        tcount[e["type"]] = tcount.get(e["type"], 0) + 1
    mcount = {}
    for e in events:
        if e.get("module"):
            mcount[e["module"]] = mcount.get(e["module"], 0) + 1
    ov = [["Scan source", src_name],
          ["Generated", datetime.now().isoformat(timespec="seconds")],
          ["Total events", str(len(events))],
          ["Findings", str(len(findings))],
          ["Assets", str(len(assets))],
          ["Screenshots", str(len(shots or []))],
          ["", ""],
          ["Critical findings", str(sev_ct["critical"])],
          ["High findings", str(sev_ct["high"])],
          ["Medium findings", str(sev_ct["medium"])],
          ["Low findings", str(sev_ct["low"])],
          ["Info findings", str(sev_ct["info"])],
          ["", ""]]
    for s in STATUSES:
        if stat_ct.get(s["key"]):
            ov.append(["Triage - " + s["label"], str(stat_ct[s["key"]])])
    ov.append(["", ""])
    ov.append(["Event types", "\n".join("%s: %d" % (t, n)
               for t, n in sorted(tcount.items(), key=lambda x: -x[1]))])
    ov.append(["Top modules", "\n".join("%s: %d" % (t, n)
               for t, n in sorted(mcount.items(), key=lambda x: -x[1])[:20])])
    sheets.append(("Overview", _xl_sheet(
        [{"title": "Metric", "width": 26, "kind": "label"},
         {"title": "Value", "width": 80, "kind": "wrap"}], ov, autofilter=False)))

    # ---- Findings ----
    if findings:
        cols = [{"title": "Severity", "width": 12, "kind": "sev"},
                {"title": "Title", "width": 40, "kind": "wrap"},
                {"title": "Target", "width": 42, "kind": "wrap"},
                {"title": "Host", "width": 24}, {"title": "Port", "width": 7, "kind": "num"},
                {"title": "Module", "width": 16}, {"title": "Status", "width": 15},
                {"title": "Notes", "width": 28, "kind": "wrap"},
                {"title": "Tags", "width": 28, "kind": "wrap"},
                {"title": "Description", "width": 55, "kind": "wrap"},
                {"title": "Evidence", "width": 55, "kind": "wrap"},
                {"title": "Remediation", "width": 55, "kind": "wrap"},
                {"title": "References", "width": 45, "kind": "wrap"},
                {"title": "Commands", "width": 55, "kind": "wrap"},
                {"title": "Evidence screenshots", "width": 32, "kind": "wrap"}]
        rows = []
        for e in findings:
            st = store.get(e["id"])
            rows.append([e.get("priority", ""), e.get("title", ""), _target_of(e),
                         e.get("dhost") or e.get("host", ""), e.get("port") or "",
                         e.get("module", ""), st["status"], st.get("notes", ""),
                         ", ".join(e.get("tags", [])), e.get("why", ""),
                         e.get("data_str", ""), e.get("remediation", ""),
                         _refs_text(e), _cmds_text(e), "\n".join(st.get("evidence", []))])
        sheets.append(("Findings", _xl_sheet(cols, rows)))

    # ---- Assets ----
    if assets:
        cols = [{"title": "Type", "width": 18}, {"title": "Target", "width": 46, "kind": "wrap"},
                {"title": "Host", "width": 26}, {"title": "Port", "width": 7, "kind": "num"},
                {"title": "Module", "width": 18}, {"title": "Tags", "width": 40, "kind": "wrap"},
                {"title": "Juicy", "width": 20, "kind": "wrap"}]
        rows = [[e.get("type", ""), _target_of(e), e.get("dhost") or e.get("host", ""),
                 e.get("port") or "", e.get("module", ""), ", ".join(e.get("tags", [])),
                 ", ".join(e.get("juicy", []))] for e in assets]
        sheets.append(("Assets", _xl_sheet(cols, rows)))

    # ---- Hosts (pivot) ----
    hosts = {}
    for e in events:
        h = (e.get("dhost") or e.get("host") or "")
        if not h:
            continue
        s = hosts.setdefault(h, {"f": 0, "p": 0, "u": 0, "t": 0, "sev": 0, "juicy": set()})
        for j in e.get("juicy", []):
            s["juicy"].add(j)
        if e.get("lane") == "finding":
            s["f"] += 1
            s["sev"] = max(s["sev"], SEV_RANK.get(e.get("priority"), 0))
        elif e.get("type") == "OPEN_TCP_PORT":
            s["p"] += 1
        elif e.get("type") in ("URL", "URL_UNVERIFIED", "URL_HINT"):
            s["u"] += 1
        elif e.get("type") == "TECHNOLOGY":
            s["t"] += 1
    if hosts:
        rank_name = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info", 0: ""}
        cols = [{"title": "Host", "width": 36}, {"title": "Top severity", "width": 13, "kind": "sev"},
                {"title": "Findings", "width": 10, "kind": "num"},
                {"title": "Open ports", "width": 11, "kind": "num"},
                {"title": "URLs", "width": 9, "kind": "num"}, {"title": "Tech", "width": 9, "kind": "num"},
                {"title": "Juicy tags", "width": 34, "kind": "wrap"}]
        rows = []
        for h, s in sorted(hosts.items(), key=lambda kv: (-kv[1]["sev"], -kv[1]["f"], kv[0])):
            rows.append([h, rank_name.get(s["sev"], ""), s["f"], s["p"], s["u"], s["t"],
                         ", ".join(sorted(s["juicy"]))])
        sheets.append(("Hosts", _xl_sheet(cols, rows)))

    # ---- URLs (deduped) ----
    seen, urows = set(), []
    for e in findings + assets:
        u = e.get("url") or ""
        if not u and e.get("type") in ("URL", "URL_UNVERIFIED", "URL_HINT"):
            d = (e.get("data_str") or "").split()
            if d and d[0].lower().startswith("http"):
                u = d[0]
        if u and u not in seen:
            seen.add(u)
            urows.append([u, e.get("type", ""), ", ".join(e.get("tags", []))])
    if urows:
        urows.sort(key=lambda r: r[0])
        cols = [{"title": "URL", "width": 72, "kind": "wrap"}, {"title": "Type", "width": 16},
                {"title": "Tags", "width": 40, "kind": "wrap"}]
        sheets.append(("URLs", _xl_sheet(cols, urows)))

    # ---- Emails ----
    emails = collect_emails(events)
    if emails:
        cols = [{"title": "Email", "width": 42}, {"title": "Domain", "width": 30}]
        rows = [[em, em.split("@")[1] if "@" in em else ""] for em in emails]
        sheets.append(("Emails", _xl_sheet(cols, rows)))

    # ---- Screenshots (metadata; images are in the live dashboard) ----
    if shots:
        cols = [{"title": "File", "width": 42}, {"title": "Label / URL", "width": 50, "kind": "wrap"},
                {"title": "Host", "width": 28}, {"title": "Status", "width": 14},
                {"title": "Size (bytes)", "width": 13, "kind": "num"}]
        rows = []
        for it in shots:
            stt = store.get("shot:" + it.get("rel", ""))["status"]
            rows.append([it.get("file", ""), it.get("label", ""),
                         (it.get("label", "") or "").replace("http://", "").replace("https://", "").split("/")[0].split(":")[0],
                         stt, it.get("size") or ""])
        sheets.append(("Screenshots", _xl_sheet(cols, rows)))

    # ---- assemble the package ----
    ct = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    for i in range(1, len(sheets) + 1):
        ct.append('<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % i)
    ct.append('</Types>')

    wb = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>']
    for i, (name, _xml) in enumerate(sheets, 1):
        wb.append('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (_xl_text(name)[:31], i, i))
    wb.append('</sheets></workbook>')

    rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for i in range(1, len(sheets) + 1):
        rels.append('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i, i))
    rels.append('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' % (len(sheets) + 1))
    rels.append('</Relationships>')

    root_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                 '</Relationships>')

    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    z.writestr("[Content_Types].xml", "".join(ct))
    z.writestr("_rels/.rels", root_rels)
    z.writestr("xl/workbook.xml", "".join(wb))
    z.writestr("xl/_rels/workbook.xml.rels", "".join(rels))
    z.writestr("xl/styles.xml", _XLSX_STYLES)
    for i, (name, xml) in enumerate(sheets, 1):
        z.writestr("xl/worksheets/sheet%d.xml" % i, xml)
    z.close()
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
padding:12px 14px;margin-bottom:10px;content-visibility:auto;contain-intrinsic-size:auto 120px;}
.card.sel{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent2);}
.card h3{margin:0 0 3px;font-size:15px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.sevtag{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
padding:2px 7px;border-radius:5px;color:#07101f;}
.statustag{font-size:11px;padding:2px 8px;border-radius:5px;color:#fff;}
.tgt{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--accent);
cursor:pointer;word-break:break-all;}
.tgt:hover{text-decoration:underline;}
.detail{margin:7px 0;padding:7px 9px;background:var(--panel2);border:1px solid var(--line);border-radius:6px;font-size:12.5px;color:var(--text);word-break:break-word;white-space:pre-wrap;}
.detail .lbl{color:var(--muted);font-weight:600;margin-right:6px;}
.why{margin:7px 0;color:var(--text);}
.remed{margin-top:8px;}
.remed>summary{cursor:pointer;color:#38c172;font-weight:600;font-size:12.5px;}
.remed .why{margin:6px 0 4px;}
.sources{font-size:12px;color:var(--muted);margin:4px 0 2px;word-break:break-word;}
.sources .lbl{color:var(--muted);font-weight:600;margin-right:4px;}
.sources a{color:var(--accent2);text-decoration:none;}
.sources a:hover{text-decoration:underline;}
.sources .sep{color:var(--line);}
.evidence{margin-top:8px;border-top:1px dashed var(--line);padding-top:8px;}
.evlbl{font-size:12px;font-weight:600;color:#a66bff;margin-bottom:5px;}
.evrow{display:flex;flex-wrap:wrap;gap:8px;}
.evrow:empty{display:none;}
.evthumb{position:relative;display:inline-block;margin-bottom:6px;}
.evthumb img{height:88px;max-width:160px;object-fit:cover;border:1px solid var(--line);border-radius:6px;cursor:zoom-in;display:block;}
.evdel{position:absolute;top:-7px;right:-7px;background:#ff4d6d;color:#fff;border:1px solid var(--bg);border-radius:50%;width:19px;height:19px;font-size:13px;line-height:1;cursor:pointer;padding:0;}
.evpaste{border:1px dashed var(--line);border-radius:6px;padding:9px 11px;font-size:12px;color:var(--muted);cursor:text;outline:none;background:var(--panel2);}
.evpaste:focus{border-color:var(--accent2);color:var(--text);background:var(--panel);}
.evfile{color:var(--accent2);cursor:pointer;text-decoration:underline;}
.sub{font-size:12px;color:var(--muted);}
details{margin-top:8px;}
summary{cursor:pointer;color:var(--muted);font-size:13px;}
.play li{margin:3px 0;}
.cmd{display:flex;align-items:center;gap:8px;margin:4px 0;}
.cmd code{flex:1;background:#0a0e15;border:1px solid var(--line);border-radius:6px;padding:5px 8px;
font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;overflow-x:auto;white-space:pre;}
.cmdblock{margin:6px 0;}
.cmdlbl{font-size:11px;color:var(--muted);margin:0 0 2px 2px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;}
.cmdtag{font-size:9px;font-weight:700;letter-spacing:.3px;text-transform:uppercase;padding:1px 6px;border-radius:9px;}
.ck-console{background:#1d3a5f;color:#8ec7ff;border:1px solid #2d5a8f;}
.ck-manual{background:#3a2f1d;color:#ffce8e;border:1px solid #6b4f2d;}
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
/* urls */
.urlbox{width:100%;min-height:440px;background:#0a0e15;border:1px solid var(--line);border-radius:8px;
color:var(--text);padding:9px 11px;font:12px/1.55 ui-monospace,Menlo,Consolas,monospace;resize:vertical;
outline:none;white-space:pre;overflow:auto;}
.urlbox:focus{border-color:var(--accent2);}
.hint{font-size:12px;color:var(--muted);margin:0 0 10px;}
.hint code{background:var(--panel2);border:1px solid var(--line);border-radius:4px;padding:0 5px;font-size:11px;}
/* screenshots */
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));}
.shot{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;transition:border-color .12s;content-visibility:auto;contain-intrinsic-size:auto 250px;}
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
.shoturl{display:block;padding:8px 11px;font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis;border-bottom:1px solid var(--line);background:var(--panel2);}
a.shoturl{color:var(--accent2);text-decoration:none;}
a.shoturl:hover{text-decoration:underline;background:var(--panel);}
.shoturl.nolink{color:var(--muted);font-weight:500;}
.shoturl .ext{opacity:.7;font-weight:400;}
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
.host{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;margin-bottom:10px;overflow:hidden;content-visibility:auto;contain-intrinsic-size:auto 90px;}
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
    <button class="tab" data-tab="urls">URLs</button>
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
      <a href="/api/export?fmt=attackforge" download="bscope-nuclei.json">AttackForge (Nuclei JSON)</a>
      <a href="/api/export?fmt=plextrac" download="bscope-plextrac.csv">PlexTrac (Findings CSV)</a>
      <a href="/api/export?fmt=xlsx">Workbook (XLSX)</a>
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
  <section id="view-urls" style="display:none"></section>
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
  top(typeCount,99).forEach(([k,v])=>h+=`<div class="sub">${esc(k)} <span class="muted">x${v}</span></div>`);
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
    if(s.shot)h+=`<img class="hthumb" loading="lazy" decoding="async" style="float:right;margin:0 0 8px 10px" src="${s.shot.src}" onclick="${hx('openImg('+JSON.stringify(s.shot.src)+','+JSON.stringify(s.host)+')')}">`;
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

/* A concise, bounded recon command set for one host: one service scan, then
   web recon against each DISTINCT web root (scheme://host:port) seen on the
   host - not one command per finding/URL, which previously produced hundreds.
   Per-finding verification commands still live on each finding card. */
const HOST_CMD_ROOT_LIMIT=8;
function hostCommands(s){
  const out=[],seen=new Set();
  const add=(label,cmd)=>{if(cmd&&!seen.has(cmd)){seen.add(cmd);out.push([label,cmd]);}};
  const ports=[...new Set(s.ports.map(p=>p.port).filter(Boolean))].sort((a,b)=>a-b);
  if(ports.length)add('Service scan (all ports)','nmap -sCV -p'+ports.join(',')+' '+s.host);
  else add('Port scan','nmap -sCV --top-ports 1000 '+s.host);
  // distinct web roots on this host, from its urls/findings
  const roots=[];const rseen=new Set();
  [...s.urls,...s.findings,...s.tech].forEach(ev=>{const u=ev.url||ev.data_str||'';
    try{const p=new URL(u);const r=p.protocol+'//'+p.host;if(!rseen.has(r)){rseen.add(r);roots.push(r);}}catch(e){}});
  roots.slice(0,HOST_CMD_ROOT_LIMIT).forEach(r=>{
    add('Headers',"curl -sSIk '"+r+"'");
    add('Fingerprint',"httpx -u '"+r+"' -sc -title -tech-detect -server");
    add('Nuclei',"nuclei -u '"+r+"'");
    add('Content discovery',"ffuf -u '"+r+"/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/common.txt");
  });
  if(roots.length>HOST_CMD_ROOT_LIMIT)add('More web roots',"# "+(roots.length-HOST_CMD_ROOT_LIMIT)+" more web root(s) on this host - see the URLs tab");
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
function reportedHTML(ev){
  // the scanner's own text for this exact finding - the ground truth of what was found
  const d=ev.data_str||'';
  if(ev.lane!=='finding'||!d)return '';
  if(d===ev.why||d===ev.title)return '';
  return `<div class="detail"><span class="lbl">Reported</span>${esc(d)}</div>`;
}
function remediationHTML(ev){
  if(ev.lane!=='finding'||!ev.remediation)return '';
  let h=`<details class="remed" open><summary>Remediation</summary><div class="why">${esc(ev.remediation)}</div>`;
  if(ev.sources&&ev.sources.length){
    h+='<div class="sources"><span class="lbl">Sources:</span> ';
    h+=ev.sources.map(x=>`<a href="${esc(x[1])}" target="_blank" rel="noopener noreferrer">${esc(x[0])}</a>`).join('<span class="sep"> &middot; </span>');
    h+='</div>';}
  h+='</details>';return h;}
function evImgs(ev){
  const list=(ev.triage&&ev.triage.evidence)||[];
  if(!list.length)return '';
  return list.map(n=>{const src='/evidence/'+encodeURIComponent(n);
    return `<span class="evthumb"><img loading="lazy" decoding="async" src="${src}" title="click to enlarge" onclick="${hx('openImg('+JSON.stringify(src)+','+JSON.stringify('Evidence: '+(ev.title||''))+')')}">`
      +`<button class="evdel" title="remove evidence" onclick="${hx('event.stopPropagation();removeEvidence('+JSON.stringify(ev.id)+','+JSON.stringify(n)+')')}">&times;</button></span>`;}).join('');
}
function evidenceHTML(ev){
  if(ev.lane!=='finding')return '';
  return `<div class="evidence" id="ev-${ev.id}">`
    +`<div class="evlbl">&#128247; Evidence${(ev.triage&&ev.triage.evidence&&ev.triage.evidence.length)?(' ('+ev.triage.evidence.length+')'):''}</div>`
    +`<div class="evrow">${evImgs(ev)}</div>`
    +`<div class="evpaste" tabindex="0" onpaste="onEvPaste(event,'${ev.id}')" onclick="this.focus()">`
    +`Click here, then press Ctrl+V / &#8984;V to paste a screenshot as evidence`
    +` &middot; <label class="evfile" onclick="event.stopPropagation()">choose file<input type="file" accept="image/*" style="display:none" onchange="onEvFile(this,'${ev.id}')"></label>`
    +`</div></div>`;
}
function setEvidence(id,list){
  const ev=DATA.findings.find(f=>f.id===id);
  if(ev){ev.triage=ev.triage||{};ev.triage.evidence=list||[];}
  const box=document.getElementById('ev-'+id);
  if(box&&ev){const row=box.querySelector('.evrow');if(row)row.innerHTML=evImgs(ev);
    const lbl=box.querySelector('.evlbl');if(lbl)lbl.innerHTML='&#128247; Evidence'+(ev.triage.evidence.length?(' ('+ev.triage.evidence.length+')'):'');}
}
function uploadEvidence(id,dataURL){
  toast('uploading evidence…');
  fetch('/api/evidence',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,data:dataURL})})
    .then(r=>r.ok?r.json():r.text().then(t=>Promise.reject(t||('HTTP '+r.status))))
    .then(d=>{setEvidence(id,d.evidence);toast('evidence added');})
    .catch(e=>toast('upload failed: '+e));
}
function removeEvidence(id,name){
  fetch('/api/evidence_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,name:name})})
    .then(r=>r.json()).then(d=>{setEvidence(id,d.evidence);toast('evidence removed');})
    .catch(()=>toast('remove failed'));
}
function fileToEvidence(id,file){
  if(!file||!/^image\//.test(file.type||''))return toast('not an image');
  if(file.size>12*1024*1024)return toast('image too large (max 12MB)');
  const fr=new FileReader();fr.onload=()=>uploadEvidence(id,fr.result);
  fr.onerror=()=>toast('could not read image');fr.readAsDataURL(file);
}
function onEvPaste(e,id){
  const items=(e.clipboardData&&e.clipboardData.items)||[];
  for(let i=0;i<items.length;i++){const it=items[i];
    if(it.type&&it.type.indexOf('image')===0){e.preventDefault();const f=it.getAsFile();if(f)fileToEvidence(id,f);return;}}
  toast('no image on the clipboard - copy a screenshot first');
}
function onEvFile(input,id){if(input.files&&input.files[0])fileToEvidence(id,input.files[0]);input.value='';}
function cmdHTML(c){
  const kind=(c&&c[2])||'shell';
  const badge=kind==='console'?'<span class="cmdtag ck-console">browser console</span>'
            :(kind==='manual'?'<span class="cmdtag ck-manual">manual</span>':'');
  const lbl=c[0]?`<div class="cmdlbl">${esc(c[0])}${badge}</div>`:'';
  return `<div class="cmdblock">${lbl}<div class="cmd"><code>${esc(c[1])}</code>`
    +`<button class="copy" onclick="${hx('copy('+JSON.stringify(c[1])+')')}">copy</button></div></div>`;
}
function playbookHTML(ev){let h='';
  if(ev.playbook&&ev.playbook.length){
    h+=`<details open><summary>What a tester can do</summary><ul class="play">`;
    ev.playbook.forEach(p=>h+=`<li>${esc(p)}</li>`);h+=`</ul>`;
    if(ev.commands&&ev.commands.length){h+='<div style="margin-top:6px">';
      ev.commands.forEach(c=>h+=cmdHTML(c));
      h+='</div>';}
    h+=`</details>`;}
  return h;}
function cardHTML(ev,idx){
  const sc=SEVC[ev.priority]||'#5c6b7e',st=SMAP[ev.triage.status]||STATUSES[0];
  const tgt=ev.url||(ev.port?`${H(ev)}:${ev.port}`:H(ev))||ev.data_str.slice(0,90);
  const thumb=thumbFor(ev);
  let h=`<div class="card ${idx===selIdx?'sel':''}" style="border-left-color:${sc}" id="card-${ev.id}" data-eid="${ev.id}" data-idx="${idx}">`;
  if(thumb)h+=`<img class="cardthumb" loading="lazy" decoding="async" src="${thumb.src}" onclick="${hx('event.stopPropagation();openImg('+JSON.stringify(thumb.src)+','+JSON.stringify(tgt)+')')}">`;
  h+=`<h3><span class="sevtag" style="background:${sc}">${ev.priority}</span>${esc(ev.title)}
      <span class="statustag" style="background:${st.color}">${st.label}</span></h3>`;
  h+=`<div>${badges(ev)}</div>`;
  h+=`<div class="tgt" onclick="${hx('copy('+JSON.stringify(tgt)+')')}" title="click to copy">${esc(tgt)}</div>`;
  h+=`<div class="sub">${esc(ev.type)} &middot; ${esc(ev.module||'-')}${ev.tags.length?' &middot; '+esc(ev.tags.join(', ')):''}</div>`;
  if(ev.why)h+=`<div class="why">${esc(ev.why)}</div>`;
  h+=reportedHTML(ev);
  h+=playbookHTML(ev);
  h+=remediationHTML(ev);
  h+=evidenceHTML(ev);
  h+=`<div class="statusrow">${statusButtons(ev,false)}</div>`;
  h+=`<textarea class="notes" placeholder="tester notes (autosaves)..." oninput="noteInput('${ev.id}',this.value)" onblur="saveNotes('${ev.id}',this.value)">${esc(ev.triage.notes||'')}</textarea>`;
  h+=`</div>`;return h;
}
function groupHTML(sig,items){
  const rep=items[0],sc=SEVC[rep.priority]||'#5c6b7e';
  const anyNew=COMPARE&&items.some(i=>i.is_new);
  const juicy=new Set();items.forEach(i=>(i.juicy||[]).forEach(j=>juicy.add(j)));
  // status breakdown across the group, in workflow order
  // one row per affected target: collapse repeated URLs/targets inside the group
  const tgtOf=ev=>ev.url||(ev.port?`${H(ev)}:${ev.port}`:H(ev))||ev.data_str||'';
  const _seenT=new Set(),uniq=[];
  items.forEach(ev=>{const tg=tgtOf(ev);if(!_seenT.has(tg)){_seenT.add(tg);uniq.push(ev);}});
  const cnt={};uniq.forEach(ev=>{const k=ev.triage.status||'new';cnt[k]=(cnt[k]||0)+1;});
  let h=`<div class="card" style="border-left-color:${sc}">`;
  h+=`<h3><span class="sevtag" style="background:${sc}">${rep.priority}</span>${esc(rep.title)}
      <span class="muted">x${uniq.length}</span></h3>`;
  let b='';if(anyNew)b+='<span class="newbadge">NEW</span> ';
  [...juicy].forEach(j=>b+=`<span class="juicytag">&#9733; ${esc(j)}</span> `);
  if(b)h+=`<div>${b}</div>`;
  h+=`<div class="sub">${esc(rep.type)} &middot; ${esc(rep.module||'-')}</div>`;
  if(rep.why)h+=`<div class="why">${esc(rep.why)}</div>`;
  h+=reportedHTML(rep);
  h+=playbookHTML(rep);
  h+=remediationHTML(rep);
  // --- affected targets: compact, scannable, paginated, drill-down per row ---
  const expanded=expandedGroups.has(sig);
  const shown=expanded?uniq:uniq.slice(0,GROUP_LIMIT);
  let sum='';STATUSES.forEach(s=>{if(cnt[s.key])sum+=`<span class="gsum"><span class="sev-dot" style="background:${s.color}"></span><b>${cnt[s.key]}</b> ${esc(s.label.toLowerCase())}</span>&nbsp; `;});
  h+=`<div class="sec" style="margin-top:8px"><h4 style="margin:0 0 4px;font-size:12px;color:var(--muted)">Affected targets (${uniq.length})</h4>`;
  if(sum)h+=`<div style="margin:2px 0 6px">${sum}</div>`;
  shown.forEach(ev=>{const tgt=tgtOf(ev).slice(0,200);
    const st=SMAP[ev.triage.status]||STATUSES[0];
    h+=`<div class="inst" data-eid="${ev.id}">
      <span class="sdot" style="background:${st.color}" title="${esc(st.label)}"></span>
      <span class="it" onclick="${hx('copy('+JSON.stringify(tgt)+')')}" title="click to copy">${esc(tgt)}</span>
      <span class="statustag mini" style="background:${st.color}">${esc(st.label)}</span>
      <details class="rowtri"><summary>triage</summary>
        <div class="statusrow">${statusButtons(ev,true)}</div>
        <input class="notes" style="min-height:28px;width:100%" placeholder="notes..." value="${esc(ev.triage.notes||'')}" oninput="noteInput('${ev.id}',this.value)" onblur="saveNotes('${ev.id}',this.value)">
        ${evidenceHTML(ev)}
      </details></div>`;});
  if(!expanded&&uniq.length>GROUP_LIMIT)
    h+=`<button class="gmore" onclick="${hx('expandGroup('+JSON.stringify(sig)+')')}">show all ${uniq.length} targets</button>`;
  h+='</div></div>';return h;
}
/* ---------------- incremental (windowed) rendering ----------------
   Large scans have thousands of findings/assets. Building every card in one
   innerHTML string is what makes the tab feel slow. Instead we render a small
   first chunk and append more as a sentinel scrolls into view, so the DOM stays
   small and the tab is interactive immediately. */
const CHUNK=60;
let _chunkIO=null, _findLoader=null;
function chunkRender(appendTarget, sentinelHost, items, itemHTML){
  if(_chunkIO){try{_chunkIO.disconnect();}catch(e){}_chunkIO=null;}
  let i=0;
  const sent=document.createElement('div');sent.style.height='1px';
  sentinelHost.appendChild(sent);
  function more(){
    const end=Math.min(i+CHUNK,items.length);let h='';
    for(;i<end;i++)h+=itemHTML(items[i],i);
    if(h)appendTarget.insertAdjacentHTML('beforeend',h);
    if(i>=items.length){try{io.disconnect();}catch(e){}if(sent.parentNode)sent.remove();}
  }
  const io=new IntersectionObserver(es=>{if(es.some(e=>e.isIntersecting))more();},{rootMargin:'1200px'});
  _chunkIO=io;io.observe(sent);
  more();                                   // first chunk, synchronously
  return function ensure(idx){while(i<=idx&&i<items.length)more();};
}
/* move the keyboard selection without rebuilding the whole list */
function moveSel(d){
  const list=window._flist||[];if(!list.length)return;
  selIdx=Math.max(0,Math.min(selIdx+d,list.length-1));
  if(_findLoader)_findLoader(selIdx);       // page in the target card if needed
  document.querySelectorAll('.card.sel').forEach(c=>c.classList.remove('sel'));
  const el=document.querySelector('.card[data-idx="'+selIdx+'"]');
  if(el){el.classList.add('sel');el.scrollIntoView({block:'nearest'});}
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

  const view=document.getElementById('view-findings');
  if(!list.length){view.innerHTML=h+'<div class="empty">No findings match the current filters.</div>';
    window._flist=[];_findLoader=null;return;}

  view.innerHTML=h+'<div id="flist"></div>';
  const flist=document.getElementById('flist');
  if(groupSimilar){
    const groups={};list.forEach(ev=>{const sig=ev.title+'|'+ev.priority+'|'+ev.module;(groups[sig]=groups[sig]||[]).push(ev);});
    const entries=Object.entries(groups).sort((a,b)=>(SEVR[b[1][0].priority]||0)-(SEVR[a[1][0].priority]||0)||b[1].length-a[1].length);
    window._flist=[];_findLoader=null;
    chunkRender(flist,view,entries,e=>groupHTML(e[0],e[1]));
  }else{
    window._flist=list;
    _findLoader=chunkRender(flist,view,list,(ev,i)=>cardHTML(ev,i));
  }
}

/* ---------------- ASSETS ---------------- */
let ASSETMAP={};   // id -> asset for the currently-rendered rows (detail built lazily)
function renderAssets(){
  flushNotes();
  ASSETMAP={};
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
  h+='<table><thead><tr><th></th><th>Type</th><th>Target</th><th>Module</th><th>Tags</th></tr></thead><tbody id="atbody"></tbody></table>';
  const view=document.getElementById('view-assets');
  view.innerHTML=h;
  const tb=document.getElementById('atbody');
  chunkRender(tb,view,rows,ev=>{ASSETMAP[ev.id]=ev;
    const tgt=ev.url||(ev.port?`${H(ev)}:${ev.port}`:H(ev))||ev.data_str;
    const star=(ev.juicy&&ev.juicy.length)?'<span class="star" title="'+esc(ev.juicy.join(', '))+'">&#9733;</span>':'';
    const nb=(COMPARE&&ev.is_new)?' <span class="newbadge">NEW</span>':'';
    // detail cell is left empty and filled on first expand (keeps big asset lists fast)
    return `<tr style="cursor:pointer" onclick="toggleAsset('${ev.id}')"><td>${star}</td><td>${esc(ev.type)}</td>`
      +`<td class="mono">${esc(tgt)}${nb}</td><td class="muted">${esc(ev.module||'-')}</td><td class="muted">${esc(ev.tags.join(', '))}</td></tr>`
      +`<tr id="ax-${ev.id}" style="display:none"><td></td><td colspan="4" class="axbody" style="background:var(--panel)"></td></tr>`;});
}

/* ---------------- URLS ----------------
   one deduped, copy-ready list of every URL BBOT touched, for pasting into
   feroxbuster/ffuf (--stdin / -u) or Burp's Target > Scope. */
let urlMode='full', urlVerified=false, urlScope=false, urlStatus='', URLLIST=[];
const URL_MODES=[['full','Full URLs','every URL, as found'],
                 ['base','Base URLs','scheme://host:port only - feroxbuster/ffuf targets'],
                 ['host','Hostnames','host only - Burp scope / resolvers']];
function urlOf(ev){
  if(ev.url)return ev.url;
  if(ev.type==='URL'||ev.type==='URL_UNVERIFIED'){const d=(ev.data_str||'').split(/\s/)[0];if(/^https?:\/\//i.test(d))return d;}
  return '';
}
function urlEvents(){return [...DATA.findings,...DATA.assets].filter(ev=>urlOf(ev));}
function urlShape(u){try{const p=new URL(u);
    return urlMode==='base'?p.protocol+'//'+p.host:urlMode==='host'?p.hostname:u;}catch(e){return urlMode==='full'?u:'';}}
function setUrlMode(m){urlMode=m;renderUrls();}
function toggleUrlVerified(){urlVerified=!urlVerified;renderUrls();}
function toggleUrlScope(){urlScope=!urlScope;renderUrls();}
function setUrlStatus(c){urlStatus=(urlStatus===c?'':c);renderUrls();}
function copyUrls(){const txt=URLLIST.join('\n');if(!txt)return toast('nothing to copy');
  const done=()=>toast('copied '+URLLIST.length+' lines');
  const fallback=()=>{const ta=document.getElementById('urlbox');if(!ta)return toast('copy failed');
    ta.focus();ta.select();try{document.execCommand('copy')?done():toast('copy failed');}catch(e){toast('copy failed');}};
  if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(txt).then(done,fallback);else fallback();}
function downloadUrls(){const txt=URLLIST.join('\n');if(!txt)return toast('nothing to download');
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([txt+'\n'],{type:'text/plain'}));
  a.download='bscope-'+urlMode+'.txt';document.body.appendChild(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href),2000);}
function renderUrls(){
  flushNotes();
  const all=urlEvents();
  const codes={};let anyScope=false,anyUnv=false;
  all.forEach(ev=>{(ev.tags||[]).forEach(t=>{const m=/^status-(\d{3})$/.exec(t);if(m)codes[m[1]]=(codes[m[1]]||0)+1;
    if(t==='in-scope')anyScope=true;});if(ev.type==='URL_UNVERIFIED'||ev.type==='URL_HINT')anyUnv=true;});
  let evs=all.filter(matchQ);
  if(urlVerified)evs=evs.filter(ev=>ev.type!=='URL_UNVERIFIED'&&ev.type!=='URL_HINT');
  if(urlScope)evs=evs.filter(ev=>(ev.tags||[]).includes('in-scope'));
  if(urlStatus)evs=evs.filter(ev=>(ev.tags||[]).includes('status-'+urlStatus));
  const seen=new Set();URLLIST=[];
  evs.forEach(ev=>{const v=urlShape(urlOf(ev));if(v&&!seen.has(v)){seen.add(v);URLLIST.push(v);}});
  URLLIST.sort();
  let h='<div class="bar">';
  URL_MODES.forEach(([k,l,t])=>h+=`<span class="chip ${urlMode===k?'on':''}" style="${urlMode===k?'background:var(--accent)':''}" title="${esc(t)}" onclick="setUrlMode('${k}')">${esc(l)}</span>`);
  h+='</div><div class="bar">';
  if(anyUnv)h+=`<span class="chip ${urlVerified?'on':''}" style="${urlVerified?'background:#38c172':''}" title="drop URL_UNVERIFIED (seen in a page/JS but never requested)" onclick="toggleUrlVerified()">verified only</span>`;
  if(anyScope)h+=`<span class="chip ${urlScope?'on':''}" style="${urlScope?'background:#38c172':''}" title="only events BBOT tagged in-scope" onclick="toggleUrlScope()">in-scope only</span>`;
  Object.keys(codes).sort().forEach(c=>h+=`<span class="chip ${urlStatus===c?'on':''}" style="${urlStatus===c?'background:#ffc93c':''}" onclick="setUrlStatus('${c}')">${c} <span class="muted">${codes[c]}</span></span>`);
  h+='</div><div class="bar">';
  h+=`<button class="btn" onclick="copyUrls()">&#128203; Copy all</button>`;
  h+=`<button class="btn" onclick="downloadUrls()">&#8681; Download .txt</button>`;
  h+=`<span class="muted">${URLLIST.length} unique &middot; ${evs.length} events &middot; search box filters this list</span></div>`;
  h+='<p class="hint">Paste into <code>feroxbuster --stdin</code> / <code>ffuf -u</code> (use Base URLs), or Burp &rarr; Target &rarr; Scope &rarr; Include (paste Hostnames or Base URLs). Ctrl-A in the box selects everything.</p>';
  h+=`<textarea class="urlbox" id="urlbox" readonly spellcheck="false">${esc(URLLIST.join('\n'))}</textarea>`;
  document.getElementById('view-urls').innerHTML=h;
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
  const vEl=document.getElementById('view-shots');
  if(!shotView.length){h+='<div class="empty">No screenshots matched.</div>';vEl.innerHTML=h;return;}
  vEl.innerHTML=h+'<div class="grid" id="shotgrid"></div>';
  chunkRender(document.getElementById('shotgrid'),vEl,shotView,(it,i)=>{
    const st=SHOTSMAP[it.status||'new']||SHOTST[0];
    const acc=(it.status&&it.status!=='new')?st.color:'var(--line)';
    const u=/^https?:\/\//i.test(it.label||'')?it.label:'';
    const head=u
      ? `<a class="shoturl" href="${esc(u)}" target="_blank" rel="noopener noreferrer" title="Open ${esc(u)} in a new tab" onclick="event.stopPropagation()">${esc(it.label)} <span class="ext">&#8599;</span></a>`
      : `<div class="shoturl nolink" title="${esc(it.label)}">${esc(it.label)}</div>`;
    return `<div class="shot" style="border-color:${acc}">
      ${head}
      <div class="thumb" onclick="openLb(${i})"><img loading="lazy" decoding="async" src="${it.src}"></div>
      <div class="m">
      <div class="sub">${esc(it.file)}${it.size?(' &middot; '+fmt(it.size)):''}</div>
      ${techChips(shotTechs(it))}
      <div class="shotbtns">${shotButtons(it)}</div></div></div>`;});
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
function assetDetailHTML(ev){
  const tgt=ev.url||(ev.port?`${H(ev)}:${ev.port}`:H(ev))||ev.data_str;
  let d='';
  if(ev.why)d+=`<div class="why">${esc(ev.why)}</div>`;
  d+=`<div class="tgt" onclick="${hx('copy('+JSON.stringify(tgt)+')')}" title="copy target">${esc(tgt)} &#128203;</div>`;
  if(ev.playbook&&ev.playbook.length){d+='<ul class="play">';ev.playbook.forEach(p=>d+=`<li>${esc(p)}</li>`);d+='</ul>';}
  if(ev.commands&&ev.commands.length)ev.commands.forEach(c=>d+=cmdHTML(c));
  return d;}
function toggleAsset(id){const r=document.getElementById('ax-'+id);if(!r)return;
  const cell=r.querySelector('.axbody');
  if(cell&&!cell.dataset.built&&ASSETMAP[id]){cell.innerHTML=assetDetailHTML(ASSETMAP[id]);cell.dataset.built='1';}
  r.style.display=(r.style.display==='none'?'':'none');}
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
    h+=`<span class="chip" onclick="setSearch('${t}')">${esc(t)} <span class="muted">${c}</span></span>`);
  h+='</div>';
  h+='<p class="muted" style="margin:-4px 0 10px">Every field BBOT captured for each event, after dedupe. Click a row to expand the full raw record.</p>';
  if(!list.length){h+='<div class="empty">No events matched.</div>';el.innerHTML=h;return;}
  h+='<table><thead><tr><th>Type</th><th>Target</th><th>Module</th><th>Tags</th></tr></thead><tbody id="mtbody"></tbody></table>';
  el.innerHTML=h;
  chunkRender(document.getElementById('mtbody'),el,list,(m,i)=>
    `<tr style="cursor:pointer" onclick="toggleMeta(${i})"><td>${esc(m.type)}</td>`
      +`<td class="mono">${esc(m.target||'')}</td><td class="muted">${esc(m.module||'-')}</td>`
      +`<td class="muted">${esc((m.tags||[]).join(', '))}</td></tr>`
      +`<tr id="mx-${i}" style="display:none"><td colspan="4" style="background:var(--panel)">`
      +`<pre class="rawjson">${esc(JSON.stringify(m.raw,null,2))}</pre></td></tr>`);
}

/* ---------------- EMAILS ---------------- */
function copyEmails(){copy((DATA.emails||[]).join('\n'));toast((DATA.emails||[]).length+' emails copied');}
function emailEnumCmds(d){
  // d is a domain; emails.txt is the exported address list (full user@dom lines).
  return [
    ['o365spray \u2014 user enum (oauth2)',
       `o365spray --enum -U emails.txt --domain ${d} --enum-module oauth2`],
    ['o365spray \u2014 user enum (onedrive, unauthenticated)',
       `o365spray --enum -U emails.txt --domain ${d} --enum-module onedrive`],
    ['onedrive_user_enum',
       `python3 onedrive_enum.py -d ${d} -U emails.txt`],
  ];
}
function emailCmdBlock(doms){
  let h='';
  const many=doms.length>6;
  const shown=many?['<domain>']:doms;
  h+='<p class="muted" style="margin:14px 0 4px">Ready-to-run user enumeration'
    +(many?(' (template \u2014 '+doms.length+' domains found; swap in each)'):'')+':</p>';
  shown.forEach(d=>{
    if(shown.length>1)h+=`<div class="muted" style="margin:8px 0 2px">&#9656; ${esc(d)}</div>`;
    emailEnumCmds(d).forEach(c=>{
      h+=`<div class="cmd"><code title="${esc(c[0])}">${esc(c[1])}</code>`
        +`<button class="copy" onclick="${hx('copy('+JSON.stringify(c[1])+')')}">copy</button></div>`;
    });
  });
  return h;
}
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
  h+='<p class="muted" style="margin:-4px 0 10px">Deduplicated addresses. Export the .txt and feed it into user-enumeration tools &mdash; o365spray (with <span class="kbd">--enum-module</span>), onedrive_user_enum, &hellip;</p>';
  const byDom={};all.forEach(e=>{const d=(e.split('@')[1]||'?');byDom[d]=(byDom[d]||0)+1;});
  h+='<div class="bar">';Object.entries(byDom).sort((a,b)=>b[1]-a[1]).forEach(([d,c])=>
    h+=`<span class="chip" onclick="setSearch('@${d}')">${esc(d)} <span class="muted">${c}</span></span>`);
  h+='</div>';
  h+=emailCmdBlock(Object.keys(byDom).filter(d=>d&&d!=='?').sort());
  if(!list.length){h+='<div class="empty">No emails matched.</div>';document.getElementById('view-emails').innerHTML=h;return;}
  h+='<table><thead><tr><th>#</th><th>Email</th><th>Domain</th></tr></thead><tbody>';
  list.forEach((e,i)=>{const dom=e.split('@')[1]||'';
    h+=`<tr><td class="muted">${i+1}</td><td class="mono" style="cursor:pointer" title="copy" onclick="${hx('copy('+JSON.stringify(e)+')')}">${esc(e)} &#128203;</td><td class="muted">${esc(dom)}</td></tr>`;});
  h+='</tbody></table>';
  document.getElementById('view-emails').innerHTML=h;
}

function rerender(){if(TAB==='findings')renderFindings();else if(TAB==='assets')renderAssets();else if(TAB==='hosts')renderHosts();else if(TAB==='emails')renderEmails();else if(TAB==='urls')renderUrls();else if(TAB==='shots')renderShots();else if(TAB==='meta')renderMeta();}

/* only surface a tab when the scan actually produced that kind of data, so an
   empty Emails / URLs / Screenshots / Findings / Assets tab is never shown. */
function tabHasData(tab){
  switch(tab){
    case 'overview': return true;
    case 'hosts':    return [...DATA.findings,...DATA.assets].some(ev=>H(ev));
    case 'findings': return DATA.findings.length>0;
    case 'assets':   return DATA.assets.length>0;
    case 'emails':   return (DATA.emails||[]).length>0;
    case 'urls':     return urlEvents().length>0;
    case 'shots':    return SHOTS.length>0;
    case 'meta':     return (DATA.findings.length+DATA.assets.length)>0;
    default:         return true;
  }
}
function applyTabVisibility(){
  document.querySelectorAll('.tab').forEach(b=>{
    b.style.display = tabHasData(b.dataset.tab) ? '' : 'none';});
  const em=document.querySelector('#exMenu a[href*="fmt=emails"]');
  if(em) em.style.display = (DATA.emails||[]).length ? '' : 'none';
}
function show(tab){selIdx=-1;
  if(!tabHasData(tab))tab='overview';
  TAB=tab;
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));
  ['overview','hosts','findings','assets','emails','urls','shots','meta'].forEach(t=>
    document.getElementById('view-'+t).style.display=(t===tab?'':'none'));
  if(tab==='overview')renderOverview();else if(tab==='hosts')renderHosts();
  else if(tab==='findings')renderFindings();else if(tab==='assets')renderAssets();
  else if(tab==='emails')renderEmails();
  else if(tab==='urls')renderUrls();
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
  if(e.key==='j'){moveSel(1);}
  else if(e.key==='k'){moveSel(-1);}
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
  applyTabVisibility();
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
    evidence_dir = ""
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
        headers = dict(extra or {})
        # gzip text/JSON payloads when the client accepts it and it's worth it.
        # Big wins on the one-shot /api/findings + /api/raw loads and the page
        # itself; binary (images, xlsx) is left untouched.
        if (self.command != "HEAD" and len(body) > 900
                and "gzip" in (self.headers.get("Accept-Encoding", "") or "").lower()
                and any(t in ctype for t in ("text/", "json", "javascript", "csv", "xml", "svg"))
                and "Content-Encoding" not in headers):
            try:
                body = gzip.compress(body, 5)
                headers["Content-Encoding"] = "gzip"
                headers["Vary"] = "Accept-Encoding"
            except Exception:
                pass
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---- client view of an event (+ live triage state) ----
    def _client_event(self, ev):
        d = {k: ev[k] for k in ("id", "type", "module", "tags", "data_str", "host",
                                "dhost", "url", "port", "scheme", "priority", "title", "why",
                                "playbook", "commands", "text", "lane", "juicy", "tech",
                                "remediation", "sources")}
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
            if fmt in ("attackforge", "nuclei", "af"):
                body = build_nuclei_export(self.events, self.store,
                                           getattr(self, "src_name", ""))
                return self._send(200, body, ctype="application/json; charset=utf-8",
                                  extra={"Content-Disposition": "attachment; filename=bscope-nuclei.json"})
            if fmt == "plextrac":
                body = build_plextrac_csv(self.events, self.store,
                                          getattr(self, "src_name", ""))
                return self._send(200, body, ctype="text/csv; charset=utf-8",
                                  extra={"Content-Disposition": "attachment; filename=bscope-plextrac.csv"})
            if fmt in ("report", "findings"):
                body = build_report_json(self.events, self.store,
                                         getattr(self, "src_name", ""))
                return self._send(200, body, ctype="application/json; charset=utf-8",
                                  extra={"Content-Disposition": "attachment; filename=bscope-findings.json"})
            if fmt in ("xlsx", "excel", "workbook"):
                body = build_xlsx(self.events, self.findings, self.assets, self.store,
                                  self.shots, getattr(self, "src_name", ""))
                return self._send(200, body,
                                  ctype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                  extra={"Content-Disposition": "attachment; filename=bscope-report.xlsx"})
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

        if path.startswith("/evidence/"):
            return self._serve_evidence(path[len("/evidence/"):])

        return self._send(404, "not found", ctype="text/plain; charset=utf-8")

    do_HEAD = do_GET

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path not in ("/api/triage", "/api/shot_triage",
                        "/api/evidence", "/api/evidence_delete"):
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

        if path == "/api/evidence":
            return self._save_evidence(body)
        if path == "/api/evidence_delete":
            return self._delete_evidence(body)

        fid = body.get("id")
        if not fid:
            return self._send(400, "missing id", ctype="text/plain; charset=utf-8")
        res = self.store.set(fid, status=body.get("status"), notes=body.get("notes"))
        return self._send(200, json.dumps(res), ctype="application/json; charset=utf-8")

    # ---- evidence screenshots pasted onto a finding ----
    _EV_EXT = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "image/gif": ".gif"}

    def _save_evidence(self, body):
        fid = (body.get("id") or "").strip()
        data = body.get("data") or ""      # data URL: data:image/png;base64,....
        if not fid or not re.match(r"^[0-9a-f]{6,16}$", fid):
            return self._send(400, "bad id", ctype="text/plain; charset=utf-8")
        m = re.match(r"^data:(image/(?:png|jpeg|webp|gif));base64,(.+)$", data, re.S)
        if not m:
            return self._send(400, "expected a base64 image data URL",
                              ctype="text/plain; charset=utf-8")
        ext = self._EV_EXT.get(m.group(1), ".png")
        try:
            raw = base64.b64decode(m.group(2), validate=True)
        except Exception:
            return self._send(400, "bad base64", ctype="text/plain; charset=utf-8")
        if len(raw) > 12 * 1024 * 1024:
            return self._send(413, "image too large (max 12MB)", ctype="text/plain; charset=utf-8")
        try:
            os.makedirs(self.evidence_dir, exist_ok=True)
            fname = "%s-%d%s" % (fid, int(time.time() * 1000), ext)
            with open(os.path.join(self.evidence_dir, fname), "wb") as f:
                f.write(raw)
        except OSError as e:
            return self._send(500, "could not save: %s" % e, ctype="text/plain; charset=utf-8")
        rec = self.store.add_evidence(fid, fname)
        return self._send(200, json.dumps({"evidence": rec.get("evidence", [])}),
                          ctype="application/json; charset=utf-8")

    def _delete_evidence(self, body):
        fid = (body.get("id") or "").strip()
        name = (body.get("name") or "").strip()
        # name must belong to this finding and carry no path separators
        if not fid or not name or "/" in name or "\\" in name or not name.startswith(fid + "-"):
            return self._send(400, "bad request", ctype="text/plain; charset=utf-8")
        try:
            fp = os.path.join(self.evidence_dir, name)
            if os.path.isfile(fp):
                os.remove(fp)
        except OSError:
            pass
        rec = self.store.remove_evidence(fid, name)
        return self._send(200, json.dumps({"evidence": rec.get("evidence", [])}),
                          ctype="application/json; charset=utf-8")

    def _serve_evidence(self, name_encoded):
        if not self.evidence_dir:
            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        name = urllib.parse.unquote(name_encoded)
        if "/" in name or "\\" in name or os.path.sep in name:
            return self._send(403, "forbidden", ctype="text/plain; charset=utf-8")
        full = os.path.realpath(os.path.join(self.evidence_dir, name))
        root_real = os.path.realpath(self.evidence_dir)
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
        self._send(200, data, ctype=ctype, extra={"Cache-Control": "max-age=60"})

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
    Handler.evidence_dir = state_path + ".evidence"
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