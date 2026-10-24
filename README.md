# External Recon Kit

![Landlord — know who owns the address before you knock: discover, verify scope, active scan, triage, report](assets/landlord-workflow.png)

A BBOT-powered toolkit for external penetration testing — from "the client gave
me a few domains" to a triaged, client-ready findings report. It discovers the
full external attack surface, verifies scope against your authorization and the
cloud providers' ranges, runs a scoped active scan, and hands off clean lists to
triage, to other scanners (Nessus, nmap), and to the client.

> **Authorization first.** These tools find and actively test internet-facing
> assets. Only run them against systems you are explicitly authorized to test.
> Discovery is not authorization — anything new goes to the client for sign-off
> before you scan it.

---

## What's in the kit

| Tool | Language | What it does |
| --- | --- | --- |
| `recon.sh` | bash | The orchestrator. Runs the whole pipeline end to end. |
| `landlord.py` | python | Resolves hostnames and classifies each IP as in-scope, cloud (Azure/AWS/GCP), out of scope, or unresolved. Writes a client Excel report. |
| `bscope.py` | python | Local web dashboard for triaging BBOT findings (severity, status, notes), plus an assets view and a screenshot gallery. |
| `report.py` | python | Turns the findings you triaged in `bscope` into a client-ready HTML or Markdown report. |

---

## The pipeline

```
domains ─▶ 1. DISCOVER ─▶ 2. VERIFY SCOPE ─▶ 3. ACTIVE SCAN ─▶ 4. TRIAGE ─▶ 5. REPORT
            (BBOT,          (landlord.py)       (BBOT, scoped)    (bscope.py)   (report.py)
             passive)             │                   ▲
                                  └── in-scope only ──┘
```

1. **Discover** — BBOT enumerates subdomains passively from the seed domains. Touches nothing.
2. **Verify scope** — `landlord.py` resolves everything and sorts each host. Produces the client scope report and the "out of scope, please confirm" list.
3. **Active scan** — BBOT runs a loud scan (web, nuclei, ports, screenshots) **only** against hosts confirmed in scope, plus any in-scope IPs that have no hostname. Scope is enforced twice: by `landlord.py`'s classification and by BBOT's `--strict-scope`.
4. **Triage** — `bscope.py` serves a dashboard to mark findings confirmed / false positive / reported, with notes.
5. **Report** — `report.py` exports the triaged findings as a client report.

---

## Requirements

- **BBOT 3.x** — `pipx install bbot`. Add API keys to `~/.config/bbot/secrets.yml` for far better discovery; `free_secrets.example.yml` lists the free ones (see *API keys* below).
- **Python 3.7+** and, for `landlord.py`:
  ```bash
  pip install -r requirements.txt   # netaddr, requests, openpyxl
  ```
- **jq** — `recon.sh` uses it to parse BBOT output.
- `bscope.py` and `report.py` are standard-library only.

### Install

```bash
git clone https://github.com/TonyDAtigerr/Landlord.git
cd Landlord
pip install -r requirements.txt
chmod +x recon.sh landlord.py bscope.py report.py
```

Keep all the scripts in one folder; `recon.sh` finds the others on your `PATH`
or beside itself.

### Optional: API keys (recommended before your first run)

BBOT works with no keys at all, but discovery quality scales with how many
free API keys it has — the passive phase pulls from every service you give it
a key for. Set these up once, before your first engagement, and every run
benefits.

Add keys under `modules:` in `~/.config/bbot/secrets.yml`. If that file does
not exist, run `bbot --reset-secrets` to generate a fresh one, then edit it:

```yaml
modules:
  virustotal:
    api_key: 'KEY'
  chaos:
    api_key: 'KEY'
  otx:
    api_key: 'KEY'
  github_codesearch:
    api_key: 'KEY'   # the same token also serves github_usersearch and github_org
  # ... securitytrails, censys, leakix, bevigil, fullhunt, builtwith,
  #     hunterio, postman, certspotter, shodan_dns
```

**Free keys worth getting** (each requires a free account):

| Service | Sign up | Notes |
| --- | --- | --- |
| VirusTotal | <https://www.virustotal.com/> | Free public API |
| ProjectDiscovery Chaos | <https://chaos.projectdiscovery.io/> | Free key |
| AlienVault OTX | <https://otx.alienvault.com/> | Free key |
| GitHub | <https://github.com/settings/tokens> | A classic token with **no** permissions checked. One token covers `github_codesearch`, `github_usersearch`, and `github_org`. |
| SecurityTrails | <https://securitytrails.com/> | Free tier |
| Censys | <https://search.censys.io/> | Free tier |
| LeakIX | <https://leakix.net/> | Free key |
| BeVigil | <https://bevigil.com/osint-api> | Free tier |
| FullHunt | <https://fullhunt.io/> | Free tier |
| BuiltWith | <https://api.builtwith.com/> | Free tier |
| Hunter.io | <https://hunter.io/> | Free tier |
| Postman | <https://www.postman.com/> | Free account key |
| Certspotter (SSLMate CT Search API) | <https://sslmate.com/ct_search_api/> | Free tier |
| Shodan | <https://account.shodan.io/> | Free account key. **Bonus:** Shodan occasionally runs a one-time-fee lifetime Membership sale (historically around Black Friday and other holidays) — well worth grabbing if you see it. |

**Currently unavailable** (as of October 2026) — skip these, BBOT will simply
not use the module:

- **BufferOverrun** (`bufferoverrun` module) — the signup page returns
  "Too many API Keys defined for this account. Limit is 10000", which is
  BufferOverrun hitting its own provider's cap. No new keys are being issued.
- **SubdomainRadar** (`subdomainradar` module) — the site shows "This service
  is paused" and is not accepting scans, API requests, or new signups while it
  changes ownership.

> `secrets.yml` holds credentials — `chmod 600` it and keep it out of version
> control. It's in `.gitignore` here already.

---

## Quick start

```bash
# 1. Prepare two files
#    scope_ips.txt : authorized IPs, CIDRs or a-b ranges (one per line)
#    domains.txt   : the client's root domains (one per line)

# 2. Run the whole pipeline
./recon.sh -s scope_ips.txt -d domains.txt -c "Client Name" -a "Your Company"

# 3. Triage in the dashboard it launches (http://127.0.0.1:7373),
#    marking real issues Confirmed / Reported.

# 4. Generate the client report from your triage
python3 report.py recon_YYYYMMDD/03_active/active/output.json \
    --client "Client Name" --assessor "Your Company" -o client_report.html
```

`recon.sh` pauses once, before the active scan, and shows how many hosts it will
touch. Use `--passive-only` to stop after the scope report, or `-y` to skip the
pause.

---

## Finding the client's root domains

Everything starts from `domains.txt`. These become BBOT's seeds, so accuracy
beats size — a wrong domain pulls unrelated infrastructure into the scan. Work
the sources in this order, best first:

**1. Ask the client at kickoff.** Anything they hand you is authoritative; start there.

**2. Microsoft 365 tenant domains.** For each domain you already know, list the
others registered in the same tenant. This appends every tenant domain to
`domains.txt`, lowercased, sorted and deduplicated:

```bash
curl -s "https://azmap.dev/api/tenant?domain=example.com&extract=true" \
  | jq -r '.related_domains[]?' | tr 'A-Z' 'a-z' >> domains.txt \
  && sort -u -o domains.txt domains.txt && cat domains.txt
```

Already have a few confirmed domains in `domains.txt`? Expand all of them in
one go (the loop reads the file once before it starts appending):

```bash
for d in $(grep -v '^#' domains.txt); do
  curl -s "https://azmap.dev/api/tenant?domain=$d&extract=true" | jq -r '.related_domains[]?'
done | tr 'A-Z' 'a-z' >> domains.txt && sort -u -o domains.txt domains.txt && cat domains.txt
```

**3. Shared certificates.** Root domains that show up on certificates alongside a
known one. Certificates often carry CDN, hosting and certificate-provider names
too, so this one goes through a review file first instead of straight into
`domains.txt`. Step one writes the candidates, most common first:

```bash
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[].name_value' \
  | tr 'A-Z' 'a-z' | sed 's/^\*\.//' | grep -E '^[a-z0-9.-]+$' \
  | awk -F. 'NF >= 2 {print $(NF-1) "." $NF}' \
  | sort | uniq -c | sort -rn | tee crtsh_candidates.txt
```

Delete the lines you don't want from `crtsh_candidates.txt` (CDNs, cert
providers, anything that isn't the client), then step two appends the keepers
to `domains.txt`, deduplicated:

```bash
awk '{print $2}' crtsh_candidates.txt >> domains.txt \
  && sort -u -o domains.txt domains.txt && cat domains.txt
```

> Domains under a two-part public suffix (`client.co.uk`, `client.com.au`) come
> out as the bare suffix (`co.uk`). Add those by hand.

**4. Reverse WHOIS by registrant email.** Every domain registered with the same
address (needs a Whoxy API key in `$WHOXY_KEY`). Whoxy pages its results, so
this walks every page and appends the domains to `domains.txt`, lowercased,
sorted and deduplicated:

```bash
Q="https://api.whoxy.com/?key=$WHOXY_KEY&reverse=whois&email=domains@example.com"
for page in $(seq 1 "$(curl -s "$Q&page=1" | jq -r '.total_pages // 1')"); do
  curl -s "$Q&page=$page" | jq -r '.search_result[]?.domain_name'
done | tr 'A-Z' 'a-z' >> domains.txt && sort -u -o domains.txt domains.txt && cat domains.txt
```

**5. The client's own websites.** Footers, "our brands" pages, and privacy
policies often list sister domains.

**Verify before adding.** For anything that didn't come straight from the client,
look for at least two signs it's really theirs: shared name servers
(`dig +short NS <domain>`), shared mail (`dig +short MX <domain>`), it resolves
into their IP ranges, or it shares a certificate with a known domain. A large
corporate group can own domains that belong to separate businesses with their
own contracts, so when coverage is unclear, confirm with the client first.

Put the confirmed domains in `domains.txt` (one per line) and your authorized IP
ranges in `scope_ips.txt` (IPs, CIDRs, or `a-b` ranges, one per line). Then run
the pipeline as shown above.

---

## `recon.sh` options

Run `./recon.sh -h` for the built-in help. Full flag list:

| Flag | Argument | What it does |
| --- | --- | --- |
| `-s` | FILE | **Required.** Authorized scope: IPs, CIDRs, or `a-b` ranges, one per line. Used as both the landlord scope and BBOT's scope. |
| `-d` | FILE or DOMAIN | **Required, repeatable.** Seed domains: a file (one per line) or a literal domain. Mix files and domains freely. |
| `-o` | DIR | Output directory (default: `recon_<date>`). |
| `-c` | "Name" | Client name shown on the reports. |
| `-a` | "Name" | Assessor / your company name shown on the reports. |
| `--gcp` | | Also classify Google Cloud ranges in the scope report. |
| `--passive-only` | | Stop after discovery and the scope report. No active scan. |
| `--deep` | | Kitchen-sink active scan (see *Tuning the active scan* below). Loud and intrusive; authorized engagements only. |
| `--active-preset` | "P ..." | Override the active-scan BBOT presets entirely. |
| `--active-modules` | "M ..." | Override the active-scan BBOT modules entirely. |
| `--no-config-tuning` | | Don't apply the quieter/faster active-scan config (WAF avoidance, bounded spider, etc.). |
| `--dns-qps` | N | DNS queries/sec for brute forcing (default: 500). |
| `--no-serve` | | Do everything but don't launch the bscope dashboard; prints the command to launch it yourself. |
| `--bscope-port` | N | Port for the bscope dashboard (default: 7373). |
| `-y` | | Non-interactive: skip the pause before the active scan. |
| `-h` | | Show help. |

---

## Output files

Each run writes to an output folder (`recon_<date>` by default):

**For the client**
- `scope_report.xlsx` — full classification report with charts
- `out_of_scope_for_client.xlsx` — assets outside scope, with columns for the client to confirm ownership / authorize testing
- `out_of_scope_ips.txt` — the bare out-of-scope IPs

**For your scanners**
- `active_targets.txt` — one entry per in-scope host, deduplicated: the hostname if it has one, otherwise the bare IP (no overlap — an IP a hostname already resolves to is not repeated). This is the list the active scan uses, and the list to paste into Nessus / nmap.
- `inscope_ips.txt` — every in-scope IP (with and without a hostname)
- `inscope_hostnames.txt` — confirmed in-scope hostnames
- `inscope_ips_no_hostname.txt` — in-scope IPs no hostname points at (subset of the above)
- `open_ports.txt` — open ports BBOT confirmed, as `host:port`

**Raw / intermediate**
- `01_passive/`, `03_active/` — raw BBOT output (NDJSON + CSV)
- `all_hostnames.txt`, `scope_check.json` — intermediate data

---

## Using the tools on their own

Each tool works standalone; `recon.sh` just chains them.

```bash
# Scope-check an existing hostname list
landlord.py hostnames.txt scope.txt --xlsx report.xlsx --client "Client"

# Triage any BBOT output
bscope.py path/to/output.json --shots path/to/screenshots

# Report from a triaged scan
report.py path/to/output.json --client "Client" --format html
```

### report.py statuses

`report.py` reads the triage file `bscope` saves (`<output>.bscope.json`). By
default it includes only **confirmed**, **reviewed**, and **reported** findings,
so "new" noise never reaches the client. Override with `--include
confirmed,reported` or `--all` (everything except *new*).

---

## API keys (strongly recommended)

Discovery quality scales with how many API keys BBOT has, and most of the
services this kit relies on have a **free tier**. The option names BBOT expects
are in [`free_secrets.example.yml`](free_secrets.example.yml); the table below
adds a sign-up link for each:

| Service | Sign up | Notes |
| --- | --- | --- |
| VirusTotal | <https://www.virustotal.com/> | Free public API |
| ProjectDiscovery Chaos | <https://chaos.projectdiscovery.io/> | Free key |
| AlienVault OTX | <https://otx.alienvault.com/> | Free key |
| GitHub | <https://github.com/settings/tokens> | Classic token with **no** scopes; one token covers `github_codesearch`, `github_usersearch`, `github_org` |
| SecurityTrails | <https://securitytrails.com/> | Free tier |
| Censys | <https://search.censys.io/> | Free tier |
| LeakIX | <https://leakix.net/> | Free key |
| BeVigil | <https://bevigil.com/osint-api> | Free tier |
| FullHunt | <https://fullhunt.io/> | Free tier |
| BuiltWith | <https://api.builtwith.com/> | Free tier |
| hunter.io | <https://hunter.io/> | Free tier |
| Postman | <https://www.postman.com/> | Free account key |
| Trickest | <https://trickest.com/> | Free tier |
| Cert Spotter | <https://sslmate.com/ct_search_api/> | SSLMate CT Search API, free tier |
| GitLab | <https://gitlab.com/-/user_settings/personal_access_tokens> | Personal access token (`read_api`) |
| Shodan | <https://account.shodan.io/> | Free account key. Shodan occasionally runs a one-time-fee **lifetime Membership** sale (historically around holidays) — worth grabbing if you see it. |

Fill in your keys and install the file where BBOT reads it:

```bash
cp free_secrets.example.yml ~/.config/bbot/secrets.yml
chmod 600 ~/.config/bbot/secrets.yml
```

The values in the template are fakes and will not work until replaced.

**Have a paid API key?** [`full_secrets.example.yml`](full_secrets.example.yml)
is the same template with **every** secret option BBOT 3.x knows about: the
free keys above, the paid services (Shodan, DeHashed, BufferOverrun, c99,
IPStack, IP2Location, SubDomainRadar, Trajan tokens, ...), the output-module
credentials (Elastic, Neo4j, Splunk, Slack, Teams, ...), and the global
`bbot_io_api_key` / `interactsh_token`. Delete every entry you don't have a
real value for before using it. You can also have BBOT generate its own fully
commented version of that file:

```bash
bbot --reset-secrets   # regenerates ~/.config/bbot/secrets.yml, backs up the old one to .bak
```

Keys can also be passed on the command line for a one-off run:
`bbot -c modules.shodan_dns.api_key=KEY`.

> `secrets.yml` holds credentials. `chmod 600` it and keep it out of version
> control. It's in `.gitignore` here already; only the `*.example.yml` templates are
> committed.

**Currently unavailable** (as of October 2026) — skip these; BBOT will simply
not use the module:

- **BufferOverrun** (`bufferoverrun` module) — the signup page returns
  "Too many API Keys defined for this account. Limit is 10000", its provider
  hitting its own cap. No new keys are being issued.
- **SubdomainRadar** (`subdomainradar` module) — the site shows "This service
  is paused" and is not accepting scans, API requests, or new signups while it
  changes ownership.

---
## Tuning the active scan

The active scan has two built-in profiles, plus full manual control.

**Standard (default).** Solid coverage without the loudest modules:
presets `web-heavy nuclei web-screenshots`, modules `portscan fingerprintx baddns`.

```bash
./recon.sh -s scope_ips.txt -d domains.txt
```

**Deep (`--deep`).** The kitchen-sink profile. On top of the standard presets it
adds cloud-bucket enumeration, code/secret-leak enumeration, email enumeration,
web spidering, directory brute-force (`webbrute`), parameter mining
(`paramminer`), light fuzzing (`lightfuzz`), and all subdomain-takeover checks
(`baddns-heavy`). This is loud and intrusive.

```bash
./recon.sh -s scope_ips.txt -d domains.txt --deep
```

> `--deep`, `lightfuzz`, and `webbrute` are intrusive and can trip a WAF or SOC.
> Only use them when testing at that depth is explicitly authorized.

**Manual override.** Replace the presets and/or modules outright for either
profile with `--active-preset` and `--active-modules`:

```bash
# A lighter, quicker pass than the standard profile
./recon.sh -s scope_ips.txt -d domains.txt \
  --active-preset "web nuclei-budget web-screenshots" --active-modules "portscan"
```

---

## Safety & operating notes

### Cert Spotter is slow with an API key, and that's expected

Near the end of the passive scan you will likely see BBOT sit on one module for
a long time:

```
[INFO] passive: Modules running (incoming:processing:outgoing) certspotter(81:1:0)
[INFO] passive: No events in queue (0 processed in the past 15 seconds)
```

This is not a hang. With an SSLMate key configured, BBOT's `certspotter` module
changes behaviour:

- **Without a key** it makes one request per domain and takes whatever comes
  back in that single page.
- **With a key** it pages through the domain's *entire* certificate history,
  requesting the next page until Cert Spotter returns nothing. SSLMate
  throttles authenticated requests by subscription level; BBOT waits out each
  throttle and carries on.

So the key is working, and it is the reason the module is slow: it is pulling
the client's full certificate history rather than a sample. That is the result
you want from passive discovery.

The queue number (`81` above) is mostly subdomains found by other modules. The
module deduplicates to the highest parent domain, so nearly all of them are
dropped the moment they are picked up. The `1` is a single root domain being
paged through. You are waiting on a handful of lookups, not 81.

Your options, in order of preference:

1. **Let it finish.** Every other module is done by this point, and this is the
   thorough result.
2. **Remove the `certspotter` key** from `~/.config/bbot/secrets.yml`. The module
   drops back to one quick request per domain. Faster, less complete.
3. **Exclude the module** by editing the passive scan line in `recon.sh`
   (`-em viewdns certspotter`). Only sensible if the `crt` module is working,
   since that is BBOT's other certificate-transparency source and it fails
   often because crt.sh times out.

- **Keep the authorization paper trail** (signed scope / email) in the engagement folder.
- **Update nuclei templates** before each engagement: `nuclei -update-templates`.
- **Refresh cloud ranges** for a formal assessment: `landlord.py ... --refresh` (cached ~7 days otherwise).
- **Mind rate limits / WAFs.** The heavy presets are loud and can get your source IP blocked or trip a SOC. Throttle with `--dns-qps` and BBOT's web rate limits if asked.
- **Retention.** Output folders contain the client's full attack surface and findings — treat them as sensitive and dispose of them per your engagement's data-handling terms.

---

## Tested with

- BBOT 3.x
- Python 3.10+

BBOT's CLI changed significantly in 3.0; this kit assumes 3.x (e.g. `--strict-scope`, the `-t`/`-s` target/seed split).

---

## License

Released under the MIT License. See [`LICENSE`](LICENSE).
