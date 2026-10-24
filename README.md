# External Recon Kit

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

- **BBOT 3.x** — `pipx install bbot`. Add API keys to `~/.config/bbot/secrets.yml` for far better discovery (see *API keys* below).
- **Python 3.7+** and, for `landlord.py`:
  ```bash
  pip install -r requirements.txt   # netaddr, requests, openpyxl
  ```
- **jq** — `recon.sh` uses it to parse BBOT output.
- `bscope.py` and `report.py` are standard-library only.

### Install

```bash
git clone <your-repo-url> recon-kit
cd recon-kit
pip install -r requirements.txt
chmod +x recon.sh landlord.py bscope.py report.py
```

Keep all the scripts in one folder; `recon.sh` finds the others on your `PATH`
or beside itself.

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
- `inscope_ips.txt` — every in-scope IP (with and without a hostname) → feed to Nessus / nmap
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

Discovery quality scales with how many free API keys BBOT has. Add them under
`modules:` in `~/.config/bbot/secrets.yml`:

```yaml
modules:
  virustotal:
    api_key: 'KEY'
  chaos:
    api_key: 'KEY'
  # ... otx, securitytrails, github_codesearch, censys_dns, certspotter, etc.
```

Free keys worth getting: VirusTotal, ProjectDiscovery Chaos, AlienVault OTX,
GitHub (a no-permission classic token), SecurityTrails, Censys, Cert Spotter (CT
Search API), LeakIX, BeVigil, FullHunt, BuiltWith, Hunter, Postman.

> `secrets.yml` holds credentials — `chmod 600` it and keep it out of version
> control. It's in `.gitignore` here already.

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
