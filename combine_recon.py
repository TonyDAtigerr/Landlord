#!/usr/bin/env python3
"""
combine_recon.py - merge ip2host, BBOT and other recon results into one file,
check every hostname against the authorized scope, and export a spreadsheet
a client can read.

Usage:
  python3 combine_recon.py -s scope_ips.txt \
      --ip2host ip2host_out --bbot bbot_seeded/output.json \
      -c "Client Name" -o recon_combined

  Every input option can be repeated, so later rounds can be added:
      --ip2host ip2host_out --ip2host ip2host_round2
      --bbot bbot_seeded/output.json --bbot bbot_round2/output.json
      --names subfinder.txt:subfinder --names amass.txt:amass

Outputs (prefix set with -o, default "recon_combined"):
  <prefix>.tsv                     every hostname: status, IPs, who found it
  <prefix>.xlsx                    client-readable report (skip with --no-xlsx)
  <prefix>_inscope_hostnames.txt   hostnames that resolve into scope
  <prefix>_new_inscope_ips.txt     in-scope IPs ip2host hasn't looked up yet
                                   (run ip2host on these for the next round)
  <prefix>_root_domains.txt        root domains of in-scope names (review,
                                   then use as BBOT seeds for the next round)

Statuses:
  In scope            resolves to at least one IP inside the scope file
  Needs confirmation  resolves, but only to IPs outside scope (NOT tested)
  Not resolving       doesn't resolve right now (historical / stale)
"""
import argparse
import datetime
import ipaddress
import json
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

HOSTNAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,62}\.)+[a-z][a-z0-9-]{1,62}$")

# BBOT labels that are mostly noise: "host" = a domain merely mentioned
# somewhere (links, email addresses); "viewdns" = automated reverse WHOIS.
NOISY_BBOT_MODULES = {"host", "viewdns"}

IP2HOST_SOURCES = {
    "shodan": "Shodan",
    "censys": "Censys",
    "virustotal": "Passive DNS (VirusTotal)",
    "ptr": "Reverse DNS",
    "tls": "TLS certificate",
    "smtp": "Mail server banner/certificate",
}
BBOT_MODULES = {
    "dnsbrute": "DNS brute force",
    "dnsbrute_mutations": "DNS brute force (name variations)",
    "crt": "Certificate transparency",
    "crt_db": "Certificate transparency",
    "certspotter": "Certificate transparency",
    "sslcert": "TLS certificate",
    "shodan_idb": "Shodan",
    "shodan_dns": "Shodan",
    "censys_dns": "Censys",
    "censys_ip": "Censys",
    "virustotal": "Passive DNS (VirusTotal)",
    "azure_tenant": "Microsoft 365 tenant",
    "viewdns": "Reverse WHOIS",
    "wayback": "Web archive",
    "CNAME": "DNS record (CNAME)",
    "PTR": "Reverse DNS",
}

# Provider domains: names under these are the client's cloud resources, but
# the root domain itself is never the client's, so it's not a BBOT seed.
CLOUD_ROOTS = {
    "azure.com", "trafficmanager.net", "openshift.com", "azurewebsites.net",
    "cloudapp.net", "windows.net", "azureedge.net", "azurefd.net",
    "azure-api.net", "amazonaws.com", "cloudfront.net", "awsglobalaccelerator.com",
    "elb.amazonaws.com", "herokuapp.com", "akamaiedge.net", "edgekey.net",
    "akamaized.net", "cloudflare.net", "fastly.net", "googleusercontent.com",
    "appspot.com", "sharepoint.com", "office.com", "outlook.com",
    "microsoft.com", "google.com", "github.io", "netlify.app", "vercel.app",
    "wpengine.com", "shopify.com", "hubspot.net", "zendesk.com",
}
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "com.br", "com.mx", "co.in", "co.za", "com.cn", "com.sg",
}

RESPONSES = ["Yes - ours, add to scope", "Yes - ours, keep out of scope",
             "Not ours", "Unsure"]


def warn(msg):
    print(msg, file=sys.stderr)


def clean_name(raw):
    n = raw.strip().lower().rstrip(".")
    if n.startswith("*."):
        n = n[2:]
    n = re.sub(r":\d+$", "", n)
    return n if HOSTNAME_RE.match(n) and not n.startswith("_wildcard.") else None


def root_domain(name):
    parts = name.split(".")
    last2 = ".".join(parts[-2:])
    if last2 in TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


# ---------------------------------------------------------------- scope
def load_scope(path):
    nets, entries = [], []
    for line in open(path):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            if "-" in line and "/" not in line:
                a, b = (ipaddress.ip_address(x.strip()) for x in line.split("-", 1))
                nets.extend(ipaddress.summarize_address_range(a, b))
                kind = "Range"
            else:
                net = ipaddress.ip_network(line, strict=False)
                nets.append(net)
                kind = "Single IP" if net.num_addresses == 1 else "Network (CIDR)"
            entries.append((line, kind))
        except ValueError:
            warn(f"[!] Skipping invalid scope entry: {line}")
    return nets, entries


def in_scope(ip, nets):
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def resolve(name):
    try:
        return name, sorted({ai[4][0] for ai in socket.getaddrinfo(name, None)})
    except OSError:
        return name, []


# ---------------------------------------------------------------- inputs
def add(names, name, tool, source):
    entry = names.setdefault(name, {"tools": set(), "sources": set()})
    entry["tools"].add(tool)
    entry["sources"].add(source)


def read_ip2host(folder, names, looked_up, ranges):
    map_file = os.path.join(folder, "map.tsv")
    if not os.path.isfile(map_file):
        warn(f"[!] {map_file} not found, skipping")
        return
    with open(map_file) as f:
        next(f, None)  # header
        for line in f:
            cols = line.rstrip("\n").split("\t")
            if len(cols) < 3:
                continue
            ip, host, sources = cols[0], cols[1], cols[2]
            looked_up.add(ip)
            name = clean_name(host) if host != "-" else None
            if not name:
                continue
            for s in sources.split(","):
                add(names, name, "ip2host", IP2HOST_SOURCES.get(s, s))

    cand = os.path.join(folder, "candidate_ranges.txt")
    if os.path.isfile(cand):
        label = None
        for line in open(cand):
            line = line.strip()
            if line.startswith("# AS"):
                label = "Announced by network " + line[2:].split(" - ")[0]
            elif line.startswith("# SPF for"):
                label = "Allowed to send email for " + line[10:].split(" - ")[0]
            elif line and not line.startswith("#") and label:
                ranges.setdefault(line, set()).add(label)


def read_bbot(path, names, keep_noisy):
    if not os.path.isfile(path):
        warn(f"[!] {path} not found, skipping")
        return
    skipped = 0
    for line in open(path):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("type") != "DNS_NAME":
            continue
        module = ev.get("module", "")
        if module in NOISY_BBOT_MODULES and not keep_noisy:
            skipped += 1
            continue
        name = clean_name(str(ev.get("data", "")))
        if name:
            add(names, name, "BBOT", BBOT_MODULES.get(module, f"BBOT ({module})"))
    if skipped:
        warn(f"[*] {path}: skipped {skipped} mentions/reverse-WHOIS names "
             f"(use --keep-noisy to include them)")


def read_names(spec, names):
    path, _, label = spec.partition(":")
    label = label or os.path.splitext(os.path.basename(path))[0]
    if not os.path.isfile(path):
        warn(f"[!] {path} not found, skipping")
        return
    for line in open(path):
        name = clean_name(line.split("\t")[0])
        if name:
            add(names, name, label, label)


# ---------------------------------------------------------------- xlsx
def write_xlsx(path, client, rows, ranges, scope_entries, tools_used):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.worksheet.datavalidation import DataValidation

    font = Font(name="Arial", size=10)
    bold = Font(name="Arial", size=10, bold=True)
    head_font = Font(name="Arial", size=10, bold=True, color="FFFFFF")
    wrap = Alignment(wrap_text=True, vertical="top")
    thin = Side(style="thin", color="BFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    fill_input = PatternFill("solid", fgColor="FFF2CC")
    colors = {"green": "2E7D32", "amber": "E69500", "blue": "1F4E79",
              "gray": "7F7F7F", "navy": "203864"}

    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"

    def table(ws, headers, data, color, widths, input_cols=()):
        ws.sheet_properties.tabColor = colors[color]
        for c, h in enumerate(headers, 1):
            cell = ws.cell(row=1, column=c, value=h)
            cell.font, cell.alignment, cell.border = head_font, wrap, border
            cell.fill = PatternFill("solid", fgColor=colors[color])
        for r, values in enumerate(data, 2):
            for c, v in enumerate(values, 1):
                cell = ws.cell(row=r, column=c, value=v)
                cell.font, cell.alignment, cell.border = font, wrap, border
            for c in input_cols:
                ws.cell(row=r, column=c).fill = fill_input
                ws.cell(row=r, column=c).border = border
        for c, w in enumerate(widths, 1):
            ws.column_dimensions[chr(64 + c)].width = w
        ws.freeze_panes = "A2"
        if data:
            ws.auto_filter.ref = f"A1:{chr(64 + len(headers))}{len(data) + 1}"
        if input_cols and data:
            dv = DataValidation(type="list", formula1='"' + ",".join(RESPONSES) + '"',
                                allow_blank=True)
            ws.add_data_validation(dv)
            col = chr(64 + input_cols[0])
            dv.add(f"{col}2:{col}{len(data) + 1}")

    inscope = [r for r in rows if r["status"] == "In scope"]
    confirm = [r for r in rows if r["status"] == "Needs confirmation"]
    stale = [r for r in rows if r["status"] == "Not resolving"]

    table(wb.create_sheet("In Scope"),
          ["Hostname", "In-scope IP address(es)", "Other IP address(es)", "How it was found"],
          [(r["name"], ", ".join(r["in_ips"]), ", ".join(r["out_ips"]), r["sources"])
           for r in inscope],
          "green", [42, 30, 30, 45])
    table(wb.create_sheet("Needs Confirmation"),
          ["Hostname", "IP address(es)", "How it was found", "Your response", "Notes"],
          [(r["name"], ", ".join(r["out_ips"]), r["sources"], None, None) for r in confirm],
          "amber", [42, 30, 40, 30, 35], input_cols=(4, 5))
    table(wb.create_sheet("Candidate Ranges"),
          ["IP range", "Why it's listed", "Your response", "Notes"],
          [(rng, "; ".join(sorted(why)), None, None) for rng, why in sorted(ranges.items())],
          "blue", [24, 55, 30, 35], input_cols=(3, 4))
    table(wb.create_sheet("Historical"),
          ["Hostname", "Where it was seen"],
          [(r["name"], r["sources"]) for r in stale],
          "gray", [45, 45])
    table(wb.create_sheet("Authorized Scope"),
          ["Scope entry", "Type"], scope_entries, "navy", [30, 20])

    # ---- Summary sheet
    ws = summary
    ws.sheet_properties.tabColor = colors["navy"]
    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 10
    ws.column_dimensions["C"].width = 60
    ws.column_dimensions["D"].width = 45
    ws["A1"] = f"{client} - External Asset Discovery" if client else "External Asset Discovery"
    ws["A1"].font = Font(name="Arial", size=14, bold=True)
    ws["A2"] = f"Generated {datetime.date.today():%B %d, %Y}. Sources: {', '.join(tools_used)}."
    ws["A2"].font = font

    ws["A4"] = ("Important: only the assets on the \"In Scope\" sheet are within the agreed "
                "scope. Everything on the other sheets was found through public sources and "
                "has NOT been tested. Finding an asset does not authorize testing it.")
    ws["A4"].font = bold
    ws["A4"].alignment = wrap
    ws.merge_cells("A4:D4")
    ws.row_dimensions[4].height = 45

    heads = ["Sheet", "Count", "What it means", "What we need from you"]
    for c, h in enumerate(heads, 1):
        cell = ws.cell(row=6, column=c, value=h)
        cell.font, cell.border = head_font, border
        cell.fill = PatternFill("solid", fgColor=colors["navy"])
    lines = [
        ("In Scope", "green",
         "Hostnames that point to IP addresses inside the agreed scope.",
         "Nothing. These are included in testing."),
        ("Needs Confirmation", "amber",
         "Hostnames that appear related to your organization but point to IP addresses "
         "outside the agreed scope. Often cloud or third-party hosted services.",
         "Fill in the yellow \"Your response\" column for each row."),
        ("Candidate Ranges", "blue",
         "IP ranges announced by your network (ASN) or listed in your email (SPF) "
         "records. Parts of a range may already be in scope; the rest has not been tested.",
         "Fill in the yellow \"Your response\" column for each row."),
        ("Historical", "gray",
         "Hostnames that pointed at your IP addresses in the past but no longer resolve.",
         "Nothing required. Consider cleaning up old DNS records."),
    ]
    for r, (sheet, color, meaning, action) in enumerate(lines, 7):
        ws.cell(row=r, column=1, value=sheet).font = Font(name="Arial", size=10, bold=True,
                                                          color=colors[color])
        ws.cell(row=r, column=2, value=f"=COUNTA('{sheet}'!A:A)-1").font = font
        ws.cell(row=r, column=3, value=meaning).font = font
        ws.cell(row=r, column=4, value=action).font = font
        for c in range(1, 5):
            ws.cell(row=r, column=c).alignment = wrap
            ws.cell(row=r, column=c).border = border
        ws.row_dimensions[r].height = 42
    ws.cell(row=11, column=1, value="Authorized scope entries").font = font
    ws.cell(row=11, column=2, value="=COUNTA('Authorized Scope'!A:A)-1").font = font

    ws["A13"] = "How to respond"
    ws["A13"].font = bold
    ws["A14"] = ("Yellow cells are for you to fill in. Choose a response from the dropdown "
                 "and add any notes. Example: \"Yes - ours, add to scope\" with the note "
                 "\"Staging site, hosted in our Azure tenant\".")
    ws["A14"].font = font
    ws["A14"].alignment = wrap
    ws.merge_cells("A14:D14")
    ws.row_dimensions[14].height = 32
    ws["A15"] = "Response options: " + "; ".join(RESPONSES) + "."
    ws["A15"].font = font
    ws["A15"].alignment = wrap
    ws.merge_cells("A15:D15")

    wb.save(path)


# ---------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-s", "--scope", required=True, help="authorized scope file")
    p.add_argument("--ip2host", action="append", default=[], metavar="DIR",
                   help="ip2host output folder (repeatable)")
    p.add_argument("--bbot", action="append", default=[], metavar="JSON",
                   help="BBOT output.json (repeatable)")
    p.add_argument("--names", action="append", default=[], metavar="FILE[:LABEL]",
                   help="any other hostname list, e.g. subfinder.txt:subfinder (repeatable)")
    p.add_argument("-c", "--client", default="", help="client name for the report title")
    p.add_argument("-o", "--out", default="recon_combined", help="output file prefix")
    p.add_argument("--keep-noisy", action="store_true",
                   help="keep BBOT mentions and automated reverse WHOIS results")
    p.add_argument("--no-xlsx", action="store_true", help="skip the spreadsheet")
    args = p.parse_args()

    if not (args.ip2host or args.bbot or args.names):
        p.error("give at least one --ip2host, --bbot or --names input")

    nets, scope_entries = load_scope(args.scope)
    names, looked_up, ranges = {}, set(), {}
    for d in args.ip2host:
        read_ip2host(d, names, looked_up, ranges)
    for j in args.bbot:
        read_bbot(j, names, args.keep_noisy)
    for n in args.names:
        read_names(n, names)
    if not names:
        sys.exit("[!] No hostnames found in the inputs.")

    warn(f"[*] Resolving {len(names)} hostnames...")
    with ThreadPoolExecutor(30) as ex:
        resolved = dict(ex.map(resolve, sorted(names)))

    rows = []
    for name in sorted(names):
        ips = resolved.get(name, [])
        in_ips = [i for i in ips if in_scope(i, nets)]
        out_ips = [i for i in ips if i not in in_ips]
        status = ("In scope" if in_ips else "Needs confirmation" if ips else "Not resolving")
        rows.append({
            "name": name, "status": status, "in_ips": in_ips, "out_ips": out_ips,
            "found_by": " + ".join(sorted(names[name]["tools"])),
            "sources": ", ".join(sorted(names[name]["sources"])),
        })

    # ---- combined TSV
    with open(f"{args.out}.tsv", "w") as f:
        f.write("hostname\tstatus\tin_scope_ips\tother_ips\tfound_by\tsources\n")
        for r in rows:
            f.write("\t".join([r["name"], r["status"], ",".join(r["in_ips"]),
                               ",".join(r["out_ips"]), r["found_by"], r["sources"]]) + "\n")

    inscope = [r for r in rows if r["status"] == "In scope"]
    with open(f"{args.out}_inscope_hostnames.txt", "w") as f:
        f.writelines(r["name"] + "\n" for r in inscope)

    new_ips = sorted({ip for r in inscope for ip in r["in_ips"]} - looked_up,
                     key=lambda x: (":" in x, x))
    with open(f"{args.out}_new_inscope_ips.txt", "w") as f:
        f.writelines(ip + "\n" for ip in new_ips)

    roots = sorted({root_domain(r["name"]) for r in inscope} - CLOUD_ROOTS)
    with open(f"{args.out}_root_domains.txt", "w") as f:
        f.writelines(d + "\n" for d in roots)

    tools_used = sorted({t for v in names.values() for t in v["tools"]})
    if not args.no_xlsx:
        try:
            write_xlsx(f"{args.out}.xlsx", args.client, rows, ranges, scope_entries, tools_used)
        except ImportError:
            warn("[!] openpyxl isn't installed, so no spreadsheet was made. "
                 "Install it with: pip install openpyxl")

    # ---- summary
    count = {s: sum(1 for r in rows if r["status"] == s)
             for s in ("In scope", "Needs confirmation", "Not resolving")}
    warn("")
    warn(f"[+] {len(rows)} unique hostnames from: {', '.join(tools_used)}")
    warn(f"    In scope:           {count['In scope']}")
    warn(f"    Needs confirmation: {count['Needs confirmation']}")
    warn(f"    Not resolving:      {count['Not resolving']}")
    warn(f"    Candidate ranges:   {len(ranges)}")
    warn("")
    warn(f"[+] Wrote {args.out}.tsv" + ("" if args.no_xlsx else f" and {args.out}.xlsx"))
    if new_ips:
        warn(f"[!] {len(new_ips)} in-scope IP(s) haven't been through ip2host yet.")
        warn(f"    Next round: ./ip2host.sh -s {args.scope} -o ip2host_round2 "
             f"{args.out}_new_inscope_ips.txt")
    else:
        warn("[+] Every in-scope IP has been through ip2host.")
    warn(f"[*] Review {args.out}_root_domains.txt for new BBOT seeds.")


if __name__ == "__main__":
    main()
