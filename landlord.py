#!/usr/bin/env python3
"""
landlord - find out who owns the building before you knock.

Resolves hostnames and classifies each address as in the agreed scope, inside
a cloud provider's published ranges (Azure / AWS / GCP), out of scope, or
unresolved. Optionally exports a client-ready Excel workbook.

usage: landlord hostnames.txt scope.txt [options]

Scope file accepts CIDRs, single IPs, ranges (a.b.c.d-a.b.c.e), hostnames,
blank lines and '#' comments.
"""
__version__ = "1.0.0"

import argparse
import csv
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests
from netaddr import IPAddress, IPNetwork, IPRange, IPSet, AddrFormatError

CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "landlord"
CACHE_TTL = 7 * 24 * 3600  # Azure updates weekly; AWS/GCP more often but this is fine

AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
AZURE_PAGES = {
    "public": ("https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519", "ServiceTags_Public"),
    "gov": ("https://www.microsoft.com/en-us/download/confirmation.aspx?id=57063", "ServiceTags_AzureGovernment"),
}
POLICY = {
    "azure": "https://learn.microsoft.com/en-us/azure/security/fundamentals/pen-testing",
    "aws": "https://aws.amazon.com/security/penetration-testing/",
    "gcp": "https://cloud.google.com/terms/aup",
}


# --------------------------------------------------------------------------- #
# Fetching / caching
# --------------------------------------------------------------------------- #
def cached_get(name, url, ttl=CACHE_TTL, refresh=False, headers=None):
    """GET url, caching the body on disk under CACHE_DIR/name."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / name
    if path.exists() and not refresh and time.time() - path.stat().st_mtime < ttl:
        return path.read_text()
    resp = requests.get(url, timeout=30, headers=headers or {"User-Agent": "Mozilla/5.0"})
    resp.raise_for_status()
    path.write_text(resp.text)
    return resp.text


def find_azure_json_url(cloud):
    """Scrape Microsoft's download confirmation page for the current ServiceTags JSON URL."""
    page_url, prefix = AZURE_PAGES[cloud]
    html = requests.get(page_url, timeout=30, headers={"User-Agent": "Mozilla/5.0"}).text
    m = re.search(r'https://download\.microsoft\.com/download/[^"\']+/%s_\d{8}\.json' % prefix, html)
    if not m:
        raise RuntimeError("could not find %s JSON link on %s" % (prefix, page_url))
    return m.group(0)


# --------------------------------------------------------------------------- #
# Range loaders - each returns a list of (IPNetwork, label)
# --------------------------------------------------------------------------- #
def load_azure(cloud="public", local_file=None, refresh=False):
    if local_file:
        data = json.loads(Path(local_file).read_text())
    else:
        url = find_azure_json_url(cloud)
        data = json.loads(cached_get("azure_%s.json" % cloud, url, refresh=refresh))
    out = []
    for obj in data.get("values", []):
        props = obj.get("properties", {})
        label = props.get("systemService") or obj.get("name", "")
        region = props.get("region") or ""
        tag = "%s/%s" % (label, region) if region else label
        for cidr in props.get("addressPrefixes", []):
            out.append((IPNetwork(cidr), tag))
    return out


def load_aws(refresh=False):
    data = json.loads(cached_get("aws.json", AWS_URL, refresh=refresh))
    out = []
    for obj in data.get("prefixes", []):
        out.append((IPNetwork(obj["ip_prefix"]), "%s/%s" % (obj["service"], obj["region"])))
    for obj in data.get("ipv6_prefixes", []):
        out.append((IPNetwork(obj["ipv6_prefix"]), "%s/%s" % (obj["service"], obj["region"])))
    return out


def load_gcp(refresh=False):
    data = json.loads(cached_get("gcp.json", GCP_URL, refresh=refresh))
    out = []
    for obj in data.get("prefixes", []):
        cidr = obj.get("ipv4Prefix") or obj.get("ipv6Prefix")
        out.append((IPNetwork(cidr), "%s/%s" % (obj.get("service", ""), obj.get("scope", ""))))
    return out


def parse_scope_line(line):
    """Return a list of IPNetwork objects for one scope-file line."""
    line = line.split("#", 1)[0].strip()
    if not line:
        return []
    try:
        if "-" in line and "/" not in line:
            a, b = (x.strip() for x in line.split("-", 1))
            return list(IPRange(a, b).cidrs())
        return [IPNetwork(line)]
    except (AddrFormatError, ValueError):
        pass
    # Not an IP/CIDR - treat as hostname and resolve every address
    nets = [IPNetwork(ip) for ip in resolve(line)[1]]
    if not nets:
        print("WARNING: scope entry %r did not parse or resolve, skipping" % line, file=sys.stderr)
    return nets


def load_scope(path):
    out = []
    for line in Path(path).read_text().splitlines():
        for net in parse_scope_line(line):
            out.append((net, line.strip()))
    return out


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
class RangeIndex:
    """Fast membership via a merged IPSet; label lookup only on a hit."""

    def __init__(self, name, entries):
        self.name = name
        self.entries = entries
        self.ipset = IPSet(net for net, _ in entries)

    def match(self, ip):
        ip = IPAddress(ip)
        if ip not in self.ipset:
            return None
        for net, label in self.entries:
            if ip in net:
                return label
        return "?"


def resolve(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = sorted({i[4][0] for i in infos})
        return hostname, ips
    except socket.gaierror:
        return hostname, []


# --------------------------------------------------------------------------- #
# Client-facing Excel export
# --------------------------------------------------------------------------- #
CATEGORY_LABELS = {
    "scope": "In agreed scope",
    "azure": "Azure (Public)",
    "azure-gov": "Azure (Government)",
    "aws": "AWS",
    "gcp": "Google Cloud",
    "out": "Out of scope",
    "unresolved": "Did not resolve",
}
CATEGORY_COLORS = {
    "scope": "2E7D32", "azure": "0078D4", "azure-gov": "004578", "aws": "FF9900",
    "gcp": "DB4437", "out": "C62828", "unresolved": "757575",
}

# Plain in-scope verdict per category, for the "In Scope" report column. Cloud
# categories are deliberately "Review (cloud)" rather than Yes/No: the host
# resolves into a provider's published ranges but is not in the agreed IP scope,
# so ownership and the provider's testing authorisation must be confirmed first.
SCOPE_STATUS = {
    "scope": "Yes",
    "out": "No",
    "aws": "Review (cloud)",
    "azure": "Review (cloud)",
    "azure-gov": "Review (cloud)",
    "gcp": "Review (cloud)",
    "unresolved": "Unresolved",
}
SCOPE_STATUS_COLORS = {
    "Yes": "2E7D32",             # green
    "No": "C62828",              # red
    "Review (cloud)": "F9A825",  # amber
    "Unresolved": "757575",      # grey
}


def export_xlsx(path, results, unresolved, client=None, assessor=None):
    """Write a client-ready workbook: Hosts, Summary (with charts), Cloud Services."""
    try:
        from openpyxl import Workbook
        from openpyxl.chart import BarChart, PieChart, Reference
        from openpyxl.chart.label import DataLabelList
        from openpyxl.chart.series import DataPoint
        from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
        from openpyxl.utils import get_column_letter
        from openpyxl.worksheet.table import Table, TableStyleInfo
    except ImportError:
        sys.exit("--xlsx requires openpyxl: pip install openpyxl")

    FONT = "Arial"
    hdr_font = Font(name=FONT, bold=True, color="FFFFFF")
    hdr_fill = PatternFill("solid", fgColor="1F3864")
    body = Font(name=FONT)
    bold = Font(name=FONT, bold=True)
    title = Font(name=FONT, bold=True, size=16)
    thin = Side(style="thin", color="BFBFBF")
    box = Border(left=thin, right=thin, top=thin, bottom=thin)
    cats = [c for c in CATEGORY_LABELS if any(r["category"] == c for r in results)]
    if unresolved:
        cats.append("unresolved")

    def header(ws, row, cols):
        for i, c in enumerate(cols, 1):
            cell = ws.cell(row=row, column=i, value=c)
            cell.font, cell.fill, cell.border = hdr_font, hdr_fill, box
            cell.alignment = Alignment(horizontal="center")

    def autosize(ws, widths):
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w

    wb = Workbook()

    # ---- Hosts sheet ---------------------------------------------------------
    ws = wb.active
    ws.title = "Hosts"
    cols = ["Hostname", "IP Address", "IP Version", "Classification", "In Scope", "Provider / Service", "Notes"]
    header(ws, 1, cols)
    rows = sorted(results, key=lambda r: (cats.index(r["category"]), r["host"], r["ip"]))
    r_i = 2
    for r in rows:
        st = SCOPE_STATUS.get(r["category"], "Review (cloud)")
        vals = [r["host"], r["ip"], "IPv6" if ":" in r["ip"] else "IPv4",
                CATEGORY_LABELS[r["category"]], st,
                r["match"] if r["category"] != "scope" else "", ""]
        for c_i, v in enumerate(vals, 1):
            cell = ws.cell(row=r_i, column=c_i, value=v)
            cell.font, cell.border = body, box
        ws.cell(row=r_i, column=4).fill = PatternFill("solid", fgColor=CATEGORY_COLORS[r["category"]])
        ws.cell(row=r_i, column=4).font = Font(name=FONT, color="FFFFFF", bold=True)
        ws.cell(row=r_i, column=5).fill = PatternFill("solid", fgColor=SCOPE_STATUS_COLORS[st])
        ws.cell(row=r_i, column=5).font = Font(name=FONT, color="FFFFFF", bold=True)
        r_i += 1
    for h in unresolved:
        vals = [h, "", "", CATEGORY_LABELS["unresolved"], SCOPE_STATUS["unresolved"], "",
                "No DNS record found at time of assessment"]
        for c_i, v in enumerate(vals, 1):
            cell = ws.cell(row=r_i, column=c_i, value=v)
            cell.font, cell.border = body, box
        ws.cell(row=r_i, column=4).fill = PatternFill("solid", fgColor=CATEGORY_COLORS["unresolved"])
        ws.cell(row=r_i, column=4).font = Font(name=FONT, color="FFFFFF", bold=True)
        ws.cell(row=r_i, column=5).fill = PatternFill("solid", fgColor=SCOPE_STATUS_COLORS["Unresolved"])
        ws.cell(row=r_i, column=5).font = Font(name=FONT, color="FFFFFF", bold=True)
        r_i += 1
    last = r_i - 1
    if last >= 2:
        tbl = Table(displayName="Hosts", ref="A1:G%d" % last)
        tbl.tableStyleInfo = TableStyleInfo(name="TableStyleLight1", showRowStripes=True)
        ws.add_table(tbl)
    ws.freeze_panes = "A2"
    autosize(ws, [42, 40, 11, 22, 16, 38, 45])

    # ---- Summary sheet (counts are live formulas over the Hosts sheet) ---------
    ss = wb.create_sheet("Summary", 0)
    ss["A1"] = "External Infrastructure Overview"
    ss["A1"].font = title
    ss["A2"] = "Client: %s" % (client or "")
    ss["A3"] = "Prepared by: %s" % (assessor or "")
    ss["A4"] = "Generated: %s" % time.strftime("%Y-%m-%d")
    for c in ("A2", "A3", "A4"):
        ss[c].font = body

    header(ss, 6, ["Classification", "Hosts", "Share"])
    first = 7
    for i, cat in enumerate(cats):
        row = first + i
        ss.cell(row=row, column=1, value=CATEGORY_LABELS[cat]).font = body
        ss.cell(row=row, column=2, value='=COUNTIF(Hosts!$D:$D,A%d)' % row).font = body
        ss.cell(row=row, column=3, value='=IF($B$%d=0,0,B%d/$B$%d)' % (first + len(cats), row, first + len(cats))).font = body
        ss.cell(row=row, column=3).number_format = "0.0%"
        ss.cell(row=row, column=1).fill = PatternFill("solid", fgColor=CATEGORY_COLORS[cat])
        ss.cell(row=row, column=1).font = Font(name=FONT, color="FFFFFF", bold=True)
        for c in range(1, 4):
            ss.cell(row=row, column=c).border = box
    total_row = first + len(cats)
    ss.cell(row=total_row, column=1, value="Total").font = bold
    ss.cell(row=total_row, column=2, value="=SUM(B%d:B%d)" % (first, total_row - 1)).font = bold
    ss.cell(row=total_row, column=3, value="=IF(B%d=0,0,1)" % total_row).number_format = "0.0%"
    for c in range(1, 4):
        ss.cell(row=total_row, column=c).border = box
    autosize(ss, [26, 10, 10])

    # Pie chart: classification breakdown, coloured to match the table
    pie = PieChart()
    pie.title = "Hosts by classification"
    pie.add_data(Reference(ss, min_col=2, min_row=6, max_row=total_row - 1), titles_from_data=True)
    pie.set_categories(Reference(ss, min_col=1, min_row=first, max_row=total_row - 1))
    pie.height, pie.width = 9, 14
    for i, cat in enumerate(cats):
        pt = DataPoint(idx=i)
        pt.graphicalProperties.solidFill = CATEGORY_COLORS[cat]
        pie.series[0].dPt.append(pt)
    pie.dataLabels = DataLabelList()
    pie.dataLabels.showPercent = True
    pie.dataLabels.showVal = pie.dataLabels.showCatName = pie.dataLabels.showSerName = False
    pie.dataLabels.showLeaderLines = False
    ss.add_chart(pie, "E2")

    # ---- Cloud Services sheet + bar chart --------------------------------------
    svc_counts = {}
    for r in results:
        if r["category"] not in ("scope", "out"):
            key = (CATEGORY_LABELS[r["category"]], r["match"].split("/")[0] or "(unlabelled)")
            svc_counts[key] = svc_counts.get(key, 0) + 1
    cs = wb.create_sheet("Cloud Services")
    header(cs, 1, ["Provider", "Service", "Hosts"])
    svc_rows = sorted(svc_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    for i, ((prov, svc), n) in enumerate(svc_rows, 2):
        # Count via formula so it stays live if the client edits the Hosts tab
        cs.cell(row=i, column=1, value=prov).font = body
        cs.cell(row=i, column=2, value=svc).font = body
        cs.cell(row=i, column=3,
                value='=COUNTIFS(Hosts!$D:$D,A%d,Hosts!$F:$F,B%d&"*")' % (i, i)).font = body
        for c in range(1, 4):
            cs.cell(row=i, column=c).border = box
    autosize(cs, [22, 30, 10])
    if svc_rows:
        top = min(len(svc_rows), 15)

        def service_bar():  # a chart object can only live on one sheet, so build one per sheet
            bar = BarChart()
            bar.type = "bar"
            bar.title = "Hosts by cloud service (top %d)" % top
            bar.add_data(Reference(cs, min_col=3, min_row=1, max_row=top + 1), titles_from_data=True)
            bar.set_categories(Reference(cs, min_col=2, min_row=2, max_row=top + 1))
            bar.legend = None
            bar.height, bar.width = max(7, top * 0.6), 16
            return bar

        cs.add_chart(service_bar(), "E2")
        ss.add_chart(service_bar(), "E22")

    # ---- Methodology / legend ----------------------------------------------------
    ms = wb.create_sheet("Methodology")
    notes = [
        ("How to read this workbook", bold),
        ("Summary: counts per classification with charts. Counts are formulas over the Hosts tab.", body),
        ("Hosts: every hostname with each resolved IP address and its classification.", body),
        ("Cloud Services: hosts grouped by the cloud provider service their IP belongs to.", body),
        ("", body),
        ("Classifications", bold),
        ("In agreed scope: IP falls within a range in the agreed scope document.", body),
        ("Azure / AWS / Google Cloud: IP is in the provider's published address ranges "
         "(not in the agreed scope). Testing may be covered by the provider's blanket policy.", body),
        ("Out of scope: IP is in none of the above; it may be a third party, a CDN, or on-prem.", body),
        ("Did not resolve: no DNS record existed when the data was collected.", body),
        ("", body),
        ("In Scope column", bold),
        ("Yes: the host is within the agreed scope. No: out of scope. "
         "Review (cloud): the IP is in a cloud provider's ranges and not in the agreed IP "
         "scope - confirm asset ownership and obtain the provider's testing authorisation "
         "before any active testing. Unresolved: no DNS record at collection time.", body),
        ("", body),
        ("Sources", bold),
        ("Azure ranges: %s" % AZURE_PAGES["public"][0], body),
        ("AWS ranges: %s" % AWS_URL, body),
        ("GCP ranges: %s" % GCP_URL, body),
        ("Provider policies: Azure %s | AWS %s | GCP %s" % (POLICY["azure"], POLICY["aws"], POLICY["gcp"]), body),
    ]
    for i, (text, font) in enumerate(notes, 1):
        ms.cell(row=i, column=1, value=text).font = font
    ms.column_dimensions["A"].width = 120

    wb.save(path)


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(prog="landlord", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="landlord " + __version__)
    ap.add_argument("hostnames", help="file with one hostname (or IP) per line")
    ap.add_argument("scope", help="scope file: CIDRs, IPs, ranges, hostnames")
    ap.add_argument("--azure-cloud", choices=["public", "gov", "both", "none"], default="public")
    ap.add_argument("--azure-file", help="use a locally downloaded ServiceTags JSON instead of fetching")
    ap.add_argument("--no-aws", action="store_true")
    ap.add_argument("--gcp", action="store_true", help="also check Google Cloud ranges")
    ap.add_argument("--refresh", action="store_true", help="ignore cached provider range files")
    ap.add_argument("-t", "--threads", type=int, default=20, help="concurrent DNS lookups")
    ap.add_argument("--json", metavar="FILE", help="write results as JSON")
    ap.add_argument("--csv", metavar="FILE", help="write results as CSV")
    ap.add_argument("--xlsx", metavar="FILE", help="write a client-ready Excel workbook (Summary with charts, Hosts, Cloud Services)")
    ap.add_argument("--client", help="client name shown on the Summary tab")
    ap.add_argument("--assessor", help="assessor / company name shown on the Summary tab")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress console report")
    args = ap.parse_args()

    # Build range indexes ----------------------------------------------------
    indexes = [RangeIndex("scope", load_scope(args.scope))]
    try:
        if args.azure_file:
            indexes.append(RangeIndex("azure", load_azure(local_file=args.azure_file)))
        elif args.azure_cloud in ("public", "both"):
            indexes.append(RangeIndex("azure", load_azure("public", refresh=args.refresh)))
        if args.azure_cloud in ("gov", "both") and not args.azure_file:
            indexes.append(RangeIndex("azure-gov", load_azure("gov", refresh=args.refresh)))
    except Exception as e:
        print("WARNING: Azure ranges unavailable (%s). Pass --azure-file to use a local copy." % e, file=sys.stderr)
    if not args.no_aws:
        try:
            indexes.append(RangeIndex("aws", load_aws(refresh=args.refresh)))
        except Exception as e:
            print("WARNING: AWS ranges unavailable (%s)" % e, file=sys.stderr)
    if args.gcp:
        try:
            indexes.append(RangeIndex("gcp", load_gcp(refresh=args.refresh)))
        except Exception as e:
            print("WARNING: GCP ranges unavailable (%s)" % e, file=sys.stderr)

    # Resolve ---------------------------------------------------------------
    hostnames = [l.strip() for l in Path(args.hostnames).read_text().splitlines()]
    hostnames = list(dict.fromkeys(h for h in hostnames if h and not h.startswith("#")))
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        resolved = list(pool.map(resolve, hostnames))

    # Classify ---------------------------------------------------------------
    results = []  # one row per (host, ip)
    unresolved = []
    for host, ips in resolved:
        if not ips:
            unresolved.append(host)
            continue
        for ip in ips:
            row = {"host": host, "ip": ip, "category": "out", "match": ""}
            for idx in indexes:
                label = idx.match(ip)
                if label is not None:
                    row["category"], row["match"] = idx.name, label
                    break  # first index wins: explicit scope beats cloud ranges
            results.append(row)

    # Output -----------------------------------------------------------------
    if not args.quiet:
        order = [i.name for i in indexes] + ["out"]
        titles = {
            "scope": "IN SCOPE",
            "azure": "IN AZURE PUBLIC RANGES (policy: %s)" % POLICY["azure"],
            "azure-gov": "IN AZURE GOVERNMENT RANGES (policy: %s)" % POLICY["azure"],
            "aws": "IN AWS RANGES (policy: %s)" % POLICY["aws"],
            "gcp": "IN GCP RANGES (policy: %s)" % POLICY["gcp"],
            "out": "OUT OF SCOPE",
        }
        for cat in order:
            rows = [r for r in results if r["category"] == cat]
            print("%s  [%d]" % (titles[cat], len(rows)))
            print("*" * 60)
            for r in rows:
                print("%-45s %-40s %s" % (r["host"], r["ip"], r["match"]))
            print()
        print("DID NOT RESOLVE  [%d]" % len(unresolved))
        print("*" * 60)
        for h in unresolved:
            print(h)

    if args.json:
        Path(args.json).write_text(json.dumps({"results": results, "unresolved": unresolved}, indent=2))
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["host", "ip", "category", "match"])
            w.writeheader()
            w.writerows(results)
            for h in unresolved:
                w.writerow({"host": h, "ip": "", "category": "unresolved", "match": ""})
    if args.xlsx:
        export_xlsx(args.xlsx, results, unresolved, client=args.client, assessor=args.assessor)


if __name__ == "__main__":
    main()