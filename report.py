#!/usr/bin/env python3
"""
report.py - turn bscope-triaged findings into a client-ready report.

Reads a BBOT results file and its bscope triage sidecar (the <input>.bscope.json
that bscope writes), then produces a clean report of the findings you've marked
- by default only the ones that matter (confirmed / reviewed / reported), so the
"new" noise never reaches the client.

Usage:
    python3 report.py active/output.json                       # -> report.html
    python3 report.py active/output.json -o acme_report.html
    python3 report.py active/output.json --format md
    python3 report.py active/output.json --state custom.bscope.json
    python3 report.py active/output.json --client "Acme Corp" --assessor "Your Co"
    python3 report.py active/output.json --include confirmed,reported   # pick statuses

Statuses bscope uses: new, triaging, confirmed, false_positive,
not_exploitable, reviewed, reported. By default this report includes
confirmed, reviewed and reported (the ones worth showing a client). Override
with --include. Pass --all to include everything except "new".

Stdlib only (Python 3.7+), matching bscope. HTML output opens in any browser and
prints straight to PDF; Markdown output drops into any docs pipeline.
"""
import argparse
import csv
import hashlib
import html
import json
import os
import re
import sys
from datetime import datetime

# ------------------------------------------------------------------ severity
SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
SEV_COLOR = {
    "critical": "#b00020", "high": "#d84315", "medium": "#d4a017",
    "low": "#1f6feb", "info": "#5a6b7b", "unknown": "#6b7684",
}
STATUS_LABEL = {
    "new": "New", "triaging": "Triaging", "confirmed": "Confirmed",
    "false_positive": "False positive", "not_exploitable": "Not exploitable",
    "reviewed": "Reviewed", "reported": "Reported",
}
FINDING_TYPES = {"VULNERABILITY", "FINDING"}
TYPE_INTEREST = {
    "VULNERABILITY": "high", "FINDING": "medium", "STORAGE_BUCKET": "medium",
    "SECRET": "high", "PASSWORD": "high", "HASHED_PASSWORD": "medium",
    "OPEN_TCP_PORT": "low", "URL": "info", "TECHNOLOGY": "info",
    "DNS_NAME": "info", "IP_ADDRESS": "info", "EMAIL_ADDRESS": "low",
}
DEFAULT_INCLUDE = ["confirmed", "reviewed", "reported"]


# ------------------------------------------------------------------ parsing
# These mirror bscope so event IDs line up with its triage file exactly:
# id = sha1("TYPE|data_str")[:12], where data_str is the description/url/host/blob.
def _event_id(type_, data_str):
    return hashlib.sha1(("%s|%s" % (type_, data_str)).encode("utf-8", "replace")).hexdigest()[:12]


def _norm(type_, data, module, tags):
    desc = host = url = ""
    severity = None
    if isinstance(data, dict):
        desc = data.get("description", "") or ""
        host = data.get("host", "") or ""
        url = data.get("url", "") or ""
        severity = (data.get("severity") or "").lower() or None
        data_str = desc or url or host or json.dumps(data, ensure_ascii=False)
    else:
        data_str = str(data)

    if severity not in SEV_RANK:
        blob = (data_str + " " + " ".join(map(str, tags or []))).lower()
        severity = next((s for s in ("critical", "high", "medium", "low")
                         if s in blob), None)

    if severity in SEV_RANK and severity != "unknown":
        priority = severity
    else:
        priority = TYPE_INTEREST.get(type_, "info")
    # If BBOT gave no severity, fall back to the type-based band so the finding
    # groups under a real heading (e.g. an exposed .git FINDING -> Medium) rather
    # than "Unknown".
    if severity not in SEV_RANK or severity == "unknown":
        severity = priority

    # recover host/port/url from a bare "host:port" or URL when not in a dict
    port = ""
    if not host and data_str:
        m = re.match(r"^([a-z0-9.\-_]+):(\d{1,5})$", data_str, re.I)
        if m:
            host, port = m.group(1), m.group(2)
        elif data_str.lower().startswith("http"):
            url = url or data_str
    if url and not host:
        m = re.match(r"^https?://([^/:]+)", url, re.I)
        if m:
            host = m.group(1)

    target = url or ("%s:%s" % (host, port) if port else host) or data_str[:100]
    lane = "finding" if (type_ in FINDING_TYPES or SEV_RANK.get(priority, 0) >= 3) else "asset"
    title = desc.split(". ")[0][:120] if desc else (type_.replace("_", " ").title())
    return {
        "id": _event_id(type_, data_str), "type": type_, "module": module or "",
        "severity": severity or "unknown", "priority": priority, "lane": lane,
        "title": title, "target": target, "host": host, "url": url, "port": port,
        "description": desc, "data_str": data_str,
    }


def load_events(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        blob = f.read().strip()
    ext = os.path.splitext(path)[1].lower()
    events = []
    if ext in (".csv", ".tsv") or (blob[:1] not in "{[" and "," in blob[:200]):
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            for row in csv.DictReader(f):
                type_ = (row.get("Event type") or row.get("type") or "UNKNOWN").strip()
                data = (row.get("Event data") or row.get("data") or "").strip()
                module = (row.get("Source Module") or row.get("module") or "").strip()
                tags = re.split(r"[,\s]+", (row.get("Event Tags") or row.get("tags") or "").strip())
                events.append(_norm(type_, data, module, [t for t in tags if t]))
        return events
    records = json.loads(blob) if blob.startswith("[") else \
        [json.loads(l) for l in blob.splitlines() if l.strip()]
    for r in records:
        if isinstance(r, dict):
            events.append(_norm(r.get("type", "UNKNOWN"), r.get("data", ""),
                                r.get("module", ""), r.get("tags", [])))
    return events


def load_state(path):
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# ------------------------------------------------------------------ assemble
def collect(events, state, include):
    rows = []
    seen = set()
    for ev in events:
        st = state.get(ev["id"], {})
        status = st.get("status", "new")
        if status not in include:
            continue
        if ev["id"] in seen:          # dedupe identical findings
            continue
        seen.add(ev["id"])
        rows.append({**ev, "status": status, "notes": st.get("notes", "")})
    rows.sort(key=lambda r: (-SEV_RANK.get(r["severity"], 0), r["type"], r["target"]))
    return rows


# ------------------------------------------------------------------ HTML out
def render_html(rows, client, assessor):
    now = datetime.now().strftime("%B %d, %Y")
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    sev_order = sorted(counts, key=lambda s: -SEV_RANK.get(s, 0))

    def esc(s):
        return html.escape(str(s or ""))

    parts = []
    parts.append("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>External Assessment Findings</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         color: #1a1f24; max-width: 900px; margin: 0 auto; padding: 40px 28px; line-height: 1.5; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 19px; margin: 34px 0 12px; border-bottom: 2px solid #e4e8ec; padding-bottom: 6px; }
  .meta { color: #5a6b7b; font-size: 14px; margin-bottom: 28px; }
  .summary { display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0 8px; }
  .pill { border-radius: 8px; padding: 10px 16px; color: #fff; font-weight: 600; font-size: 14px; }
  .pill small { display: block; font-weight: 400; opacity: .9; font-size: 12px; }
  .finding { border: 1px solid #e4e8ec; border-left-width: 5px; border-radius: 8px;
             padding: 16px 18px; margin: 14px 0; page-break-inside: avoid; }
  .finding h3 { margin: 0 0 8px; font-size: 16px; }
  .badge { display: inline-block; font-size: 11px; font-weight: 700; text-transform: uppercase;
           letter-spacing: .04em; color: #fff; border-radius: 4px; padding: 2px 8px; margin-right: 8px; }
  .status { display: inline-block; font-size: 11px; font-weight: 600; color: #3a4654;
            background: #eef1f4; border-radius: 4px; padding: 2px 8px; }
  .kv { margin: 6px 0; font-size: 14px; }
  .kv b { color: #3a4654; }
  .target { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px;
            background: #f4f6f8; padding: 1px 6px; border-radius: 4px; word-break: break-all; }
  .notes { background: #fafbfc; border: 1px solid #eef1f4; border-radius: 6px;
           padding: 8px 12px; margin-top: 8px; font-size: 14px; }
  .disclaimer { background: #fbf7e9; border: 1px solid #efe3b8; border-radius: 8px;
                padding: 12px 16px; font-size: 13px; color: #5a4b1f; margin-top: 28px; }
  .empty { color: #5a6b7b; font-style: italic; }
  @media print { body { padding: 0; } .finding { border-left-width: 4px; } }
</style></head><body>""")

    parts.append("<h1>External Assessment Findings</h1>")
    sub = []
    if client:
        sub.append("Prepared for <b>%s</b>" % esc(client))
    if assessor:
        sub.append("by %s" % esc(assessor))
    sub.append(now)
    parts.append('<div class="meta">%s</div>' % " &middot; ".join(sub))

    # summary pills
    if rows:
        parts.append('<div class="summary">')
        for sev in sev_order:
            parts.append('<div class="pill" style="background:%s">%d<small>%s</small></div>'
                         % (SEV_COLOR.get(sev, "#5a6b7b"), counts[sev], esc(sev.title())))
        parts.append('</div>')
        parts.append('<p class="meta">%d finding%s included.</p>'
                     % (len(rows), "" if len(rows) == 1 else "s"))
    else:
        parts.append('<p class="empty">No findings matched the selected statuses. '
                     'Triage findings in bscope (mark them Confirmed, Reviewed or Reported), '
                     'then regenerate.</p>')

    # findings grouped by severity
    cur = None
    for r in rows:
        if r["severity"] != cur:
            cur = r["severity"]
            parts.append("<h2>%s</h2>" % esc(cur.upper()))
        color = SEV_COLOR.get(r["severity"], "#5a6b7b")
        parts.append('<div class="finding" style="border-left-color:%s">' % color)
        parts.append('<h3><span class="badge" style="background:%s">%s</span>%s'
                     '<span class="status">%s</span></h3>'
                     % (color, esc(r["severity"]), esc(r["title"]),
                        esc(STATUS_LABEL.get(r["status"], r["status"]))))
        parts.append('<div class="kv"><b>Affected:</b> <span class="target">%s</span></div>'
                     % esc(r["target"]))
        if r["description"] and r["description"] != r["title"]:
            parts.append('<div class="kv"><b>Description:</b> %s</div>' % esc(r["description"]))
        parts.append('<div class="kv"><b>Detected by:</b> %s%s</div>'
                     % (esc(r["type"]), (" / %s" % esc(r["module"])) if r["module"] else ""))
        if r["notes"]:
            parts.append('<div class="notes"><b>Assessor notes:</b> %s</div>' % esc(r["notes"]))
        parts.append('</div>')

    parts.append('<div class="disclaimer"><b>Scope &amp; limitations.</b> '
                 'These findings reflect the external assessment of in-scope hosts at the time of '
                 'testing. Only assets within the agreed scope were tested. This report lists items '
                 'reviewed and confirmed by the assessor; it is not an exhaustive statement of every '
                 'possible weakness.</div>')
    parts.append("</body></html>")
    return "\n".join(parts)


# ------------------------------------------------------------------ Markdown out
def render_md(rows, client, assessor):
    now = datetime.now().strftime("%B %d, %Y")
    out = ["# External Assessment Findings", ""]
    sub = []
    if client:
        sub.append("Prepared for **%s**" % client)
    if assessor:
        sub.append("by %s" % assessor)
    sub.append(now)
    out.append(" &middot; ".join(sub) if False else " | ".join(sub))
    out.append("")
    if not rows:
        out.append("_No findings matched the selected statuses. Triage findings in bscope "
                   "(mark them Confirmed, Reviewed or Reported), then regenerate._")
        return "\n".join(out)

    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    out.append("## Summary")
    out.append("")
    out.append("| Severity | Count |")
    out.append("| --- | --- |")
    for sev in sorted(counts, key=lambda s: -SEV_RANK.get(s, 0)):
        out.append("| %s | %d |" % (sev.title(), counts[sev]))
    out.append("")

    cur = None
    for r in rows:
        if r["severity"] != cur:
            cur = r["severity"]
            out.append("")
            out.append("## %s" % cur.upper())
        out.append("")
        out.append("### %s  _(%s)_" % (r["title"], STATUS_LABEL.get(r["status"], r["status"])))
        out.append("- **Affected:** `%s`" % r["target"])
        if r["description"] and r["description"] != r["title"]:
            out.append("- **Description:** %s" % r["description"])
        out.append("- **Detected by:** %s%s" % (r["type"], (" / %s" % r["module"]) if r["module"] else ""))
        if r["notes"]:
            out.append("- **Assessor notes:** %s" % r["notes"])
    out.append("")
    out.append("---")
    out.append("_Scope & limitations: these findings reflect the external assessment of in-scope "
               "hosts at the time of testing. Only assets within the agreed scope were tested._")
    return "\n".join(out)


# ------------------------------------------------------------------ main
def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("infile", help="BBOT results file (output.json / .ndjson / .csv)")
    p.add_argument("-o", "--out", help="output file (default: report.html or report.md)")
    p.add_argument("--format", choices=["html", "md"], default="html")
    p.add_argument("--state", help="bscope triage file (default: <infile>.bscope.json)")
    p.add_argument("--client", default="", help="client name on the report")
    p.add_argument("--assessor", default="", help="assessor / company name")
    p.add_argument("--include", help="comma-separated statuses to include "
                   "(default: confirmed,reviewed,reported)")
    p.add_argument("--all", action="store_true",
                   help="include every triaged status except 'new'")
    args = p.parse_args()

    if not os.path.isfile(args.infile):
        sys.exit("error: no such file: %s" % args.infile)

    state_path = args.state or (args.infile + ".bscope.json")
    if not os.path.isfile(state_path):
        print("warning: no triage file at %s - nothing has been triaged yet, "
              "so the report will be empty. Run bscope first." % state_path, file=sys.stderr)

    if args.all:
        include = [s for s in STATUS_LABEL if s != "new"]
    elif args.include:
        include = [s.strip() for s in args.include.split(",") if s.strip()]
        bad = [s for s in include if s not in STATUS_LABEL]
        if bad:
            sys.exit("error: unknown status(es): %s\nvalid: %s"
                     % (", ".join(bad), ", ".join(STATUS_LABEL)))
    else:
        include = DEFAULT_INCLUDE

    events = load_events(args.infile)
    state = load_state(state_path)
    rows = collect(events, state, include)

    if args.format == "html":
        text = render_html(rows, args.client, args.assessor)
        out = args.out or "report.html"
    else:
        text = render_md(rows, args.client, args.assessor)
        out = args.out or "report.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)

    print("[+] %d finding(s) written to %s" % (len(rows), out), file=sys.stderr)
    if not rows:
        print("    (statuses included: %s)" % ", ".join(include), file=sys.stderr)
    elif args.format == "html":
        print("    Open it in a browser; print to PDF for the client.", file=sys.stderr)


if __name__ == "__main__":
    main()
