#!/usr/bin/env bash
# recon.sh - end-to-end external recon built entirely on BBOT.
#
# Pipeline (full / "passive + active" mode):
#   1. Passive discovery  (BBOT subdomain-enum, passive only) on the seed domains
#   2. Scope verification (landlord.py) on everything found, against scope_ips.txt
#   3. Active coverage     (BBOT, loud web + nuclei + screenshots) on the
#                          in-scope hosts landlord confirmed - nothing else
#   4. Triage              (bscope.py) serves a dashboard of the active results
#
# Scan modes (chosen at launch, interactively, or with a flag):
#   * passive   - steps 1-2 only: discover + scope-check, never touch the target
#   * both      - the full 4-step pipeline above (default)
#   * active    - skip discovery/scope-check and actively scan the seeds + scope
#                 directly, confined by the scope file and BBOT --strict-scope
#
# Every host that gets actively scanned has first been confirmed in scope by
# landlord.py. Out-of-scope and cloud-provider hosts are reported, never touched.
#
# Seed prep (step 0, only IPs to start from):
#   Run with -s and no -d. BBOT pulls every hostname it can find for the scope
#   IPs (sslcert, shodan_idb, viewdns, rapiddns, hackertarget), split into
#   in-scope and affiliate (related but OUT of scope) hostnames and IPs. The
#   in-scope root domains are expanded through azmap (M365 tenant domains) and
#   crt.sh (shared certs); affiliate root domains go to a review file. It
#   then STOPS so you can review the domains before running the full pipeline.
#   Note: sslcert connects to the scope IPs on TLS ports to read certificates.
#
# Usage:
#   ./recon.sh -s scope_ips.txt -d domains.txt [options]
#   ./recon.sh -s scope_ips.txt -d example.com -d example.net [options]
#   ./recon.sh -s scope_ips.txt                 # seed prep: IPs -> domains
#
# Required:
#   -s FILE         authorized scope: IPs, CIDRs, a-b ranges (landlord + BBOT scope)
#   -d FILE|DOMAIN  seed domains: a file (one per line) or a literal domain.
#                   Repeatable; mix files and domains freely. Leave out to run
#                   seed prep (step 0) instead of the pipeline.
#
# Options:
#   -o DIR          output directory (default: the current directory)
#   -c "Name"       client name for the landlord report
#   -a "Name"       assessor/company name for the landlord report
#   --gcp           also classify Google Cloud ranges in landlord
#   --passive-only  passive mode: stop after step 2 (discovery + scope check)
#   --active-only   active mode: skip discovery/scope-check, actively scan the
#                   seeds + scope directly (confined by scope + --strict-scope)
#                   With neither flag, on an interactive terminal you'll be asked
#                   to choose passive / both / active at launch.
#   --deep          kitchen-sink active scan: adds cloud-enum, code-enum,
#                   email-enum, spider, webbrute, paramminer, lightfuzz and
#                   baddns-heavy. Loud and intrusive - authorized engagements only.
#   --active-preset "P ..."  override the active-scan presets entirely
#                   (default: "web-heavy nuclei web-screenshots"; --deep adds more)
#   --active-modules "M ..." override the active-scan modules entirely
#                   (default: "portscan fingerprintx baddns")
#   --no-config-tuning  don't apply the quieter/faster active-scan config
#                   (recursive-mutation off, WAF avoidance, bounded spider, etc.)
#   --dns-qps N     DNS queries/sec for brute forcing (default: 500)
#   --no-serve      do everything but don't launch the bscope dashboard
#   --bscope-port N bscope port (default: 7373)
#   -y              non-interactive: don't pause before the active scan
#   -h              this help
#
# Needs: bbot (3.x), python3, landlord.py and bscope.py on PATH or beside this
#        script, plus netaddr + requests + openpyxl for landlord.

set -o pipefail
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

SCOPE="" ; OUT="" ; CLIENT="" ; ASSESSOR="" ; GCP=0
PASSIVE_ONLY=0 ; ACTIVE_ONLY=0 ; MODE="" ; NO_SERVE=0 ; YES=0 ; DNS_QPS=500 ; BSCOPE_PORT=7373
DEEP=0
# Standard active scan: solid coverage without the loudest modules.
STD_PRESETS="web-heavy nuclei web-screenshots"
STD_MODULES="portscan fingerprintx baddns"
# Deep active scan (--deep): the kitchen-sink set. Superset of a full manual
# BBOT scan - adds cloud buckets, code/secret leaks, emails, spidering,
# directory brute-force, parameter mining, light fuzzing, and all takeover checks.
DEEP_PRESETS="web-heavy nuclei web-screenshots spider webbrute paramminer lightfuzz baddns-heavy cloud-enum code-enum email-enum"
DEEP_MODULES="portscan fingerprintx"
ACTIVE_PRESETS="" ; ACTIVE_MODULES=""   # set after arg parsing unless overridden
# Config applied to the active scan: quieter and faster, from hard-won defaults.
# Turn off recursive mutation explosions, avoid WAFs in brute-force, bound the
# spider, and keep wayback to URL discovery only.
ACTIVE_CONFIG=(
  modules.dnsbrute.recursive_mutations=false
  modules.dnscommonsrv.recursive_mutations=false
  modules.webbrute.avoid_wafs=true
  modules.wayback.urls=true
  modules.wayback.parameters=false
  modules.wayback.archive=false
  web.spider_distance=2
  web.spider_depth=3
  web.spider_links_per_page=10
)
declare -a SEEDS_IN=()

# Messages show paths relative to the current directory, so they stay short and
# copy-pasteable (".../recon/domains.txt" prints as "domains.txt").
err() {
  local m="$*"
  [ "$PWD" != / ] && m=${m//"$PWD/"/}
  echo -e "$m" >&2
}
die() { err "[!] $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# locate a helper script: PATH first, then next to this script
find_helper() {
  local name=$1
  if have "$name"; then echo "$name"; return; fi
  if [ -f "$SELF_DIR/$name" ]; then echo "python3 $SELF_DIR/$name"; return; fi
  return 1
}

usage() { sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# ---------------------------------------------------------------- args
while [ $# -gt 0 ]; do
  case $1 in
    -s) SCOPE=$2; shift 2 ;;
    -d) SEEDS_IN+=("$2"); shift 2 ;;
    -o) OUT=$2; shift 2 ;;
    -c) CLIENT=$2; shift 2 ;;
    -a) ASSESSOR=$2; shift 2 ;;
    --gcp) GCP=1; shift ;;
    --passive-only) PASSIVE_ONLY=1; shift ;;
    --active-only) ACTIVE_ONLY=1; shift ;;
    --deep) DEEP=1; shift ;;
    --active-preset) ACTIVE_PRESETS=$2; PRESETS_SET=1; shift 2 ;;
    --active-modules) ACTIVE_MODULES=$2; MODULES_SET=1; shift 2 ;;
    --no-config-tuning) ACTIVE_CONFIG=(); shift ;;
    --dns-qps) DNS_QPS=$2; shift 2 ;;
    --no-serve) NO_SERVE=1; shift ;;
    --bscope-port) BSCOPE_PORT=$2; shift 2 ;;
    -y) YES=1; shift ;;
    -h|--help) usage 0 ;;
    *) die "Unknown option: $1 (use -h for help)" ;;
  esac
done

# Choose the active scan profile. An explicit --active-preset / --active-modules
# always wins (even when empty); otherwise --deep picks the kitchen-sink set,
# else the standard one.
if [ "${PRESETS_SET:-0}" != 1 ]; then
  [ "$DEEP" = 1 ] && ACTIVE_PRESETS="$DEEP_PRESETS" || ACTIVE_PRESETS="$STD_PRESETS"
fi
if [ "${MODULES_SET:-0}" != 1 ]; then
  [ "$DEEP" = 1 ] && ACTIVE_MODULES="$DEEP_MODULES" || ACTIVE_MODULES="$STD_MODULES"
fi

# ---------------------------------------------------------------- checks
[ -n "$SCOPE" ] || { err "[!] -s scope file is required."; usage 1; }
[ -f "$SCOPE" ] || die "Scope file not found: $SCOPE"
have bbot || die "bbot not found. Install it: pipx install bbot"
have python3 || die "python3 not found."

# ==================================================================
# STEP 0: Seed prep (no -d given) - scope IPs -> hostnames -> root domains
# ==================================================================
if [ "${#SEEDS_IN[@]}" -eq 0 ]; then
  have jq   || die "jq not found (needed for azmap / crt.sh parsing)."
  have curl || die "curl not found (needed for azmap / crt.sh lookups)."
  OUT="${OUT:-.}"
  mkdir -p "$OUT" || die "Could not create output dir: $OUT"
  PREP=$(cd "$OUT" && pwd)

  err "==================================================================="
  err " recon.sh - STEP 0  Seed prep (no -d given: starting from scope IPs)"
  err " Scope:  $SCOPE"
  echo " Output: $PREP" >&2
  err "==================================================================="
  err "[*] BBOT: hostnames + IPs for the scope (sslcert, shodan_idb, viewdns, rapiddns, hackertarget)"
  err "    sslcert connects to the scope IPs on TLS ports to read certificates."

  HN_IPS="$PREP/hostnames_ips.txt"
  bbot -t "$SCOPE" -m sslcert shodan_idb viewdns rapiddns hackertarget \
       --brief --event-types DNS_NAME IP_ADDRESS -y \
    | sort -u > "$HN_IPS" \
    || die "Seed-prep BBOT scan failed."

  # --brief lines are tab-separated:  TYPE <tab> SCOPE <tab> DATA
  #   SCOPE "in-scope"              -> inside the scope file (a target)
  #   SCOPE "affiliate"/"distance-N" -> related to a target but OUTSIDE scope
  #                                    (CDN, cloud, SaaS, a name off a cert...)
  # Affiliate hostnames are still leads for the domain list; affiliate IPs are
  # out of scope and must not be tested without client sign-off.
  IN_HOSTS="$PREP/seed_inscope_hostnames.txt"
  IN_IPS="$PREP/seed_inscope_ips.txt"
  AFF_HOSTS="$PREP/affiliate_hostnames.txt"
  AFF_IPS="$PREP/affiliate_ips.txt"
  awk -F'\t' -v ih="$IN_HOSTS" -v ii="$IN_IPS" -v ah="$AFF_HOSTS" -v ai="$AFF_IPS" '
    NF < 2 { next }
    {
      type = toupper($1); gsub(/[][[:space:]]/, "", type)
      scope = tolower($2); gsub(/[[:space:]]/, "", scope)
      data = tolower($NF); gsub(/[[:space:]]/, "", data)
      sub(/\.$/, "", data); sub(/^\*\./, "", data)
      if (data == "") next
      ins = (scope == "in-scope")
      if (type == "IP_ADDRESS")    print data > (ins ? ii : ai)
      else if (type == "DNS_NAME") print data > (ins ? ih : ah)
    }' "$HN_IPS"
  for f in "$IN_HOSTS" "$IN_IPS" "$AFF_HOSTS" "$AFF_IPS"; do
    touch "$f"; sort -u -o "$f" "$f"
  done
  # A hostname BBOT reported as both in-scope and affiliate counts as in-scope.
  comm -23 "$AFF_HOSTS" "$IN_HOSTS" > "$AFF_HOSTS.tmp" && mv "$AFF_HOSTS.tmp" "$AFF_HOSTS"
  [ -s "$HN_IPS" ] && [ ! -s "$IN_HOSTS" ] && [ ! -s "$AFF_HOSTS" ] && [ ! -s "$IN_IPS" ] && [ ! -s "$AFF_IPS" ] \
    && err "[!] BBOT returned output but none of it parsed as TYPE<tab>SCOPE<tab>DATA - check $HN_IPS"
  err "[+] In scope:   $(wc -l < "$IN_HOSTS" | tr -d ' ') hostname(s) -> $IN_HOSTS"
  err "                $(wc -l < "$IN_IPS" | tr -d ' ') IP(s)       -> $IN_IPS"
  err "[+] Affiliate:  $(wc -l < "$AFF_HOSTS" | tr -d ' ') hostname(s) -> $AFF_HOSTS  (leads only, NOT in scope)"
  err "                $(wc -l < "$AFF_IPS" | tr -d ' ') IP(s)       -> $AFF_IPS  (out of scope - do not test)"

  # Root domains: last two labels, or last three under a common two-part
  # public suffix (client.co.uk, client.com.au).
  to_roots() {
    grep -E '^[a-z0-9_.-]+\.[a-z]{2,}$' "$1" \
      | awk -F. 'NF >= 3 && length($NF) == 2 && $(NF-1) ~ /^(co|com|net|org|gov|ac|edu)$/ \
                   {print $(NF-2) "." $(NF-1) "." $NF; next}
                 NF >= 2 {print $(NF-1) "." $NF}' | sort -u
  }
  # In-scope roots seed the draft list and the azmap / crt.sh lookups.
  ROOTS="$PREP/root_domains.txt"
  to_roots "$IN_HOSTS" > "$ROOTS"
  # Affiliate roots (minus ones already in-scope) are a review file: often the
  # client's own domains hosted elsewhere, but also CDN / cloud / SaaS names.
  AFF_ROOTS="$PREP/affiliate_root_domains.txt"
  to_roots "$AFF_HOSTS" | comm -23 - "$ROOTS" > "$AFF_ROOTS"
  err "[+] $(wc -l < "$ROOTS" | tr -d ' ') in-scope root domain(s) -> $ROOTS"
  err "[+] $(wc -l < "$AFF_ROOTS" | tr -d ' ') affiliate root domain(s), to review -> $AFF_ROOTS"

  # azmap: other domains registered in the same Microsoft 365 tenant.
  AZMAP="$PREP/azmap_domains.txt"
  err "[*] azmap: M365 tenant domains for each root domain..."
  while read -r d; do
    [ -n "$d" ] || continue
    curl -s --max-time 30 "https://azmap.dev/api/tenant?domain=$d&extract=true" \
      | jq -r '.related_domains[]?' 2>/dev/null
  done < "$ROOTS" | tr 'A-Z' 'a-z' | awk 'NF' | sort -u > "$AZMAP"
  err "[+] $(wc -l < "$AZMAP" | tr -d ' ') tenant domain(s) -> $AZMAP"

  # crt.sh: root domains sharing certificates with the known ones. These carry
  # CDN / hosting / CA names too, so they go to a review file, not the seeds.
  CRTSH="$PREP/crtsh_candidates.txt"
  err "[*] crt.sh: root domains on shared certificates (can be slow)..."
  sort -u "$ROOTS" "$AZMAP" | while read -r d; do
    [ -n "$d" ] || continue
    curl -s --max-time 90 "https://crt.sh/?q=$d&output=json" \
      | jq -r '.[].name_value' 2>/dev/null
  done | tr 'A-Z' 'a-z' | sed 's/^\*\.//' | grep -E '^[a-z0-9.-]+$' \
    | awk -F. 'NF >= 2 {print $(NF-1) "." $NF}' \
    | sort | uniq -c | sort -rn > "$CRTSH"
  err "[+] $(wc -l < "$CRTSH" | tr -d ' ') candidate root domain(s), most common first -> $CRTSH"

  # Draft seed list: root domains from the IPs + tenant domains. Keep any
  # existing domains.txt (e.g. one you already reviewed) as domains.txt.bak.
  DRAFT="$PREP/domains.txt"
  if [ -s "$DRAFT" ]; then
    cp "$DRAFT" "$DRAFT.bak"
    err "[*] Existing domains.txt saved as domains.txt.bak"
  fi
  sort -u "$ROOTS" "$AZMAP" | awk 'NF' > "$DRAFT"

  n() { wc -l < "$1" | tr -d ' '; }
  D=$(err "$DRAFT" 2>&1); A=$(err "$AFF_ROOTS" 2>&1); C=$(err "$CRTSH" 2>&1)
  OUT_ARG=""; [ "$PREP" != "$PWD" ] && OUT_ARG=" -o \"$(err "$PREP" 2>&1)\""

  err ""
  err "==================================================================="
  err " Seed prep done. Nothing has been actively scanned yet."
  err "==================================================================="
  err ""
  err " Review these files, then run the pipeline:"
  err ""
  err " 1. $D  ($(n "$DRAFT") domains)"
  err "    In-scope root domains + M365 tenant domains. Remove anything that"
  err "    isn't the client (hosting, CDN, shared-hosting neighbours)."
  err ""
  err " 2. $A  ($(n "$AFF_ROOTS") domains)"
  err "    Root domains of out-of-scope hostnames. Delete the ones that aren't"
  err "    the client (CDN, cloud, SaaS), then add the rest:"
  err ""
  err "      cat $A >> $D && sort -u -o $D $D"
  err ""
  err " 3. $C  ($(n "$CRTSH") domains, most common first)"
  err "    Delete the lines you don't want, then add the rest:"
  err ""
  err "      awk '{print \$2}' $C >> $D && sort -u -o $D $D"
  err ""
  err " 4. Run the pipeline with the reviewed list:"
  err ""
  err "      $0 -s \"$SCOPE\" -d $D$OUT_ARG"
  err ""
  err "==================================================================="
  exit 0
fi

LANDLORD=$(find_helper landlord.py) || die "landlord.py not found on PATH or in $SELF_DIR"
BSCOPE=$(find_helper bscope.py) || die "bscope.py not found on PATH or in $SELF_DIR"

# ---------------------------------------------------------------- scan mode
# Explicit flags win. Otherwise ask on an interactive terminal; fall back to the
# full pipeline ("both") when non-interactive or -y, so scripted runs are unchanged.
[ "$PASSIVE_ONLY" = 1 ] && [ "$ACTIVE_ONLY" = 1 ] \
  && die "--passive-only and --active-only are mutually exclusive."
if   [ "$PASSIVE_ONLY" = 1 ]; then MODE=passive
elif [ "$ACTIVE_ONLY" = 1 ];  then MODE=active
fi
if [ -z "$MODE" ]; then
  if [ "$YES" != 1 ] && { : </dev/tty; } 2>/dev/null; then
    err "Choose a scan mode:"
    err "  1) Passive only        - discovery + scope check, never touches the target"
    err "  2) Passive + Active     - full pipeline: discover, scope-check, then scan (default)"
    err "  3) Active only          - skip discovery/scope-check; scan the seeds + scope directly"
    read -rp "Enter 1, 2 or 3 [2]: " _m </dev/tty
    case "${_m:-2}" in
      1) MODE=passive ;;
      3) MODE=active  ;;
      *) MODE=both    ;;
    esac
  else
    MODE=both
  fi
fi
# keep the legacy flag in sync for any downstream check
[ "$MODE" = passive ] && PASSIVE_ONLY=1
err "[*] Scan mode: $MODE"

OUT="${OUT:-.}"
mkdir -p "$OUT" || die "Could not create output dir: $OUT"
OUT=$(cd "$OUT" && pwd)

# Expand the scope file to every individual IPv4/IPv6 address it covers, so we
# can later tell which in-scope IPs no discovered hostname points at. Huge
# ranges (e.g. a whole IPv6 /64) are skipped with a note - you can't enumerate
# those host-by-host, so hostname discovery is the only way in for them.
SCOPE_IPS_ALL="$OUT/scope_all_ips.txt"
python3 - "$SCOPE" > "$SCOPE_IPS_ALL" <<'PY'
import sys, ipaddress
MAX = 65536  # don't explode a range bigger than a /16
skipped = []
for line in open(sys.argv[1]):
    line = line.split("#", 1)[0].strip()
    if not line:
        continue
    try:
        if "-" in line and "/" not in line:
            a, b = (ipaddress.ip_address(x.strip()) for x in line.split("-", 1))
            nets = list(ipaddress.summarize_address_range(a, b))
        else:
            nets = [ipaddress.ip_network(line, strict=False)]
    except ValueError:
        continue
    total = sum(n.num_addresses for n in nets)
    if total > MAX:
        skipped.append((line, total)); continue
    for net in nets:
        if net.num_addresses == 1:
            print(net.network_address)
        else:
            for host in net.hosts():
                print(host)
for line, total in skipped:
    print(f"[*] scope entry {line} has {total} addresses - too large to enumerate "
          f"host-by-host; relying on hostname discovery for it.", file=sys.stderr)
PY
SCOPE_IP_COUNT=$(awk 'NF' "$SCOPE_IPS_ALL" | wc -l | tr -d ' ')

# ---------------------------------------------------------------- build seed list
SEEDS="$OUT/seeds.txt"
: > "$SEEDS"
for item in "${SEEDS_IN[@]}"; do
  if [ -f "$item" ]; then
    cat "$item" >> "$SEEDS"
  else
    echo "$item" >> "$SEEDS"
  fi
done
# tidy: strip comments/blanks/whitespace, lowercase, dedupe
sed 's/#.*//; s/[[:space:]]//g' "$SEEDS" | tr 'A-Z' 'a-z' | awk 'NF && !seen[$0]++' > "$SEEDS.tmp" \
  && mv "$SEEDS.tmp" "$SEEDS"
SEED_COUNT=$(wc -l < "$SEEDS" | tr -d ' ')
[ "$SEED_COUNT" -gt 0 ] || die "No valid seed domains after cleanup."

err "==================================================================="
err " recon.sh - BBOT-only external recon"
echo " Output:   $OUT" >&2
err " Scope:    $SCOPE"
err " Seeds:    $SEED_COUNT domain(s) -> $SEEDS"
err "==================================================================="
err "[*] Review the seed list before the active scan. Anything not clearly"
err "    in your engagement should be removed from $SEEDS now."
err ""

# gcp flag for landlord
LAND_GCP=""; [ "$GCP" = 1 ] && LAND_GCP="--gcp"
LAND_CLIENT=(); [ -n "$CLIENT" ] && LAND_CLIENT=(--client "$CLIENT")
LAND_ASSESSOR=(); [ -n "$ASSESSOR" ] && LAND_ASSESSOR=(--assessor "$ASSESSOR")

if [ "$MODE" != active ]; then
# ==================================================================
# STEP 1: Passive discovery
# ==================================================================
err "### STEP 1/4  Passive discovery (BBOT subdomain-enum, passive only)"
PASSIVE_DIR="$OUT/01_passive"
# -t scope + seeds: scope is the IPs, seeds are the domains BBOT starts from.
# -rf passive keeps BBOT from touching the client. -em viewdns drops noisy reverse WHOIS.
bbot -t "$SCOPE" -s "$SEEDS" \
     -p subdomain-enum -rf passive -em viewdns \
     -c dns.brute_threads="$DNS_QPS" \
     -n passive -o "$PASSIVE_DIR" -y \
  || die "Passive BBOT scan failed."

PASSIVE_JSON="$PASSIVE_DIR/passive/output.json"
[ -f "$PASSIVE_JSON" ] || die "Expected BBOT output not found: $PASSIVE_JSON"

# Every hostname BBOT discovered -> flat list for landlord
ALL_HOSTS="$OUT/all_hostnames.txt"
jq -r 'select(.type=="DNS_NAME") | .data' "$PASSIVE_JSON" \
  | tr 'A-Z' 'a-z' | sed 's/\.$//; s/^\*\.//' | awk 'NF && !seen[$0]++' | sort > "$ALL_HOSTS"
HOST_COUNT=$(wc -l < "$ALL_HOSTS" | tr -d ' ')
err "[+] Discovered $HOST_COUNT unique hostname(s) -> $ALL_HOSTS"
[ "$HOST_COUNT" -gt 0 ] || die "No hostnames discovered; nothing to check."

# ==================================================================
# STEP 2: Scope verification (landlord.py)
# ==================================================================
err ""
err "### STEP 2/4  Scope verification (landlord.py)"
LAND_JSON="$OUT/scope_check.json"
LAND_XLSX="$OUT/scope_report.xlsx"
# shellcheck disable=SC2086
$LANDLORD "$ALL_HOSTS" "$SCOPE" $LAND_GCP \
  --json "$LAND_JSON" --xlsx "$LAND_XLSX" \
  "${LAND_CLIENT[@]}" "${LAND_ASSESSOR[@]}" \
  || die "landlord.py failed."
err "[+] Scope report: $LAND_XLSX"
err "[+] Classified data: $LAND_JSON"

# Pull the confirmed in-scope hostnames out of landlord's JSON
INSCOPE_HOSTS="$OUT/inscope_hostnames.txt"
python3 - "$LAND_JSON" > "$INSCOPE_HOSTS" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
hosts = sorted({r["host"] for r in data.get("results", []) if r.get("category") == "scope"})
print("\n".join(hosts))
PY
INSCOPE_COUNT=$(awk 'NF' "$INSCOPE_HOSTS" | wc -l | tr -d ' ')
err "[+] $INSCOPE_COUNT hostname(s) confirmed in scope -> $INSCOPE_HOSTS"

# Out-of-scope but client-related: hosts whose IPs are NOT in scope (out of
# scope, or in a cloud provider's ranges). This is the list to hand the client
# so they can confirm ownership and authorize (or exclude) each one. Written as
# a formatted Excel workbook (with a plain-text IP list alongside).
OOS_XLSX="$OUT/out_of_scope_for_client.xlsx"
OOS_IPS="$OUT/out_of_scope_ips.txt"
# In-scope IPs that at least one discovered hostname resolves to.
INSCOPE_IPS_WITH_HOST="$OUT/inscope_ips_with_hostname.txt"
python3 - "$LAND_JSON" > "$INSCOPE_IPS_WITH_HOST" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
ips = sorted({r["ip"] for r in data.get("results", [])
              if r.get("category") == "scope" and r.get("ip")})
print("\n".join(ips))
PY
# In-scope IPs that NO discovered hostname points at. These still get scanned -
# important services often live on bare IPs with no DNS name. Only meaningful
# when the scope was small enough to enumerate (SCOPE_IPS_ALL is non-empty).
NOHOST_IPS="$OUT/inscope_ips_no_hostname.txt"
if [ -s "$SCOPE_IPS_ALL" ]; then
  comm -23 <(sort -u "$SCOPE_IPS_ALL") <(sort -u "$INSCOPE_IPS_WITH_HOST") > "$NOHOST_IPS"
else
  : > "$NOHOST_IPS"
fi
NOHOST_COUNT=$(awk 'NF' "$NOHOST_IPS" | wc -l | tr -d ' ')
err "[+] In-scope IPs with no hostname (scanned anyway): $NOHOST_COUNT -> $NOHOST_IPS"

OOS_COUNT=$(python3 - "$LAND_JSON" "$OOS_XLSX" "$OOS_IPS" "$CLIENT" <<'PY'
import json, sys
land_json, xlsx_path, ips_path, client = sys.argv[1], sys.argv[2], sys.argv[3], (sys.argv[4] if len(sys.argv) > 4 else "")
data = json.load(open(land_json))
labels = {"azure": "Azure (Public)", "azure-gov": "Azure (Government)",
          "aws": "AWS", "gcp": "Google Cloud", "out": "Out of scope"}
colors = {"Azure (Public)": "0078D4", "Azure (Government)": "004578",
          "AWS": "FF9900", "Google Cloud": "DB4437", "Out of scope": "C62828"}
rows = {}
for r in data.get("results", []):
    cat = r.get("category")
    if cat in labels:
        rows.setdefault((r["host"], r["ip"]), (labels[cat], r.get("match", "")))
rows = sorted((h, ip, lbl, m) for (h, ip), (lbl, m) in rows.items())

# bare out-of-scope IP list (easy to paste into a ticket)
with open(ips_path, "w") as f:
    f.write("\n".join(sorted({ip for _, ip, lbl, _ in rows if lbl == "Out of scope"})) + "\n")

try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.worksheet.table import Table, TableStyleInfo
    from openpyxl.utils import get_column_letter
except ImportError:
    # openpyxl missing: fall back to a .tsv next to where the xlsx would go
    tsv = xlsx_path[:-5] + ".tsv"
    with open(tsv, "w") as f:
        f.write("hostname\tip_address\tclassification\tprovider_or_service\n")
        for h, ip, lbl, m in rows:
            f.write(f"{h}\t{ip}\t{lbl}\t{m}\n")
    print(len(rows)); sys.exit(0)

FONT = "Arial"
wb = Workbook(); ws = wb.active; ws.title = "For Review"
title = Font(name=FONT, bold=True, size=14)
body = Font(name=FONT, size=10)
bold = Font(name=FONT, size=10, bold=True)
hdr_font = Font(name=FONT, bold=True, color="FFFFFF")
hdr_fill = PatternFill("solid", fgColor="1F3864")
wrap = Alignment(wrap_text=True, vertical="top")
thin = Side(style="thin", color="BFBFBF")
box = Border(left=thin, right=thin, top=thin, bottom=thin)
input_fill = PatternFill("solid", fgColor="FFF2CC")

ws["A1"] = (("%s - " % client) if client else "") + "Assets Outside the Agreed Scope"
ws["A1"].font = title
ws["A2"] = ("These hostnames point at your organization but resolve to IP addresses that are "
            "NOT in the agreed testing scope - they are hosted in a cloud provider or elsewhere. "
            "They have NOT been tested. Please confirm which are yours and whether we may test them.")
ws["A2"].font = body; ws["A2"].alignment = wrap
ws.merge_cells("A2:F2"); ws.row_dimensions[2].height = 45

headers = ["Hostname", "IP Address", "Classification", "Provider / Service",
           "Yours? (Yes/No)", "OK to test? (Yes/No)"]
hrow = 4
for i, h in enumerate(headers, 1):
    c = ws.cell(row=hrow, column=i, value=h)
    c.font, c.fill, c.border = hdr_font, hdr_fill, box
    c.alignment = Alignment(horizontal="center", wrap_text=True)
for ri, (host, ip, lbl, match) in enumerate(rows, hrow + 1):
    for ci, v in enumerate([host, ip, lbl, match, "", ""], 1):
        c = ws.cell(row=ri, column=ci, value=v)
        c.font, c.border, c.alignment = body, box, wrap
    cc = ws.cell(row=ri, column=3)
    cc.fill = PatternFill("solid", fgColor=colors.get(lbl, "C62828"))
    cc.font = Font(name=FONT, color="FFFFFF", bold=True)
    ws.cell(row=ri, column=5).fill = input_fill
    ws.cell(row=ri, column=6).fill = input_fill
last = hrow + len(rows)
if rows:
    t = Table(displayName="OutOfScope", ref="A%d:F%d" % (hrow, last))
    t.tableStyleInfo = TableStyleInfo(name="TableStyleLight1", showRowStripes=True)
    ws.add_table(t)
ws.freeze_panes = "A%d" % (hrow + 1)
for i, w in enumerate([42, 18, 20, 32, 16, 20], 1):
    ws.column_dimensions[get_column_letter(i)].width = w
wb.save(xlsx_path)
print(len(rows))
PY
)
if [ -f "$OOS_XLSX" ]; then
  err "[+] $OOS_COUNT out-of-scope / cloud host(s) for the client -> $OOS_XLSX"
else
  err "[+] $OOS_COUNT out-of-scope / cloud host(s) for the client -> ${OOS_XLSX%.xlsx}.tsv (openpyxl not installed)"
  OOS_XLSX="${OOS_XLSX%.xlsx}.tsv"
fi
err "    (bare out-of-scope IP list -> $OOS_IPS)"

if [ "$MODE" = passive ]; then
  err ""
  err "[*] Passive mode. Stopping after scope verification."
  err "    For the client: $LAND_XLSX (full report)"
  err "                    $OOS_XLSX (out-of-scope / cloud hosts to confirm)"
  err "    Run the active scan later with the confirmed in-scope hosts."
  exit 0
fi
fi   # end of passive discovery + scope verification (skipped in active mode)

# Build the active target list.
ACTIVE_TARGETS="$OUT/active_targets.txt"
if [ "$MODE" = active ]; then
  # No discovery / scope-check ran. Targets are your seed domains plus every
  # individually enumerable in-scope IP. BBOT's own scope (the scope file passed
  # as -t) and --strict-scope keep every active module confined to the scope.
  cat "$SEEDS" "$SCOPE_IPS_ALL" 2>/dev/null | awk 'NF && !seen[$0]++' > "$ACTIVE_TARGETS"
else
  # The active scan targets everything in scope: the confirmed hostnames PLUS the
  # bare in-scope IPs no hostname pointed at (so nothing on those IPs is missed).
  # This same list - one entry per host, hostname when there is one else the bare
  # IP, no overlap - is exactly what to feed Nessus/nmap.
  cat "$INSCOPE_HOSTS" "$NOHOST_IPS" | awk 'NF && !seen[$0]++' > "$ACTIVE_TARGETS"
fi
ACTIVE_COUNT=$(wc -l < "$ACTIVE_TARGETS" | tr -d ' ')

if [ "$ACTIVE_COUNT" -eq 0 ]; then
  err ""
  err "[!] Nothing in scope to actively scan. Likely causes:"
  err "    - scope file lists IPs none of the discovered names resolve to, and"
  err "      the range was too large to enumerate host-by-host"
  [ "$MODE" != active ] && err "    - the client's sites are all behind a CDN (see the Azure/AWS tabs" \
                        && err "      of $LAND_XLSX and confirm those ranges with the client)"
  exit 0
fi

# ==================================================================
# STEP 3: Active coverage
# ==================================================================
err ""
if [ "$MODE" = active ]; then
  err "### Active scan for maximum coverage (active-only mode)"
else
  err "### STEP 3/4  Active scan for maximum coverage"
fi
[ "$DEEP" = 1 ] && err "    Profile: DEEP (kitchen-sink: cloud/code/email enum, spider, brute-force, fuzzing)"
err "    Presets: $ACTIVE_PRESETS"
err "    Modules: $ACTIVE_MODULES"
err "    Targets: $ACTIVE_COUNT in-scope target(s) ONLY"
if [ "$MODE" = active ]; then
  err "             (seeds + enumerable in-scope IPs; confined by scope + --strict-scope)"
else
  err "             ($INSCOPE_COUNT hostname(s) + $NOHOST_COUNT bare IP(s) with no hostname)"
fi
err ""
err "[!] This step sends traffic directly to the targets (port scans, web"
err "    requests, nuclei templates, screenshots)."
if [ "$MODE" = active ]; then
  err "[!] Active-only: passive discovery and the landlord scope-confirmation step"
  err "    were SKIPPED. The scan is confined to your scope file by BBOT"
  err "    --strict-scope; make sure that scope file is correct before proceeding."
else
  err "    Only in-scope targets are included: hostnames landlord confirmed, plus"
  err "    in-scope IPs that no hostname points at (so services on bare IPs aren't missed)."
fi

if [ "$YES" != 1 ]; then
  if { : </dev/tty; } 2>/dev/null; then
    read -rp "Proceed with the active scan? [y/N] " go </dev/tty
    [[ "$go" =~ ^[Yy] ]] || { err "[*] Stopped before active scan. Passive results and scope report are in $OUT."; exit 0; }
  else
    die "No terminal to confirm the active scan. Re-run with -y to allow it."
  fi
fi

ACTIVE_DIR="$OUT/03_active"
# Active scan. Targets AND seeds are the in-scope hosts + bare in-scope IPs:
# BBOT's own scope control then keeps every active module confined to them.
# subdomain-enum is intentionally NOT re-run here; this pass is about depth on
# known in-scope targets, not discovery.
# ACTIVE_CONFIG tunes the scan quieter/faster (see top of script); empty if
# --no-config-tuning was passed.
# In active-only mode nothing was scope-verified first, so pass the scope FILE as
# BBOT's targets (-t) - it covers CIDRs/ranges that can't be enumerated host-by-
# host - and seed from the target list. --strict-scope then confines every module
# to the scope. In both/passive-derived mode, targets are the confirmed in-scope
# hosts themselves.
if [ "$MODE" = active ]; then SCAN_SCOPE_T="$SCOPE"; else SCAN_SCOPE_T="$ACTIVE_TARGETS"; fi
# shellcheck disable=SC2086
bbot -t "$SCAN_SCOPE_T" -s "$ACTIVE_TARGETS" \
     -p $ACTIVE_PRESETS -m $ACTIVE_MODULES \
     ${ACTIVE_CONFIG:+-c "${ACTIVE_CONFIG[@]}"} \
     --strict-scope \
     -n active -o "$ACTIVE_DIR" -y \
  || die "Active BBOT scan failed."

ACTIVE_JSON="$ACTIVE_DIR/active/output.json"
[ -f "$ACTIVE_JSON" ] || die "Expected active output not found: $ACTIVE_JSON"
err "[+] Active scan complete -> $ACTIVE_JSON"

# Scan-ready target lists for other tools (Nessus, nmap, etc.).
# Open-port targets BBOT confirmed, as host:port (both modes).
jq -r 'select(.type=="OPEN_TCP_PORT") | .data' "$ACTIVE_JSON" 2>/dev/null \
  | sort -u > "$OUT/open_ports.txt"
# The complete in-scope IP list = IPs hostnames resolve to + bare in-scope IPs
# with no hostname. Only available when the scope-check step ran (not active-only).
INSCOPE_IPS=""
if [ "$MODE" != active ]; then
  INSCOPE_IPS="$OUT/inscope_ips.txt"
  cat "$INSCOPE_IPS_WITH_HOST" "$NOHOST_IPS" \
    | awk 'NF' | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$INSCOPE_IPS" 2>/dev/null \
    || cat "$INSCOPE_IPS_WITH_HOST" "$NOHOST_IPS" | awk 'NF' | sort -u > "$INSCOPE_IPS"
  err "[+] Scan-ready in-scope IPs (for Nessus/nmap) -> $INSCOPE_IPS"
  err "    ($(awk 'NF' "$INSCOPE_IPS_WITH_HOST" | wc -l | tr -d ' ') with a hostname, $NOHOST_COUNT without)"
fi

# Find the screenshots gowitness produced, if any
SHOTS_DIR=""
for cand in "$ACTIVE_DIR/active/gowitness/screenshots" "$ACTIVE_DIR/active/gowitness"; do
  [ -d "$cand" ] && { SHOTS_DIR=$cand; break; }
done

# ==================================================================
# STEP 4: Triage dashboard (bscope.py)
# ==================================================================
err ""
if [ "$MODE" = active ]; then
  err "### Triage dashboard (bscope.py)"
else
  err "### STEP 4/4  Triage dashboard (bscope.py)"
fi
VULN_COUNT=$(jq -r 'select(.type=="VULNERABILITY" or .type=="FINDING")' "$ACTIVE_JSON" 2>/dev/null | grep -c '"type"')
err "[+] Active scan surfaced findings/vulnerabilities: ${VULN_COUNT:-0}"

SHOTS_ARG=()
[ -n "$SHOTS_DIR" ] && { SHOTS_ARG=(--shots "$SHOTS_DIR"); err "[+] Screenshots: $SHOTS_DIR"; }

err ""
err "==================================================================="
echo " Done. Everything is in: $OUT" >&2
if [ "$MODE" != active ]; then
  err "   FOR THE CLIENT:"
  err "     Scope report (Excel)      : $LAND_XLSX"
  err "     Out-of-scope / cloud hosts: $OOS_XLSX"
  err "     Out-of-scope IPs only     : $OOS_IPS"
fi
err "   FOR YOUR SCANNERS (Nessus, nmap...):"
err "     Targets, 1 per host (Nessus): $ACTIVE_TARGETS"
[ -n "$INSCOPE_IPS" ]   && err "     In-scope IPs (ALL)        : $INSCOPE_IPS"
[ "$MODE" != active ]   && err "     In-scope hostnames        : $INSCOPE_HOSTS"
[ "$MODE" != active ]   && err "     In-scope IPs, no hostname : $NOHOST_IPS"
err "     Confirmed open ports      : $OUT/open_ports.txt"
err "   RAW BBOT OUTPUT:"
[ "$MODE" != active ]   && err "     Passive                   : $PASSIVE_JSON"
err "     Active                    : $ACTIVE_JSON"
err "==================================================================="

if [ "$NO_SERVE" = 1 ]; then
  err ""
  err "[*] --no-serve set. Launch the dashboard yourself with:"
  err "    $BSCOPE $ACTIVE_JSON ${SHOTS_ARG[*]} --port $BSCOPE_PORT"
  exit 0
fi

err ""
err "[*] Launching bscope triage dashboard (Ctrl-C to stop)..."
# shellcheck disable=SC2086
exec $BSCOPE "$ACTIVE_JSON" "${SHOTS_ARG[@]}" --port "$BSCOPE_PORT"
