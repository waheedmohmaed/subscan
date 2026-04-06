#!/bin/bash
# ============================================================
#  subscan.sh — Subdomain Scanner v1.2
#  Step 1 : Subfinder       — passive OSINT
#  Step 2 : dnsx            — live DNS resolution
#  Step 3 : httpx           — web detection + CDN + IP + TLS
#  Step 4 : Nuclei          — vulnerability scan (--vuln)
#  Step 5 : Takeover check  — (--takeover)
#  Extras : Priority targets, alerting, top technologies
#  Speed  : Parallel execution (httpx + TLS simultaneously)
# ============================================================

VERSION="1.2"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BLUE='\033[0;34m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

elapsed() {
    local secs=$(( $2 - $1 ))
    printf "%dm %ds" $(( secs/60 )) $(( secs%60 ))
}

check_deps() {
    local missing=()
    for tool in subfinder dnsx httpx; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[!] Missing: ${missing[*]}${NC}"
        echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo "  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        exit 1
    fi
    command -v nuclei &>/dev/null || echo -e "${YELLOW}[!] nuclei not found — install for --vuln${NC}"
    command -v subzy  &>/dev/null || echo -e "${YELLOW}[!] subzy not found  — install for --takeover${NC}"
}

usage() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           SubScan v${VERSION} — Usage                        ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BOLD}Syntax:${NC}  subscan <domain> [options]\n"
    echo -e "${BOLD}Options:${NC}"
    printf "  ${CYAN}%-22s${NC} %s\n" "--vuln"          "Step 4: Nuclei vulnerability scan"
    printf "  ${CYAN}%-22s${NC} %s\n" "--takeover"      "Step 5: Subdomain takeover detection"
    printf "  ${CYAN}%-22s${NC} %s\n" "--threads <n>"   "Threads (default: 50)"
    printf "  ${CYAN}%-22s${NC} %s\n" "--output <dir>"  "Custom output directory"
    printf "  ${CYAN}%-22s${NC} %s\n" "--help"          "Show this menu"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ${GREEN}subscan domain.com${NC}"
    echo -e "  ${GREEN}subscan domain.com --vuln${NC}"
    echo -e "  ${GREEN}subscan domain.com --vuln --takeover${NC}"
    echo -e "  ${GREEN}subscan domain.com --threads 100${NC}"
    echo -e "  ${GREEN}subscan domain.com --output /opt/results --vuln${NC}"
    echo ""
    exit 0
}

# ── Args ──────────────────────────────────────────────────────
[[ $# -lt 1 ]] && usage
DOMAIN="$1"; shift
OUTDIR=""; VULN=false; TAKEOVER=false; THREADS=50

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vuln)     VULN=true ;;
        --takeover) TAKEOVER=true ;;
        --threads)  shift; THREADS="$1" ;;
        --output)   shift; OUTDIR="$1" ;;
        --help|-h)  usage ;;
        *) echo -e "${RED}[!] Unknown: $1 — try --help${NC}"; exit 1 ;;
    esac
    shift
done

DATE=$(date +%Y-%m-%d_%H-%M)
OUTDIR="${OUTDIR:-./subscan_${DOMAIN}_${DATE}}"
mkdir -p "$OUTDIR"

SUBFINDER_OUT="$OUTDIR/subfinder.txt"
LIVE_SUBS="$OUTDIR/live_subs.txt"
WEB_SUBS="$OUTDIR/web_subs.txt"
TLS_OUT="$OUTDIR/tls.txt"
NUCLEI_OUT="$OUTDIR/nuclei.txt"
TAKEOVER_OUT="$OUTDIR/takeover.txt"
PRIORITY_OUT="$OUTDIR/priority.txt"
SUMMARY_OUT="$OUTDIR/summary.txt"

for f in "$SUBFINDER_OUT" "$LIVE_SUBS" "$WEB_SUBS" "$TLS_OUT" \
          "$NUCLEI_OUT" "$TAKEOVER_OUT" "$PRIORITY_OUT"; do > "$f"; done

SCAN_START=$(date +%s)
check_deps

# ── Banner ────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          SubScan v${VERSION}                         ║"
echo "║  Step 1 → Subfinder passive OSINT               ║"
echo "║  Step 2 → dnsx live resolution                  ║"
echo "║  Step 3 → httpx + CDN + IP + TLS (parallel)    ║"
[[ "$VULN"     == true ]] && \
echo "║  Step 4 → Nuclei vulnerability scan             ║"
[[ "$TAKEOVER" == true ]] && \
echo "║  Step 5 → Subdomain takeover detection          ║"
echo "╚══════════════════════════════════════════════════╝${NC}"
echo -e "${YELLOW}[*] Domain    : ${DOMAIN}${NC}"
echo -e "${YELLOW}[*] Output    : ${OUTDIR}${NC}"
echo -e "${YELLOW}[*] Threads   : ${THREADS}${NC}"
echo -e "${YELLOW}[*] Vuln      : ${VULN}${NC}"
echo -e "${YELLOW}[*] Takeover  : ${TAKEOVER}${NC}"
echo -e "${YELLOW}[*] Started   : $(date)${NC}\n"

# ════════════════════════════════════════════════════════════
#  STEP 1 — Subfinder
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${GREEN}[+] STEP 1 — Subfinder passive enumeration...${NC}"
echo -e "    ${CYAN}subfinder -d ${DOMAIN} -all -silent${NC}\n"
echo -e "${DIM}─── Live results ────────────────────────────────${NC}"

S1_START=$(date +%s); SUB_COUNT=0

while IFS= read -r sub; do
    [[ -z "$sub" ]] && continue
    SUB_COUNT=$(( SUB_COUNT + 1 ))
    echo -e "  ${GREEN}[+]${NC} ${sub}"
    echo "$sub" >> "$SUBFINDER_OUT"
done < <(subfinder -d "$DOMAIN" -all -silent 2>/dev/null)

S1_END=$(date +%s)
echo -e "${DIM}─────────────────────────────────────────────────${NC}"
echo -e "${BOLD}${GREEN}[✓] STEP 1 DONE — $(elapsed $S1_START $S1_END) | Found: ${SUB_COUNT}${NC}\n"

[[ "$SUB_COUNT" -eq 0 ]] && echo -e "${RED}[!] No subdomains found.${NC}" && exit 0

# ════════════════════════════════════════════════════════════
#  STEP 2 — dnsx
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${BLUE}[+] STEP 2 — Resolving live subdomains...${NC}"
echo -e "    ${CYAN}dnsx -l subfinder.txt -resp -t ${THREADS}${NC}\n"
echo -e "${DIM}─── Live DNS resolution ──────────────────────────${NC}"

S2_START=$(date +%s); LIVE_COUNT=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    sub=$(echo "$line" | awk '{print $1}')
    ip=$(echo "$line"  | grep -oP '\[\K[^\]]+' | head -1)
    LIVE_COUNT=$(( LIVE_COUNT + 1 ))
    printf "  ${BLUE}[+]${NC} %-45s ${DIM}→${NC} ${CYAN}%s${NC}\n" "$sub" "$ip"
    echo "$sub" >> "$LIVE_SUBS"
done < <(dnsx -l "$SUBFINDER_OUT" -resp -t "$THREADS" -silent 2>/dev/null)

S2_END=$(date +%s)
echo -e "${DIM}─────────────────────────────────────────────────${NC}"
echo -e "${BOLD}${BLUE}[✓] STEP 2 DONE — $(elapsed $S2_START $S2_END) | Live: ${LIVE_COUNT}${NC}\n"

[[ ! -s "$LIVE_SUBS" ]] && echo -e "${RED}[!] No live subdomains.${NC}" && exit 0

# ════════════════════════════════════════════════════════════
#  STEP 3 — httpx + TLS in parallel
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${YELLOW}[+] STEP 3 — httpx web detection + TLS probe (parallel)...${NC}"
echo -e "    ${CYAN}httpx -title -status-code -tech-detect -server -ip -cdn -content-length${NC}\n"
echo -e "${DIM}─── Live web detection ───────────────────────────${NC}"
printf "${BOLD}${DIM}  %-38s %-7s %-7s %-18s %-22s %s${NC}\n" \
       "SUBDOMAIN" "STATUS" "SIZE" "SERVER" "TITLE" "CDN/TECH"
echo -e "${DIM}  ─────────────────────────────────────────────────────────────────────────────────${NC}"

S3_START=$(date +%s); WEB_COUNT=0

# TLS probe in background
httpx -l "$LIVE_SUBS" -tls-probe -silent -t "$THREADS" > "$TLS_OUT" 2>/dev/null &
TLS_PID=$!

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    url=$(echo "$line"    | awk '{print $1}')
    status=$(echo "$line" | grep -oP '\[\K[0-9]{3}(?=\])' | head -1)
    size=$(echo "$line"   | grep -oP '\[\K[0-9]+(?=\])' | grep -v '^[1-5][0-9][0-9]$' | head -1)
    server=$(echo "$line" | grep -oP '(?<=\[)[a-zA-Z0-9._/-]+(?=/[^\]]*\])' | head -1)
    title=$(echo "$line"  | grep -oP '(?<=\[title:)[^\]]+' | head -1 | cut -c1-20)
    cdn=$(echo "$line"    | grep -oP '(?<=\[cdn:)[^\]]+' | head -1)
    tech=$(echo "$line"   | grep -oP '(?<=\[)[A-Za-z][^\[\]]{2,20}(?=\])' | tail -1 | cut -c1-20)

    [[ -z "$status" ]] && status="???"
    [[ -z "$size"   ]] && size="—"
    [[ -z "$server" ]] && server="—"
    [[ -z "$title"  ]] && title="—"
    extra="${cdn:-${tech:-—}}"

    case "$status" in
        200|201|204)         sc="${GREEN}${status}${NC}" ;;
        301|302|303|307|308) sc="${YELLOW}${status}${NC}" ;;
        401|403)             sc="${MAGENTA}${status}${NC}" ;;
        500|502|503)         sc="${RED}${status}${NC}" ;;
        *)                   sc="${CYAN}${status}${NC}" ;;
    esac

    [[ -n "$cdn" ]] && extra="${CYAN}[CDN]${NC} ${cdn}"

    WEB_COUNT=$(( WEB_COUNT + 1 ))
    printf "  ${GREEN}%-38s${NC} %-17b %-7s %-18s %-22s %b\n" \
           "$url" "$sc" "$size" "$server" "$title" "$extra"
    echo "$line" >> "$WEB_SUBS"

done < <(httpx -l "$LIVE_SUBS" \
               -title -status-code -tech-detect \
               -server -ip -cdn -content-length \
               -follow-redirects -t "$THREADS" -silent 2>/dev/null)

wait $TLS_PID
S3_END=$(date +%s)
echo -e "${DIM}  ─────────────────────────────────────────────────────────────────────────────────${NC}"
echo -e "${BOLD}${YELLOW}[✓] STEP 3 DONE — $(elapsed $S3_START $S3_END) | Web: ${WEB_COUNT}${NC}\n"

# ════════════════════════════════════════════════════════════
#  STEP 4 — Nuclei (optional)
# ════════════════════════════════════════════════════════════
VULN_COUNT=0
if [[ "$VULN" == true ]]; then
    if ! command -v nuclei &>/dev/null; then
        echo -e "${RED}[!] nuclei not installed.${NC}"
        echo -e "    ${CYAN}go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}\n"
    else
        echo -e "${BOLD}${RED}[+] STEP 4 — Nuclei vulnerability scan...${NC}\n"
        echo -e "${DIM}─── Live vulnerability findings ──────────────────${NC}"
        S4_START=$(date +%s)

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            VULN_COUNT=$(( VULN_COUNT + 1 ))
            if echo "$line" | grep -qi "critical"; then
                echo -e "  ${RED}[CRITICAL]${NC} $line"
            elif echo "$line" | grep -qi "high"; then
                echo -e "  ${RED}[HIGH]${NC} $line"
            elif echo "$line" | grep -qi "medium"; then
                echo -e "  ${YELLOW}[MEDIUM]${NC} $line"
            else
                echo -e "  ${CYAN}[LOW]${NC} $line"
            fi
            echo "$line" >> "$NUCLEI_OUT"
        done < <(nuclei -l "$WEB_SUBS" -severity low,medium,high,critical -silent 2>/dev/null)

        S4_END=$(date +%s)
        echo -e "${DIM}─────────────────────────────────────────────────${NC}"
        echo -e "${BOLD}${RED}[✓] STEP 4 DONE — $(elapsed $S4_START $S4_END) | Findings: ${VULN_COUNT}${NC}\n"
    fi
fi

# ════════════════════════════════════════════════════════════
#  STEP 5 — Takeover Detection (optional)
# ════════════════════════════════════════════════════════════
TAKEOVER_COUNT=0
if [[ "$TAKEOVER" == true ]]; then
    if ! command -v subzy &>/dev/null; then
        echo -e "${RED}[!] subzy not installed.${NC}"
        echo -e "    ${CYAN}go install -v github.com/PentestPad/subzy@latest${NC}\n"
    else
        echo -e "${BOLD}${MAGENTA}[+] STEP 5 — Takeover detection...${NC}\n"
        S5_START=$(date +%s)
        subzy run --targets "$LIVE_SUBS" 2>/dev/null | tee "$TAKEOVER_OUT"
        TAKEOVER_COUNT=$(grep -c "VULNERABLE" "$TAKEOVER_OUT" 2>/dev/null || echo 0)
        S5_END=$(date +%s)
        echo -e "\n${BOLD}${MAGENTA}[✓] STEP 5 DONE — $(elapsed $S5_START $S5_END) | Takeover: ${TAKEOVER_COUNT}${NC}\n"
    fi
fi

# ════════════════════════════════════════════════════════════
#  PRIORITY TARGET DETECTION
# ════════════════════════════════════════════════════════════
PRIORITY_KEYWORDS="admin|dev|test|stage|staging|api|vpn|internal|beta|corp|mgmt|management|portal|remote|citrix|outlook|mail|webmail|ftp|ssh|rdp|jira|gitlab|jenkins|grafana|kibana|elastic|backup|db|database|sql|phpmyadmin"

echo -e "${BOLD}${RED}[+] Priority Target Detection...${NC}"
echo -e "${DIM}─── High-value subdomains ────────────────────────${NC}"
PRIORITY_COUNT=0

while IFS= read -r sub; do
    if echo "$sub" | grep -qEi "$PRIORITY_KEYWORDS"; then
        kw=$(echo "$sub" | grep -oEi "$(echo $PRIORITY_KEYWORDS | tr '|' '\n' | head -1)" | head -1)
        printf "  ${RED}⚠${NC}  %-45s ${YELLOW}[%s]${NC}\n" "$sub" "$kw"
        echo "$sub" >> "$PRIORITY_OUT"
        PRIORITY_COUNT=$(( PRIORITY_COUNT + 1 ))
    fi
done < "$LIVE_SUBS"

[[ "$PRIORITY_COUNT" -eq 0 ]] && echo -e "  ${DIM}No high-value targets detected${NC}"
echo -e "${DIM}─────────────────────────────────────────────────${NC}\n"

# ════════════════════════════════════════════════════════════
#  ALERTING
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${RED}[!] Critical Alerts:${NC}"
echo "────────────────────────────────────────"
ALERT=false

ADMIN_HITS=$(grep -Eic "admin|login|dashboard|portal" "$WEB_SUBS" 2>/dev/null || echo 0)
if [[ "$ADMIN_HITS" -gt 0 ]]; then
    echo -e "  ${RED}⚠  Admin/login panels: ${ADMIN_HITS}${NC}"
    grep -Ei "admin|login|dashboard|portal" "$WEB_SUBS" 2>/dev/null | \
        awk '{print $1}' | head -5 | sed 's/^/      /'
    ALERT=true
fi

API_HITS=$(grep -c "api\." "$WEB_SUBS" 2>/dev/null || echo 0)
[[ "$API_HITS" -gt 0 ]] && \
    echo -e "  ${YELLOW}⚠  API endpoints: ${API_HITS}${NC}" && ALERT=true

DEV_HITS=$(grep -Eic "dev\.|staging\.|test\.|beta\." "$WEB_SUBS" 2>/dev/null || echo 0)
[[ "$DEV_HITS" -gt 0 ]] && \
    echo -e "  ${YELLOW}⚠  Dev/staging exposed: ${DEV_HITS}${NC}" && ALERT=true

if [[ -s "$NUCLEI_OUT" ]]; then
    CRIT=$(grep -ci "critical" "$NUCLEI_OUT" 2>/dev/null || echo 0)
    HIGH=$(grep -ci "high"     "$NUCLEI_OUT" 2>/dev/null || echo 0)
    [[ "$CRIT" -gt 0 ]] && echo -e "  ${RED}⚠  CRITICAL: ${CRIT}${NC}" && ALERT=true
    [[ "$HIGH"  -gt 0 ]] && echo -e "  ${RED}⚠  HIGH: ${HIGH}${NC}"     && ALERT=true
fi

[[ -s "$TAKEOVER_OUT" ]] && \
    T=$(grep -c "VULNERABLE" "$TAKEOVER_OUT" 2>/dev/null || echo 0) && \
    [[ "$T" -gt 0 ]] && echo -e "  ${RED}⚠  Takeover candidates: ${T}${NC}" && ALERT=true

[[ "$ALERT" == false ]] && echo -e "  ${GREEN}No critical alerts${NC}"
echo ""

# ════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ════════════════════════════════════════════════════════════
SCAN_END=$(date +%s)

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                       FINAL SUMMARY                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════╝${NC}"

if [[ -s "$WEB_SUBS" ]]; then
    echo -e "${BOLD}Status Breakdown:${NC}"
    grep -oP '\[\K[0-9]{3}(?=\])' "$WEB_SUBS" | sort | uniq -c | sort -rn | \
    while read -r count code; do
        case "$code" in
            200|201|204) color=$GREEN ;;
            301|302|303|307|308) color=$YELLOW ;;
            401|403) color=$MAGENTA ;;
            500|502|503) color=$RED ;;
            *) color=$CYAN ;;
        esac
        printf "  ${color}HTTP %-5s${NC} → %s\n" "$code" "$count"
    done
    echo ""
    echo -e "${BOLD}Top Technologies:${NC}"
    grep -oP '\[[A-Za-z][^\[\]]{2,25}\]' "$WEB_SUBS" \
    | tr -d '[]' | sort | uniq -c | sort -rn | head -8 | \
    while read -r count tech; do
        printf "  ${CYAN}%-25s${NC} %s\n" "$tech" "$count"
    done
    echo ""
fi

TLS_COUNT=$(wc -l < "$TLS_OUT" 2>/dev/null || echo 0)
CDN_COUNT=$(grep -c "cdn:" "$WEB_SUBS" 2>/dev/null || echo 0)
[[ "$CDN_COUNT" -gt 0 ]] && echo -e "${CYAN}[*] CDN-protected : ${CDN_COUNT}${NC}"
[[ "$TLS_COUNT" -gt 0 ]] && echo -e "${CYAN}[*] TLS-enabled   : ${TLS_COUNT}${NC}"
echo ""

{
    echo "=== SubScan — ${DOMAIN} === $(date)"
    echo "Subdomains : ${SUB_COUNT} | Live: ${LIVE_COUNT} | Web: ${WEB_COUNT} | Priority: ${PRIORITY_COUNT}"
    [[ "$VULN"     == true ]] && echo "Vulns      : ${VULN_COUNT}"
    [[ "$TAKEOVER" == true ]] && echo "Takeover   : ${TAKEOVER_COUNT}"
    echo ""; echo "=== Priority ==="; cat "$PRIORITY_OUT" 2>/dev/null
    echo ""; echo "=== Web Servers ==="; cat "$WEB_SUBS" 2>/dev/null
    echo ""; echo "=== Live Subs ==="; cat "$LIVE_SUBS" 2>/dev/null
} > "$SUMMARY_OUT"

echo -e "${GREEN}[✓] Subdomains   : ${SUB_COUNT}${NC}"
echo -e "${BLUE}[✓] Live         : ${LIVE_COUNT}${NC}"
echo -e "${YELLOW}[✓] Web servers  : ${WEB_COUNT}${NC}"
echo -e "${RED}[✓] Priority     : ${PRIORITY_COUNT}${NC}"
[[ "$VULN"     == true ]] && echo -e "${RED}[✓] Vulns        : ${VULN_COUNT}${NC}"
[[ "$TAKEOVER" == true ]] && echo -e "${MAGENTA}[✓] Takeover     : ${TAKEOVER_COUNT}${NC}"
echo -e "${GREEN}[✓] Total time   : $(elapsed $SCAN_START $SCAN_END)${NC}"
echo -e "${GREEN}[✓] Output       : ${OUTDIR}${NC}"
echo ""
echo -e "${BOLD}Status Legend:${NC}"
echo -e "  ${GREEN}200${NC} Live  ${YELLOW}30x${NC} Redirect  ${MAGENTA}401/403${NC} Forbidden  ${RED}5xx${NC} Error"
echo ""
