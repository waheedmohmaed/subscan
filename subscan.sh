#!/bin/bash
# ============================================================
#  subscan.sh — Subdomain Scanner v1.0
#  Step 1 : Subfinder  — passive OSINT enumeration
#  Step 2 : ffuf       — DNS brute-force (optional --brute)
#  Step 3 : dnsx       — resolve live subdomains
#  Step 4 : httpx      — detect live web servers
#  Output : color-coded live table + saved files
# ============================================================

VERSION="1.0"

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Status code color ─────────────────────────────────────────
color_status() {
    local code="$1"
    case "$code" in
        200) echo -e "${GREEN}${code}${NC}" ;;
        201|204) echo -e "${GREEN}${code}${NC}" ;;
        301|302|303|307|308) echo -e "${YELLOW}${code}${NC}" ;;
        401|403) echo -e "${MAGENTA}${code}${NC}" ;;
        404) echo -e "${DIM}${code}${NC}" ;;
        500|502|503) echo -e "${RED}${code}${NC}" ;;
        *) echo -e "${CYAN}${code}${NC}" ;;
    esac
}

elapsed() {
    local secs=$(( $2 - $1 ))
    printf "%dm %ds" $(( secs/60 )) $(( secs%60 ))
}

# ── Dependency check ──────────────────────────────────────────
check_deps() {
    local missing=()
    for tool in subfinder dnsx httpx; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[!] Missing tools: ${missing[*]}${NC}"
        echo -e "${YELLOW}Install with:${NC}"
        echo ""
        echo "  # Install Go first if needed:"
        echo "  sudo apt install golang-go"
        echo ""
        echo "  # Then install tools:"
        echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo "  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo ""
        echo "  # Add Go bin to PATH:"
        echo "  echo 'export PATH=\$PATH:\$(go env GOPATH)/bin' >> ~/.bashrc"
        echo "  source ~/.bashrc"
        echo ""
        exit 1
    fi
}

# ════════════════════════════════════════════════════════════
#  USAGE
# ════════════════════════════════════════════════════════════
usage() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           SubScan v${VERSION} — Usage                        ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BOLD}Syntax:${NC}"
    echo -e "  subscan <domain> [output-dir] [options]\n"
    echo -e "${BOLD}Options:${NC}"
    printf "  ${CYAN}%-16s${NC} %s\n" "--brute"   "DNS brute-force with ffuf (wordlist required)"
    printf "  ${CYAN}%-16s${NC} %s\n" "--wordlist" "Custom wordlist path for brute-force"
    printf "  ${CYAN}%-16s${NC} %s\n" "--threads"  "Number of threads (default: 50)"
    printf "  ${CYAN}%-16s${NC} %s\n" "--help"     "Show this help menu"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ${GREEN}subscan domain.com${NC}"
    echo -e "    → Passive subfinder + resolve + web check\n"
    echo -e "  ${GREEN}subscan domain.com --brute${NC}"
    echo -e "    → Passive + DNS brute-force with default wordlist\n"
    echo -e "  ${GREEN}subscan domain.com /opt/results --brute${NC}"
    echo -e "    → Custom output folder + brute-force\n"
    echo -e "  ${GREEN}subscan domain.com --brute --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt${NC}"
    echo -e "    → Custom wordlist brute-force\n"
    echo -e "  ${GREEN}subscan domain.com --threads 100${NC}"
    echo -e "    → Faster scan with 100 threads\n"
    echo -e "${BOLD}Output files:${NC}"
    printf "  ${CYAN}%-30s${NC} %s\n" "subfinder.txt"    "Raw subfinder results"
    printf "  ${CYAN}%-30s${NC} %s\n" "brute.txt"        "ffuf brute-force results (--brute)"
    printf "  ${CYAN}%-30s${NC} %s\n" "all_subs.txt"     "All subdomains merged + deduped"
    printf "  ${CYAN}%-30s${NC} %s\n" "live_subs.txt"    "Resolved live subdomains (dnsx)"
    printf "  ${CYAN}%-30s${NC} %s\n" "web_subs.txt"     "Live web servers (httpx)"
    printf "  ${CYAN}%-30s${NC} %s\n" "summary.txt"      "Final color-stripped summary table"
    echo ""
    exit 0
}

# ════════════════════════════════════════════════════════════
#  ARGUMENT PARSING
# ════════════════════════════════════════════════════════════
[[ $# -lt 1 ]] && usage

DOMAIN=""
OUTDIR=""
BRUTE=false
THREADS=50
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

i=1
while [[ $i -le $# ]]; do
    arg="${!i}"
    case "$arg" in
        --brute)    BRUTE=true ;;
        --help|-h)  usage ;;
        --threads)  i=$(( i+1 )); THREADS="${!i}" ;;
        --wordlist) i=$(( i+1 )); WORDLIST="${!i}" ;;
        *)
            if [[ -z "$DOMAIN" ]]; then DOMAIN="$arg"
            elif [[ -z "$OUTDIR" ]]; then OUTDIR="$arg"
            fi ;;
    esac
    i=$(( i+1 ))
done

[[ -z "$DOMAIN" ]] && usage

DATE=$(date +%Y-%m-%d_%H-%M)
OUTDIR="${OUTDIR:-./subscan_${DOMAIN}_${DATE}}"
mkdir -p "$OUTDIR"

SUBFINDER_OUT="$OUTDIR/subfinder.txt"
BRUTE_OUT="$OUTDIR/brute.txt"
ALL_SUBS="$OUTDIR/all_subs.txt"
LIVE_SUBS="$OUTDIR/live_subs.txt"
WEB_SUBS="$OUTDIR/web_subs.txt"
SUMMARY_OUT="$OUTDIR/summary.txt"

SCAN_START=$(date +%s)

# ── Check dependencies ────────────────────────────────────────
check_deps

# ── Banner ────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          SubScan v${VERSION}                          ║"
echo "║  Step 1 → Subfinder passive OSINT               ║"
[[ "$BRUTE" == true ]] && \
echo "║  Step 2 → ffuf DNS brute-force                  ║"
echo "║  Step 3 → dnsx live resolution                  ║"
echo "║  Step 4 → httpx web server detection            ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${YELLOW}[*] Domain   : ${DOMAIN}${NC}"
echo -e "${YELLOW}[*] Output   : ${OUTDIR}${NC}"
echo -e "${YELLOW}[*] Threads  : ${THREADS}${NC}"
echo -e "${YELLOW}[*] Brute    : ${BRUTE}${NC}"
echo -e "${YELLOW}[*] Started  : $(date)${NC}"
echo ""

# ════════════════════════════════════════════════════════════
#  STEP 1 — Subfinder Passive Enumeration (LIVE OUTPUT)
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${GREEN}[+] STEP 1 — Subfinder passive enumeration...${NC}"
echo -e "    ${CYAN}subfinder -d ${DOMAIN} -all -silent${NC}\n"

S1_START=$(date +%s)
SUB_COUNT=0

# Live output — print each subdomain as it's found
echo -e "${DIM}─── Live results ────────────────────────────────${NC}"

while IFS= read -r sub; do
    [[ -z "$sub" ]] && continue
    SUB_COUNT=$(( SUB_COUNT + 1 ))
    echo -e "  ${GREEN}[+]${NC} ${sub}"
    echo "$sub" >> "$SUBFINDER_OUT"
done < <(subfinder -d "$DOMAIN" -all -silent 2>/dev/null)

S1_END=$(date +%s)

echo -e "${DIM}─────────────────────────────────────────────────${NC}"
echo ""
echo -e "${BOLD}${GREEN}[✓] STEP 1 DONE — $(elapsed $S1_START $S1_END) | Found: ${SUB_COUNT} subdomains${NC}\n"

# ════════════════════════════════════════════════════════════
#  STEP 2 — ffuf DNS Brute-Force (optional, LIVE OUTPUT)
# ════════════════════════════════════════════════════════════
if [[ "$BRUTE" == true ]]; then
    if [[ ! -f "$WORDLIST" ]]; then
        echo -e "${RED}[!] Wordlist not found: ${WORDLIST}${NC}"
        echo -e "    Install SecLists: ${CYAN}sudo apt install seclists${NC}\n"
    else
        echo -e "${BOLD}${MAGENTA}[+] STEP 2 — ffuf DNS brute-force...${NC}"
        echo -e "    ${CYAN}ffuf -u https://FUZZ.${DOMAIN} -w ${WORDLIST} -t ${THREADS}${NC}\n"

        WORDLIST_SIZE=$(wc -l < "$WORDLIST")
        echo -e "${DIM}─── Brute-force live results (${WORDLIST_SIZE} words) ─────${NC}"

        S2_START=$(date +%s)
        BRUTE_COUNT=0

        # Run ffuf and parse live JSON output line by line
        ffuf -u "https://FUZZ.${DOMAIN}" \
             -w "$WORDLIST" \
             -t "$THREADS" \
             -mc 200,201,301,302,303,307,308,401,403 \
             -p 0.1 \
             -k \
             -of json \
             -o "$OUTDIR/ffuf_raw.json" \
             -s 2>/dev/null \
        | while IFS= read -r line; do
            sub=$(echo "$line" | grep -oP '"input":\{"FUZZ":"[^"]*"' | grep -oP '(?<=FUZZ":")[^"]*')
            [[ -z "$sub" ]] && continue
            BRUTE_COUNT=$(( BRUTE_COUNT + 1 ))
            echo -e "  ${MAGENTA}[+]${NC} ${sub}.${DOMAIN}"
            echo "${sub}.${DOMAIN}" >> "$BRUTE_OUT"
        done

        # Also parse the saved JSON for clean extraction
        if [[ -f "$OUTDIR/ffuf_raw.json" ]]; then
            python3 -c "
import json,sys
try:
    data=json.load(open('$OUTDIR/ffuf_raw.json'))
    for r in data.get('results',[]):
        print(r['input']['FUZZ']+'.$DOMAIN')
except: pass
" 2>/dev/null >> "$BRUTE_OUT"
        fi

        # Dedup brute file
        [[ -f "$BRUTE_OUT" ]] && sort -u "$BRUTE_OUT" -o "$BRUTE_OUT"
        BRUTE_COUNT=$(wc -l < "$BRUTE_OUT" 2>/dev/null || echo 0)

        S2_END=$(date +%s)
        echo -e "${DIM}─────────────────────────────────────────────────${NC}"
        echo ""
        echo -e "${BOLD}${MAGENTA}[✓] STEP 2 DONE — $(elapsed $S2_START $S2_END) | Found: ${BRUTE_COUNT} via brute-force${NC}\n"
    fi
fi

# ── Merge + deduplicate all sources ──────────────────────────
echo -e "${CYAN}[*] Merging and deduplicating results...${NC}"
cat "$SUBFINDER_OUT" "$BRUTE_OUT" 2>/dev/null | sort -u > "$ALL_SUBS"
TOTAL=$(wc -l < "$ALL_SUBS")
echo -e "${GREEN}[✓] Total unique subdomains: ${BOLD}${TOTAL}${NC}\n"

# ════════════════════════════════════════════════════════════
#  STEP 3 — dnsx Live Resolution (LIVE OUTPUT)
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${BLUE}[+] STEP 3 — Resolving live subdomains with dnsx...${NC}"
echo -e "    ${CYAN}dnsx -l ${ALL_SUBS} -resp -t ${THREADS}${NC}\n"

echo -e "${DIM}─── Live DNS resolution ──────────────────────────${NC}"

S3_START=$(date +%s)
LIVE_COUNT=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    sub=$(echo "$line" | awk '{print $1}')
    ip=$(echo "$line" | grep -oP '\[\K[^\]]+' | head -1)
    LIVE_COUNT=$(( LIVE_COUNT + 1 ))
    printf "  ${BLUE}[+]${NC} %-45s ${DIM}→${NC} ${CYAN}%s${NC}\n" "$sub" "$ip"
    echo "$sub" >> "$LIVE_SUBS"
done < <(dnsx -l "$ALL_SUBS" -resp -t "$THREADS" -silent 2>/dev/null)

S3_END=$(date +%s)

echo -e "${DIM}─────────────────────────────────────────────────${NC}"
echo ""
echo -e "${BOLD}${BLUE}[✓] STEP 3 DONE — $(elapsed $S3_START $S3_END) | Live: ${LIVE_COUNT} subdomains${NC}\n"

if [[ ! -s "$LIVE_SUBS" ]]; then
    echo -e "${RED}[!] No live subdomains resolved. Check domain or DNS.${NC}"
    exit 0
fi

# ════════════════════════════════════════════════════════════
#  STEP 4 — httpx Web Server Detection (LIVE OUTPUT)
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${YELLOW}[+] STEP 4 — Detecting web servers with httpx...${NC}"
echo -e "    ${CYAN}httpx -l ${LIVE_SUBS} -title -status-code -tech-detect -t ${THREADS}${NC}\n"

echo -e "${DIM}─── Live web detection ───────────────────────────${NC}"
printf "${BOLD}${DIM}  %-45s %-8s %-30s %s${NC}\n" "SUBDOMAIN" "STATUS" "TITLE" "TECH"
echo -e "${DIM}  ──────────────────────────────────────────────────────────────────────────────${NC}"

S4_START=$(date +%s)
WEB_COUNT=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    url=$(echo "$line"   | awk '{print $1}')
    status=$(echo "$line" | grep -oP '\[\K[0-9]{3}(?=\])' | head -1)
    title=$(echo "$line"  | grep -oP '\[title:\K[^\]]+' | head -1 | cut -c1-28)
    tech=$(echo "$line"   | grep -oP '\[tech:\K[^\]]+' | head -1 | cut -c1-30)

    [[ -z "$status" ]] && status="???"
    [[ -z "$title"  ]] && title="—"
    [[ -z "$tech"   ]] && tech="—"

    # Color status
    case "$status" in
        200|201|204)         sc="${GREEN}${status}${NC}" ;;
        301|302|303|307|308) sc="${YELLOW}${status}${NC}" ;;
        401|403)             sc="${MAGENTA}${status}${NC}" ;;
        500|502|503)         sc="${RED}${status}${NC}" ;;
        *)                   sc="${CYAN}${status}${NC}" ;;
    esac

    WEB_COUNT=$(( WEB_COUNT + 1 ))
    printf "  ${GREEN}%-45s${NC} %-8b %-30s ${DIM}%s${NC}\n" "$url" "$sc" "$title" "$tech"
    echo "$line" >> "$WEB_SUBS"

done < <(httpx -l "$LIVE_SUBS" \
               -title \
               -status-code \
               -tech-detect \
               -follow-redirects \
               -t "$THREADS" \
               -silent 2>/dev/null)

S4_END=$(date +%s)

echo -e "${DIM}  ──────────────────────────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "${BOLD}${YELLOW}[✓] STEP 4 DONE — $(elapsed $S4_START $S4_END) | Web servers: ${WEB_COUNT}${NC}\n"

# ════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ════════════════════════════════════════════════════════════
SCAN_END=$(date +%s)

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                       FINAL SUMMARY                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Status code breakdown
echo -e "${BOLD}Status Code Breakdown:${NC}"
if [[ -s "$WEB_SUBS" ]]; then
    grep -oP '\[\K[0-9]{3}(?=\])' "$WEB_SUBS" | sort | uniq -c | sort -rn | \
    while read -r count code; do
        case "$code" in
            200|201|204)         color=$GREEN ;;
            301|302|303|307|308) color=$YELLOW ;;
            401|403)             color=$MAGENTA ;;
            500|502|503)         color=$RED ;;
            *)                   color=$CYAN ;;
        esac
        printf "  ${color}HTTP %-5s${NC} → %s results\n" "$code" "$count"
    done
fi

echo ""

# Save plain summary (no color codes) for file
{
    echo "=== SubScan Summary — ${DOMAIN} ==="
    echo "Date       : $(date)"
    echo "Domain     : ${DOMAIN}"
    echo ""
    echo "Total subdomains found : ${TOTAL}"
    echo "Live subdomains        : ${LIVE_COUNT}"
    echo "Web servers found      : ${WEB_COUNT}"
    echo ""
    echo "=== Web Servers ==="
    cat "$WEB_SUBS" 2>/dev/null
    echo ""
    echo "=== All Live Subdomains ==="
    cat "$LIVE_SUBS" 2>/dev/null
} > "$SUMMARY_OUT"

echo -e "${GREEN}[✓] Domain          : ${DOMAIN}${NC}"
echo -e "${GREEN}[✓] Total found     : ${TOTAL}${NC}"
echo -e "${BLUE}[✓] Live subs       : ${LIVE_COUNT}${NC}"
echo -e "${YELLOW}[✓] Web servers     : ${WEB_COUNT}${NC}"
echo -e "${GREEN}[✓] Total time      : $(elapsed $SCAN_START $SCAN_END)${NC}"
echo ""
echo -e "${YELLOW}[*] Output files:${NC}"
printf "  ${CYAN}%-14s${NC} %s\n" "subfinder.txt" "$SUBFINDER_OUT"
[[ "$BRUTE" == true ]] && \
printf "  ${CYAN}%-14s${NC} %s\n" "brute.txt"     "$BRUTE_OUT"
printf "  ${CYAN}%-14s${NC} %s\n" "all_subs.txt"  "$ALL_SUBS"
printf "  ${CYAN}%-14s${NC} %s\n" "live_subs.txt" "$LIVE_SUBS"
printf "  ${CYAN}%-14s${NC} %s\n" "web_subs.txt"  "$WEB_SUBS"
printf "  ${CYAN}%-14s${NC} %s\n" "summary.txt"   "$SUMMARY_OUT"
echo ""
echo -e "${BOLD}Status Legend:${NC}"
echo -e "  ${GREEN}200${NC}  Live and accessible"
echo -e "  ${YELLOW}30x${NC}  Redirect"
echo -e "  ${MAGENTA}401/403${NC}  Auth required / Forbidden"
echo -e "  ${RED}5xx${NC}  Server error"
echo ""
