#!/bin/bash
# ============================================================
#  subscan.sh — Subdomain Scanner v1.1
#  Step 1 : Subfinder  — passive OSINT enumeration
#  Step 2 : ffuf       — DNS brute-force (--brute)
#  Step 3 : dnsx       — resolve live subdomains
#  Step 4 : httpx      — detect live web servers
#  Fix    : argument parser rewritten — no more dir conflicts
# ============================================================

VERSION="1.1"

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
        echo -e "${YELLOW}Install:${NC}"
        echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo "  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo "  echo 'export PATH=\$PATH:\$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc"
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
    echo -e "  subscan <domain> [options]\n"
    echo -e "${BOLD}Options:${NC}"
    printf "  ${CYAN}%-20s${NC} %s\n" "--brute"          "DNS brute-force with ffuf"
    printf "  ${CYAN}%-20s${NC} %s\n" "--wordlist <path>" "Custom wordlist (default: seclists top-5000)"
    printf "  ${CYAN}%-20s${NC} %s\n" "--threads <n>"    "Threads (default: 50)"
    printf "  ${CYAN}%-20s${NC} %s\n" "--output <dir>"   "Custom output directory"
    printf "  ${CYAN}%-20s${NC} %s\n" "--help"           "Show this menu"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ${GREEN}subscan domain.com${NC}"
    echo -e "  ${GREEN}subscan domain.com --brute${NC}"
    echo -e "  ${GREEN}subscan domain.com --brute --threads 100${NC}"
    echo -e "  ${GREEN}subscan domain.com --output /opt/results${NC}"
    echo -e "  ${GREEN}subscan domain.com --brute --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt${NC}"
    echo ""
    exit 0
}

# ════════════════════════════════════════════════════════════
#  ARGUMENT PARSING — fixed, flag-based only
# ════════════════════════════════════════════════════════════
[[ $# -lt 1 ]] && usage

DOMAIN=""
OUTDIR=""
BRUTE=false
THREADS=50
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

# First positional arg = domain
DOMAIN="$1"
shift

# Parse remaining flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --brute)    BRUTE=true ;;
        --help|-h)  usage ;;
        --threads)  shift; THREADS="$1" ;;
        --wordlist) shift; WORDLIST="$1" ;;
        --output)   shift; OUTDIR="$1" ;;
        *)
            echo -e "${RED}[!] Unknown option: $1${NC}"
            echo -e "    Use ${CYAN}subscan --help${NC} for usage."
            exit 1
            ;;
    esac
    shift
done

# ── Validate domain ───────────────────────────────────────────
if [[ -z "$DOMAIN" ]]; then
    echo -e "${RED}[!] No domain specified.${NC}"
    usage
fi

DATE=$(date +%Y-%m-%d_%H-%M)
OUTDIR="${OUTDIR:-./subscan_${DOMAIN}_${DATE}}"
mkdir -p "$OUTDIR"

SUBFINDER_OUT="$OUTDIR/subfinder.txt"
BRUTE_OUT="$OUTDIR/brute.txt"
ALL_SUBS="$OUTDIR/all_subs.txt"
LIVE_SUBS="$OUTDIR/live_subs.txt"
WEB_SUBS="$OUTDIR/web_subs.txt"
SUMMARY_OUT="$OUTDIR/summary.txt"

# Clear output files
> "$SUBFINDER_OUT"
> "$ALL_SUBS"
> "$LIVE_SUBS"
> "$WEB_SUBS"

SCAN_START=$(date +%s)

# ── Check deps ────────────────────────────────────────────────
check_deps

# ── Banner ────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          SubScan v${VERSION}                         ║"
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
#  STEP 1 — Subfinder Passive Enumeration
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${GREEN}[+] STEP 1 — Subfinder passive enumeration...${NC}"
echo -e "    ${CYAN}subfinder -d ${DOMAIN} -all -silent${NC}\n"

S1_START=$(date +%s)
SUB_COUNT=0

echo -e "${DIM}─── Live results ────────────────────────────────${NC}"

while IFS= read -r sub; do
    [[ -z "$sub" ]] && continue
    SUB_COUNT=$(( SUB_COUNT + 1 ))
    echo -e "  ${GREEN}[+]${NC} ${sub}"
    echo "$sub" >> "$SUBFINDER_OUT"
done < <(subfinder -d "$DOMAIN" -all -silent 2>/dev/null)

S1_END=$(date +%s)
echo -e "${DIM}─────────────────────────────────────────────────${NC}\n"
echo -e "${BOLD}${GREEN}[✓] STEP 1 DONE — $(elapsed $S1_START $S1_END) | Found: ${SUB_COUNT} subdomains${NC}\n"

# ════════════════════════════════════════════════════════════
#  STEP 2 — ffuf DNS Brute-Force (optional)
# ════════════════════════════════════════════════════════════
if [[ "$BRUTE" == true ]]; then
    if [[ ! -f "$WORDLIST" ]]; then
        echo -e "${RED}[!] Wordlist not found: ${WORDLIST}${NC}"
        echo -e "    Install: ${CYAN}sudo apt install seclists${NC}\n"
    else
        WORDLIST_SIZE=$(wc -l < "$WORDLIST")
        echo -e "${BOLD}${MAGENTA}[+] STEP 2 — ffuf DNS brute-force (${WORDLIST_SIZE} words)...${NC}"
        echo -e "    ${CYAN}ffuf -u https://FUZZ.${DOMAIN} -w ${WORDLIST} -t ${THREADS}${NC}\n"
        echo -e "${DIM}─── Brute-force live results ─────────────────────${NC}"

        > "$BRUTE_OUT"
        S2_START=$(date +%s)

        ffuf -u "https://FUZZ.${DOMAIN}" \
             -w "$WORDLIST" \
             -t "$THREADS" \
             -mc 200,201,301,302,303,307,308,401,403 \
             -p 0.1 \
             -k \
             -s 2>/dev/null \
        | while IFS= read -r word; do
            [[ -z "$word" ]] && continue
            echo -e "  ${MAGENTA}[+]${NC} ${word}.${DOMAIN}"
            echo "${word}.${DOMAIN}" >> "$BRUTE_OUT"
        done

        sort -u "$BRUTE_OUT" -o "$BRUTE_OUT" 2>/dev/null
        BRUTE_COUNT=$(wc -l < "$BRUTE_OUT" 2>/dev/null || echo 0)
        S2_END=$(date +%s)

        echo -e "${DIM}─────────────────────────────────────────────────${NC}\n"
        echo -e "${BOLD}${MAGENTA}[✓] STEP 2 DONE — $(elapsed $S2_START $S2_END) | Found: ${BRUTE_COUNT} via brute-force${NC}\n"
    fi
fi

# ── Merge + deduplicate ───────────────────────────────────────
echo -e "${CYAN}[*] Merging and deduplicating all sources...${NC}"
cat "$SUBFINDER_OUT" "$BRUTE_OUT" 2>/dev/null | sort -u > "$ALL_SUBS"
TOTAL=$(wc -l < "$ALL_SUBS")
echo -e "${GREEN}[✓] Total unique subdomains: ${BOLD}${TOTAL}${NC}\n"

if [[ "$TOTAL" -eq 0 ]]; then
    echo -e "${RED}[!] No subdomains found for ${DOMAIN}.${NC}"
    exit 0
fi

# ════════════════════════════════════════════════════════════
#  STEP 3 — dnsx Live Resolution
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${BLUE}[+] STEP 3 — Resolving live subdomains with dnsx...${NC}"
echo -e "    ${CYAN}dnsx -l ${ALL_SUBS} -resp -t ${THREADS}${NC}\n"
echo -e "${DIM}─── Live DNS resolution ──────────────────────────${NC}"

S3_START=$(date +%s)
LIVE_COUNT=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    sub=$(echo "$line" | awk '{print $1}')
    ip=$(echo "$line"  | grep -oP '\[\K[^\]]+' | head -1)
    LIVE_COUNT=$(( LIVE_COUNT + 1 ))
    printf "  ${BLUE}[+]${NC} %-45s ${DIM}→${NC} ${CYAN}%s${NC}\n" "$sub" "$ip"
    echo "$sub" >> "$LIVE_SUBS"
done < <(dnsx -l "$ALL_SUBS" -resp -t "$THREADS" -silent 2>/dev/null)

S3_END=$(date +%s)
echo -e "${DIM}─────────────────────────────────────────────────${NC}\n"
echo -e "${BOLD}${BLUE}[✓] STEP 3 DONE — $(elapsed $S3_START $S3_END) | Live: ${LIVE_COUNT} subdomains${NC}\n"

if [[ ! -s "$LIVE_SUBS" ]]; then
    echo -e "${RED}[!] No live subdomains resolved.${NC}"
    exit 0
fi

# ════════════════════════════════════════════════════════════
#  STEP 4 — httpx Web Server Detection
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${YELLOW}[+] STEP 4 — Detecting web servers with httpx...${NC}"
echo -e "    ${CYAN}httpx -l ${LIVE_SUBS} -title -status-code -tech-detect -t ${THREADS}${NC}\n"
echo -e "${DIM}─── Live web detection ───────────────────────────${NC}"
printf "${BOLD}${DIM}  %-45s %-8s %-30s %s${NC}\n" "SUBDOMAIN" "STATUS" "TITLE" "TECH"
echo -e "${DIM}  ────────────────────────────────────────────────────────────────────────────${NC}"

S4_START=$(date +%s)
WEB_COUNT=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    url=$(echo "$line"    | awk '{print $1}')
    status=$(echo "$line" | grep -oP '\[\K[0-9]{3}(?=\])' | head -1)
    title=$(echo "$line"  | grep -oP '(?<=\[)[^\[\]]{1,50}(?=\])' | grep -v '^[0-9]' | head -1 | cut -c1-28)
    tech=$(echo "$line"   | grep -oP '(?<=\[)[^\[\]]+(?=\])' | tail -1 | cut -c1-30)

    [[ -z "$status" ]] && status="???"
    [[ -z "$title"  ]] && title="—"
    [[ "$title" == "$status" ]] && title="—"

    case "$status" in
        200|201|204)         sc="${GREEN}${status}${NC}" ;;
        301|302|303|307|308) sc="${YELLOW}${status}${NC}" ;;
        401|403)             sc="${MAGENTA}${status}${NC}" ;;
        500|502|503)         sc="${RED}${status}${NC}" ;;
        *)                   sc="${CYAN}${status}${NC}" ;;
    esac

    WEB_COUNT=$(( WEB_COUNT + 1 ))
    printf "  ${GREEN}%-45s${NC} %-18b %-30s ${DIM}%s${NC}\n" "$url" "$sc" "$title" "$tech"
    echo "$line" >> "$WEB_SUBS"

done < <(httpx -l "$LIVE_SUBS" \
               -title \
               -status-code \
               -tech-detect \
               -follow-redirects \
               -t "$THREADS" \
               -silent 2>/dev/null)

S4_END=$(date +%s)
echo -e "${DIM}  ────────────────────────────────────────────────────────────────────────────${NC}\n"
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

if [[ -s "$WEB_SUBS" ]]; then
    echo -e "${BOLD}Status Code Breakdown:${NC}"
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
    echo ""
fi

# Save plain summary
{
    echo "=== SubScan Summary — ${DOMAIN} ==="
    echo "Date       : $(date)"
    echo "Domain     : ${DOMAIN}"
    echo ""
    echo "Total subdomains : ${TOTAL}"
    echo "Live subdomains  : ${LIVE_COUNT}"
    echo "Web servers      : ${WEB_COUNT}"
    echo ""
    echo "=== Web Servers ==="
    cat "$WEB_SUBS" 2>/dev/null
    echo ""
    echo "=== All Live Subdomains ==="
    cat "$LIVE_SUBS" 2>/dev/null
} > "$SUMMARY_OUT"

echo -e "${GREEN}[✓] Domain       : ${DOMAIN}${NC}"
echo -e "${GREEN}[✓] Total found  : ${TOTAL}${NC}"
echo -e "${BLUE}[✓] Live subs    : ${LIVE_COUNT}${NC}"
echo -e "${YELLOW}[✓] Web servers  : ${WEB_COUNT}${NC}"
echo -e "${GREEN}[✓] Total time   : $(elapsed $SCAN_START $SCAN_END)${NC}"
echo ""
echo -e "${YELLOW}[*] Output files:${NC}"
printf "  ${CYAN}%-18s${NC} %s\n" "subfinder.txt"  "$SUBFINDER_OUT"
[[ "$BRUTE" == true ]] && \
printf "  ${CYAN}%-18s${NC} %s\n" "brute.txt"      "$BRUTE_OUT"
printf "  ${CYAN}%-18s${NC} %s\n" "all_subs.txt"   "$ALL_SUBS"
printf "  ${CYAN}%-18s${NC} %s\n" "live_subs.txt"  "$LIVE_SUBS"
printf "  ${CYAN}%-18s${NC} %s\n" "web_subs.txt"   "$WEB_SUBS"
printf "  ${CYAN}%-18s${NC} %s\n" "summary.txt"    "$SUMMARY_OUT"
echo ""
echo -e "${BOLD}Status Legend:${NC}"
echo -e "  ${GREEN}200${NC}      Live and accessible"
echo -e "  ${YELLOW}30x${NC}      Redirect"
echo -e "  ${MAGENTA}401/403${NC}  Auth required / Forbidden"
echo -e "  ${RED}5xx${NC}      Server error"
echo ""
