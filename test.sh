#!/usr/bin/env bash
set -euo pipefail

# -- Settings --
TEST_TIMEOUT=30   # seconds per test (must exceed TLS_READ_TIMEOUT_S in tls_client.c)
MAX_FAILURES=10   # bail early after this many failures in pass tests
SAMPLE_SIZE=0     # 0 = run all; >0 = random sample of N pass tests
SECTIONS=""       # comma-separated: compile,static,pass,xfail,local (empty = all)

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n) SAMPLE_SIZE="$2"; shift 2 ;;
        -s) SECTIONS="$2"; shift 2 ;;
        *)  echo "Usage: $0 [-n sample_size] [-s sections]" >&2
            echo "  sections: compile,static,pass,xfail,local (default: all)" >&2
            exit 1 ;;
    esac
done

# Section helpers
run_section() {
    [[ -z "$SECTIONS" ]] && return 0
    [[ ",$SECTIONS," == *",$1,"* ]]
}

# -- Colors --
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
BLD='\033[1m'
RST='\033[0m'

pass=0
fail=0
xfail=0
xfail_unexpected_pass=0
failures=()
xfail_pass_list=()

if run_section compile; then
printf "${BLD}=== Compile ===${RST}\n"

printf "  cc  ... "
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -c tls_client.c
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -c https_get.c
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -c tls_test.c
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o https_get https_get.o tls_client.o
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o tls_test tls_test.o tls_client.o
printf "${GRN}ok${RST}\n"

printf "  gcc-15 ... "
gcc-15 -std=c99 -Wall -Wextra -Werror -pedantic -O2 -c -o tls_client_gcc.o tls_client.c
gcc-15 -std=c99 -Wall -Wextra -Werror -pedantic -O2 -c -o https_get_gcc.o https_get.c
gcc-15 -std=c99 -Wall -Wextra -Werror -pedantic -O2 -c -o tls_test_gcc.o tls_test.c
gcc-15 -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o https_get_gcc https_get_gcc.o tls_client_gcc.o
gcc-15 -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o tls_test_gcc tls_test_gcc.o tls_client_gcc.o
rm -f https_get_gcc tls_test_gcc *_gcc.o
printf "${GRN}ok${RST}\n"

printf "  self-tests ... "
./tls_test
printf "${GRN}ok${RST}\n"
fi

if run_section static; then
printf "\n${BLD}=== Static analysis ===${RST}\n"

printf "  cppcheck ... "
if cppcheck --error-exitcode=1 --quiet --std=c99 tls_client.c https_get.c tls_test.c 2>&1; then
    printf "${GRN}ok${RST}\n"
else
    printf "${YLW}warnings (non-fatal)${RST}\n"
fi

printf "  clang --analyze ... "
if clang --analyze -std=c99 -Weverything tls_client.c https_get.c tls_test.c 2>&1 | head -20; then
    printf "${GRN}ok${RST}\n"
else
    printf "${YLW}warnings (non-fatal)${RST}\n"
fi
rm -f tls_client.plist https_get.plist tls_test.plist
fi

# -- Timeout helper (macOS lacks GNU timeout) --
# Usage: run_with_timeout <seconds> <command> [args...]
# Captures stdout+stderr in $TIMEOUT_OUTPUT, sets $TIMEOUT_RC.
run_with_timeout() {
    local secs=$1; shift
    local tmpf
    tmpf=$(mktemp)
    "$@" >"$tmpf" 2>&1 &
    local pid=$!
    ( sleep "$secs"; kill "$pid" 2>/dev/null; true ) &
    local watcher=$!
    TIMEOUT_RC=0
    wait "$pid" 2>/dev/null || TIMEOUT_RC=$?
    kill "$watcher" 2>/dev/null || true
    wait "$watcher" 2>/dev/null || true
    TIMEOUT_OUTPUT=$(cat "$tmpf")
    rm -f "$tmpf"
}

# ================================================================
# Tests expected to PASS
# ================================================================
# Format: URL|description
pass_tests=(
    # -- badssl: key types and cipher configs --
    "https://sha256.badssl.com/|SHA-256 cert"
    "https://ecc256.badssl.com/|ECDSA P-256 cert"
    "https://ecc384.badssl.com/|ECDSA P-384 cert"
    "https://rsa2048.badssl.com/|RSA-2048 cert"
    "https://rsa4096.badssl.com/|RSA-4096 cert"
    "https://mozilla-old.badssl.com/|Mozilla old config"
    "https://mozilla-intermediate.badssl.com/|Mozilla intermediate config"
    "https://mozilla-modern.badssl.com/|Mozilla modern config"
    "https://cbc.badssl.com/|CBC cipher mode"
    "https://static-rsa.badssl.com/|static RSA key exchange"
    "https://tls-v1-2.badssl.com:1012/|TLS 1.2 only server"
    "https://pinning-test.badssl.com/|cert pinning test"
    "https://hsts.badssl.com/|HSTS header"
    # -- Top 250 domains --
    "https://www.google.com/|Google"
    "https://www.youtube.com/|YouTube"
    "https://www.facebook.com/|Facebook"
    "https://www.instagram.com/|Instagram"
    "https://www.twitter.com/|Twitter"
    "https://x.com/|X"
    "https://www.wikipedia.org/|Wikipedia"
    "https://www.reddit.com/|Reddit"
    "https://www.amazon.com/|Amazon"
    "https://www.linkedin.com/|LinkedIn"
    "https://www.netflix.com/|Netflix"
    "https://www.microsoft.com/|Microsoft"
    "https://www.office.com/|Office 365"
    "https://www.live.com/|Live.com"
    "https://www.bing.com/|Bing"
    "https://www.yahoo.com/|Yahoo"
    "https://www.whatsapp.com/|WhatsApp"
    "https://www.tiktok.com/|TikTok"
    "https://www.pinterest.com/|Pinterest"
    "https://www.github.com/|GitHub"
    "https://www.stackoverflow.com/|Stack Overflow"
    "https://www.cloudflare.com/|Cloudflare"
    "https://www.apple.com/|Apple"
    "https://www.spotify.com/|Spotify"
    "https://www.twitch.tv/|Twitch"
    "https://www.discord.com/|Discord"
    "https://www.paypal.com/|PayPal"
    "https://www.ebay.com/|eBay"
    "https://www.walmart.com/|Walmart"
    "https://www.target.com/|Target"
    "https://www.bestbuy.com/|Best Buy"
    "https://www.nytimes.com/|NY Times"
    "https://www.washingtonpost.com/|Washington Post"
    "https://www.bbc.com/|BBC"
    "https://www.cnn.com/|CNN"
    "https://www.reuters.com/|Reuters"
    "https://www.theguardian.com/|The Guardian"
    "https://www.forbes.com/|Forbes"
    "https://www.bloomberg.com/|Bloomberg"
    "https://www.wsj.com/|WSJ"
    "https://medium.com/|Medium"
    "https://www.wordpress.com/|WordPress"
    "https://www.tumblr.com/|Tumblr"
    "https://www.blogger.com/|Blogger"
    "https://www.quora.com/|Quora"
    "https://www.imdb.com/|IMDb"
    "https://www.rottentomatoes.com/|Rotten Tomatoes"
    "https://www.espn.com/|ESPN"
    "https://weather.com/|Weather.com"
    "https://www.craigslist.org/|Craigslist"
    "https://www.zoom.us/|Zoom"
    "https://www.slack.com/|Slack"
    "https://www.dropbox.com/|Dropbox"
    "https://www.box.com/|Box"
    "https://www.notion.so/|Notion"
    "https://www.figma.com/|Figma"
    "https://www.canva.com/|Canva"
    "https://www.adobe.com/|Adobe"
    "https://www.atlassian.com/|Atlassian"
    "https://www.bitbucket.org/|Bitbucket"
    "https://www.gitlab.com/|GitLab"
    "https://www.npmjs.com/|npm"
    "https://pypi.org/|PyPI"
    "https://crates.io/|crates.io"
    "https://hub.docker.com/|Docker Hub"
    "https://aws.amazon.com/|AWS"
    "https://cloud.google.com/|Google Cloud"
    "https://www.digitalocean.com/|DigitalOcean"
    "https://www.heroku.com/|Heroku"
    "https://vercel.com/|Vercel"
    "https://www.netlify.com/|Netlify"
    "https://www.fastly.com/|Fastly"
    "https://www.akamai.com/|Akamai"
    "https://www.stripe.com/|Stripe"
    "https://www.squareup.com/|Square"
    "https://www.shopify.com/|Shopify"
    "https://www.etsy.com/|Etsy"
    "https://www.zillow.com/|Zillow"
    "https://www.airbnb.com/|Airbnb"
    "https://www.booking.com/|Booking.com"
    "https://www.tripadvisor.com/|TripAdvisor"
    "https://www.uber.com/|Uber"
    "https://www.lyft.com/|Lyft"
    "https://www.doordash.com/|DoorDash"
    "https://www.grubhub.com/|Grubhub"
    "https://www.chase.com/|Chase"
    "https://www.bankofamerica.com/|Bank of America"
    "https://www.wellsfargo.com/|Wells Fargo"
    "https://www.capitalone.com/|Capital One"
    "https://www.americanexpress.com/|American Express"
    "https://www.fidelity.com/|Fidelity"
    "https://www.schwab.com/|Schwab"
    "https://www.robinhood.com/|Robinhood"
    "https://www.coinbase.com/|Coinbase"
    "https://www.openai.com/|OpenAI"
    "https://www.anthropic.com/|Anthropic"
    "https://huggingface.co/|Hugging Face"
    "https://arxiv.org/|arXiv"
    "https://www.nature.com/|Nature"
    "https://www.mozilla.org/|Mozilla"
    "https://signal.org/|Signal"
    "https://proton.me/|Proton"
    "https://www.example.com/|example.com"
    "https://httpbin.org/get|httpbin"
    "https://incomplete-chain.badssl.com/|incomplete chain (AIA fetched)"
    # -- Additional top 250 domains --
    "https://www.baidu.com/|Baidu"
    "https://www.samsung.com/|Samsung"
    "https://www.nvidia.com/|Nvidia"
    "https://www.oracle.com/|Oracle"
    "https://www.ibm.com/|IBM"
    "https://www.intel.com/|Intel"
    "https://www.cisco.com/|Cisco"
    "https://www.salesforce.com/|Salesforce"
    "https://www.sap.com/|SAP"
    "https://www.vmware.com/|VMware"
    "https://www.dell.com/|Dell"
    "https://www.hp.com/|HP"
    "https://www.lenovo.com/|Lenovo"
    "https://www.sony.com/|Sony"
    "https://www.panasonic.com/|Panasonic"
    "https://www.siemens.com/|Siemens"
    "https://www.philips.com/|Philips"
    "https://www.tesla.com/|Tesla"
    "https://www.ford.com/|Ford"
    "https://www.toyota.com/|Toyota"
    "https://www.bmw.com/|BMW"
    "https://www.mercedes-benz.com/|Mercedes-Benz"
    "https://www.honda.com/|Honda"
    "https://www.nike.com/|Nike"
    "https://www.adidas.com/|Adidas"
    "https://www.zara.com/|Zara"
    "https://www.hm.com/|H&M"
    "https://www.ikea.com/|IKEA"
    "https://www.costco.com/|Costco"
    "https://www.homedepot.com/|Home Depot"
    "https://www.lowes.com/|Lowe's"
    "https://www.macys.com/|Macy's"
    "https://www.nordstrom.com/|Nordstrom"
    "https://www.wayfair.com/|Wayfair"
    "https://www.chewy.com/|Chewy"
    "https://www.newegg.com/|Newegg"
    "https://www.aliexpress.com/|AliExpress"
    "https://www.wish.com/|Wish"
    "https://www.groupon.com/|Groupon"
    "https://www.instacart.com/|Instacart"
    "https://www.postmates.com/|Postmates"
    "https://www.yelp.com/|Yelp"
    "https://www.glassdoor.com/|Glassdoor"
    "https://www.indeed.com/|Indeed"
    "https://www.monster.com/|Monster"
    "https://www.ziprecruiter.com/|ZipRecruiter"
    "https://www.upwork.com/|Upwork"
    "https://www.fiverr.com/|Fiverr"
    "https://www.coursera.org/|Coursera"
    "https://www.udemy.com/|Udemy"
    "https://www.khanacademy.org/|Khan Academy"
    "https://www.edx.org/|edX"
    "https://www.duolingo.com/|Duolingo"
    "https://www.archive.org/|Internet Archive"
    "https://www.wolframalpha.com/|Wolfram Alpha"
    "https://www.w3.org/|W3C"
    "https://www.ietf.org/|IETF"
    "https://letsencrypt.org/|Let's Encrypt"
    "https://www.eff.org/|EFF"
    "https://www.aclu.org/|ACLU"
    "https://www.usps.com/|USPS"
    "https://www.ups.com/|UPS"
    "https://www.fedex.com/|FedEx"
    "https://www.dhl.com/|DHL"
    "https://www.united.com/|United Airlines"
    "https://www.delta.com/|Delta Airlines"
    "https://www.aa.com/|American Airlines"
    "https://www.southwest.com/|Southwest Airlines"
    "https://www.expedia.com/|Expedia"
    "https://www.kayak.com/|Kayak"
    "https://www.hotels.com/|Hotels.com"
    "https://www.vrbo.com/|Vrbo"
    "https://www.marriott.com/|Marriott"
    "https://www.hilton.com/|Hilton"
    "https://www.hyatt.com/|Hyatt"
    "https://www.wyndhamhotels.com/|Wyndham"
    "https://www.webmd.com/|WebMD"
    "https://www.mayoclinic.org/|Mayo Clinic"
    "https://www.nih.gov/|NIH"
    "https://www.cdc.gov/|CDC"
    "https://www.who.int/|WHO"
    "https://www.healthline.com/|Healthline"
    "https://www.goodrx.com/|GoodRx"
    "https://www.zocdoc.com/|Zocdoc"
    "https://www.realtor.com/|Realtor.com"
    "https://www.redfin.com/|Redfin"
    "https://www.trulia.com/|Trulia"
    "https://www.apartments.com/|Apartments.com"
    "https://www.mint.com/|Mint"
    "https://www.creditkarma.com/|Credit Karma"
    "https://www.nerdwallet.com/|NerdWallet"
    "https://www.turbotax.com/|TurboTax"
    "https://www.hrblock.com/|H&R Block"
    "https://www.vanguard.com/|Vanguard"
    "https://www.tdameritrade.com/|TD Ameritrade"
    "https://www.etrade.com/|E*TRADE"
    "https://www.sofi.com/|SoFi"
    "https://www.venmo.com/|Venmo"
    "https://www.cashapp.com/|Cash App"
    "https://www.wise.com/|Wise"
    "https://www.hulu.com/|Hulu"
    "https://www.disneyplus.com/|Disney+"
    "https://www.hbomax.com/|HBO Max"
    "https://www.peacocktv.com/|Peacock"
    "https://www.paramountplus.com/|Paramount+"
    "https://www.crunchyroll.com/|Crunchyroll"
    "https://www.soundcloud.com/|SoundCloud"
    "https://www.pandora.com/|Pandora"
    "https://www.deezer.com/|Deezer"
    "https://www.bandcamp.com/|Bandcamp"
    "https://store.steampowered.com/|Steam"
    "https://www.ea.com/|EA"
    "https://www.epicgames.com/|Epic Games"
    "https://www.roblox.com/|Roblox"
    "https://www.minecraft.net/|Minecraft"
    "https://www.snap.com/|Snap"
    "https://www.telegram.org/|Telegram"
    "https://www.skype.com/|Skype"
    "https://www.webex.com/|Webex"
    "https://www.gotomeeting.com/|GoToMeeting"
    "https://www.Monday.com/|Monday.com"
    "https://www.asana.com/|Asana"
    "https://www.trello.com/|Trello"
    "https://www.jira.com/|Jira"
    "https://www.confluence.com/|Confluence"
    "https://www.hubspot.com/|HubSpot"
    "https://www.mailchimp.com/|Mailchimp"
    "https://www.zendesk.com/|Zendesk"
    "https://www.intercom.com/|Intercom"
    "https://www.twilio.com/|Twilio"
    "https://www.datadog.com/|Datadog"
    "https://www.splunk.com/|Splunk"
    "https://www.elastic.co/|Elastic"
    "https://www.grafana.com/|Grafana"
    "https://www.hashicorp.com/|HashiCorp"
    "https://www.docker.com/|Docker"
    "https://kubernetes.io/|Kubernetes"
    "https://www.redhat.com/|Red Hat"
    "https://www.canonical.com/|Canonical"
    "https://www.suse.com/|SUSE"
    "https://www.mongodb.com/|MongoDB"
    "https://www.postgresql.org/|PostgreSQL"
    "https://www.mysql.com/|MySQL"
    "https://redis.io/|Redis"
    "https://www.snowflake.com/|Snowflake"
    "https://www.databricks.com/|Databricks"
    "https://www.palantir.com/|Palantir"
    "https://www.tableau.com/|Tableau"
    "https://www.okta.com/|Okta"
    "https://www.crowdstrike.com/|CrowdStrike"
    "https://www.paloaltonetworks.com/|Palo Alto Networks"
    "https://www.fortinet.com/|Fortinet"
    "https://www.godaddy.com/|GoDaddy"
    "https://www.namecheap.com/|Namecheap"
    "https://www.squarespace.com/|Squarespace"
    "https://www.wix.com/|Wix"
    "https://www.weebly.com/|Weebly"
)

# ================================================================
# Tests expected to FAIL (xfail)
# ================================================================
# Format: URL|description|expected error substring
xfail_tests=(
    # -- Revoked certificates --
    "https://revoked.badssl.com/|revoked cert (CRL)|revoked"
    # -- Bad certificates (cert verification should reject) --
    "https://expired.badssl.com/|expired cert|Certificate verification failed"
    "https://wrong.host.badssl.com/|wrong hostname|Certificate verification failed"
    "https://self-signed.badssl.com/|self-signed cert|Certificate verification failed"
    "https://untrusted-root.badssl.com/|untrusted root CA|Certificate verification failed"
    "https://no-common-name.badssl.com/|no common name|Certificate verification failed"
    "https://no-subject.badssl.com/|no subject|Certificate verification failed"
    "https://sha384.badssl.com/|SHA-384 cert (expired)|Certificate verification failed"
    "https://sha512.badssl.com/|SHA-512 cert (expired)|Certificate verification failed"
    "https://1000-sans.badssl.com/|1000 SANs (expired)|Certificate verification failed"
    "https://extended-validation.badssl.com/|EV cert (expired)|Certificate verification failed"
    "https://no-sct.badssl.com/|no SCT (expired)|Certificate verification failed"
    "https://superfish.badssl.com/|Superfish CA|Certificate verification failed"
    "https://edellroot.badssl.com/|eDellRoot CA|Certificate verification failed"
    "https://dsdtestprovider.badssl.com/|DSD Test Provider CA|Certificate verification failed"
    "https://preact-cli.badssl.com/|preact-cli cert|Certificate verification failed"
    "https://webpack-dev-server.badssl.com/|webpack-dev-server cert|Certificate verification failed"
    # -- Unsupported ciphers (server rejects our ClientHello) --
    "https://rc4.badssl.com/|RC4 only|server sent alert"
    "https://rc4-md5.badssl.com/|RC4-MD5 only|server sent alert"
    "https://3des.badssl.com/|3DES only|server sent alert"
    "https://null.badssl.com/|null cipher|server sent alert"
    # -- Unsupported DH key exchange --
    "https://dh480.badssl.com/|DH-480|server sent alert"
    "https://dh512.badssl.com/|DH-512|server sent alert"
    "https://dh1024.badssl.com/|DH-1024 (no FFDHE support)|server sent alert"
    "https://dh2048.badssl.com/|DH-2048 (no FFDHE support)|server sent alert"
    "https://dh-small-subgroup.badssl.com/|DH small subgroup|server sent alert"
    "https://dh-composite.badssl.com/|DH composite|server sent alert"
    # -- Protocol/size limitations --
    "https://10000-sans.badssl.com/|10000 SANs (buffer overflow)|handshake buffer overflow"
    "https://rsa8192.badssl.com/|RSA-8192 cert|signature verification failed"
    "https://tls-v1-0.badssl.com:1010/|TLS 1.0 only|SKE signature truncated"
    "https://tls-v1-1.badssl.com:1011/|TLS 1.1 only|SKE signature truncated"
    "https://client-cert-missing.badssl.com/|client cert required|expected ChangeCipherSpec"
)

# ================================================================
# Run tests expected to PASS
# ================================================================
if run_section pass; then

# Random sampling: shuffle indices and take first N
if [[ $SAMPLE_SIZE -gt 0 && $SAMPLE_SIZE -lt ${#pass_tests[@]} ]]; then
    indices=($(seq 0 $(( ${#pass_tests[@]} - 1 ))))
    for (( i=${#indices[@]}-1; i>0; i-- )); do
        j=$(( RANDOM % (i+1) ))
        tmp=${indices[$i]}; indices[$i]=${indices[$j]}; indices[$j]=$tmp
    done
    indices=("${indices[@]:0:$SAMPLE_SIZE}")
    # Sort so output order is stable
    IFS=$'\n' indices=($(sort -n <<<"${indices[*]}")); unset IFS
    sampled=()
    for idx in "${indices[@]}"; do
        sampled+=("${pass_tests[$idx]}")
    done
    pass_tests=("${sampled[@]}")
fi

total_pass_tests=${#pass_tests[@]}
printf "\n${BLD}=== Connection tests (expected pass) [0/%d] ===${RST}\n" "$total_pass_tests"
printf "\n"  # placeholder line for domain result (overwritten on first iteration)

i=0
for entry in "${pass_tests[@]}"; do
    i=$((i + 1))
    url="${entry%%|*}"
    desc="${entry##*|}"

    # Progress bar — go up 2 lines to overwrite bar + previous result
    pct=$((i * 100 / total_pass_tests))
    filled=$((pct / 2))
    empty=$((50 - filled))
    bar=$(printf "%${filled}s" | tr ' ' '█')$(printf "%${empty}s" | tr ' ' '░')
    printf "\033[2A\r\033[K${BLD}=== Connection tests (expected pass) [%d/%d] %3d%% ${bar} ===${RST}\n" \
        "$i" "$total_pass_tests" "$pct"
    printf "\033[K  %-50s " "$url"

    run_with_timeout "$TEST_TIMEOUT" ./https_get "$url"
    rc=$TIMEOUT_RC
    output="$TIMEOUT_OUTPUT"

    if [[ $rc -eq 0 ]]; then
        printf "${GRN}PASS${RST}  %s\n" "$desc"
        pass=$((pass + 1))
    else
        reason=$(echo "$output" | grep 'FATAL:' | head -1 || true)
        printf "${RED}FAIL${RST}  %s  %s\n" "$desc" "$reason"
        fail=$((fail + 1))
        failures+=("$url ($desc): $reason")
        if [[ $fail -ge $MAX_FAILURES ]]; then
            printf "\n  ${RED}Bailing early: %d failures reached (max %d)${RST}\n" "$fail" "$MAX_FAILURES"
            break
        fi
    fi
done
fi # run_section pass

# ================================================================
# Run tests expected to FAIL (xfail)
# ================================================================
if run_section xfail; then
printf "\n${BLD}=== Connection tests (expected fail) ===${RST}\n"

for entry in "${xfail_tests[@]}"; do
    url="${entry%%|*}"
    rest="${entry#*|}"
    desc="${rest%%|*}"
    expected_err="${rest##*|}"
    printf "  %-50s " "$url"

    run_with_timeout "$TEST_TIMEOUT" ./https_get "$url"
    rc=$TIMEOUT_RC
    output="$TIMEOUT_OUTPUT"

    if [[ $rc -eq 0 ]]; then
        printf "${RED}XPASS${RST} %s  (unexpected success!)\n" "$desc"
        xfail_unexpected_pass=$((xfail_unexpected_pass + 1))
        xfail_pass_list+=("$url ($desc): expected failure but passed")
    elif echo "$output" | grep -qi "$expected_err"; then
        printf "${GRN}XFAIL${RST} %s\n" "$desc"
        xfail=$((xfail + 1))
    else
        reason=$(echo "$output" | grep 'FATAL:' | head -1 || true)
        printf "${YLW}XFAIL${RST} %s  [%s]\n" "$desc" "${reason:-timeout/unknown}"
        xfail=$((xfail + 1))
    fi
done
fi # run_section xfail

# ================================================================
# Local crypto tests (openssl s_server)
# ================================================================
local_pass=0
local_fail=0
local_skip=0
local_xfail=0

if run_section local; then
printf "\n${BLD}=== Local crypto tests ===${RST}\n"
LOCAL_PORT=14433
LOCAL_TMPDIR=$(mktemp -d)
local_cleanup_pids=()

cleanup_local() {
    for pid in ${local_cleanup_pids[@]+"${local_cleanup_pids[@]}"}; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$LOCAL_TMPDIR"
    rm -f trust_store/local_test_*.crt
}
trap cleanup_local EXIT

wait_for_server() {
    local port=$1 i=0
    while [[ $i -lt 30 ]]; do
        if nc -z localhost "$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

wait_for_port_free() {
    local port=$1 i=0
    while [[ $i -lt 30 ]]; do
        if ! nc -z localhost "$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# --- Generate certificates ---
# RSA-2048 (always available)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$LOCAL_TMPDIR/rsa_key.pem" 2>/dev/null
openssl req -new -x509 -key "$LOCAL_TMPDIR/rsa_key.pem" \
    -out "$LOCAL_TMPDIR/rsa_cert.pem" -days 1 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
RSA_KEY="$LOCAL_TMPDIR/rsa_key.pem"
RSA_CERT="$LOCAL_TMPDIR/rsa_cert.pem"

# ECDSA P-256 (always available)
openssl ecparam -name prime256v1 -genkey -noout \
    -out "$LOCAL_TMPDIR/ec256_key.pem" 2>/dev/null
openssl req -new -x509 -key "$LOCAL_TMPDIR/ec256_key.pem" \
    -out "$LOCAL_TMPDIR/ec256_cert.pem" -days 1 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
EC256_KEY="$LOCAL_TMPDIR/ec256_key.pem"
EC256_CERT="$LOCAL_TMPDIR/ec256_cert.pem"

# ECDSA P-384 (always available)
openssl ecparam -name secp384r1 -genkey -noout \
    -out "$LOCAL_TMPDIR/ec384_key.pem" 2>/dev/null
openssl req -new -x509 -key "$LOCAL_TMPDIR/ec384_key.pem" \
    -out "$LOCAL_TMPDIR/ec384_cert.pem" -days 1 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
EC384_KEY="$LOCAL_TMPDIR/ec384_key.pem"
EC384_CERT="$LOCAL_TMPDIR/ec384_cert.pem"

# Ed25519 (may not be available)
HAS_ED25519=false
if openssl genpkey -algorithm Ed25519 -out "$LOCAL_TMPDIR/ed25519_key.pem" 2>/dev/null && \
   openssl req -new -x509 -key "$LOCAL_TMPDIR/ed25519_key.pem" \
       -out "$LOCAL_TMPDIR/ed25519_cert.pem" -days 1 \
       -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null; then
    HAS_ED25519=true
    ED25519_KEY="$LOCAL_TMPDIR/ed25519_key.pem"
    ED25519_CERT="$LOCAL_TMPDIR/ed25519_cert.pem"
fi

# Ed448 (may not be available)
HAS_ED448=false
if openssl genpkey -algorithm Ed448 -out "$LOCAL_TMPDIR/ed448_key.pem" 2>/dev/null && \
   openssl req -new -x509 -key "$LOCAL_TMPDIR/ed448_key.pem" \
       -out "$LOCAL_TMPDIR/ed448_cert.pem" -days 1 \
       -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null; then
    HAS_ED448=true
    ED448_KEY="$LOCAL_TMPDIR/ed448_key.pem"
    ED448_CERT="$LOCAL_TMPDIR/ed448_cert.pem"
fi

# X448 support check (uses EC-256 cert, just forces X448 group)
HAS_X448=false
if openssl genpkey -algorithm X448 -out /dev/null 2>/dev/null; then
    HAS_X448=true
fi

# Expired cert (RSA, notAfter in the past)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$LOCAL_TMPDIR/expired_key.pem" 2>/dev/null
openssl req -new -x509 -key "$LOCAL_TMPDIR/expired_key.pem" \
    -out "$LOCAL_TMPDIR/expired_cert.pem" -days 1 \
    -not_before 20200101000000Z -not_after 20200102000000Z \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
EXPIRED_KEY="$LOCAL_TMPDIR/expired_key.pem"
EXPIRED_CERT="$LOCAL_TMPDIR/expired_cert.pem"

# Wrong-hostname cert (RSA, CN and SAN mismatch)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$LOCAL_TMPDIR/wronghost_key.pem" 2>/dev/null
openssl req -new -x509 -key "$LOCAL_TMPDIR/wronghost_key.pem" \
    -out "$LOCAL_TMPDIR/wronghost_cert.pem" -days 1 \
    -subj "/CN=wrong.example.com" -addext "subjectAltName=DNS:wrong.example.com" 2>/dev/null
WRONGHOST_KEY="$LOCAL_TMPDIR/wronghost_key.pem"
WRONGHOST_CERT="$LOCAL_TMPDIR/wronghost_cert.pem"

# Untrusted cert (RSA, valid CN=localhost but NOT copied to trust_store)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$LOCAL_TMPDIR/untrusted_key.pem" 2>/dev/null
openssl req -new -x509 -key "$LOCAL_TMPDIR/untrusted_key.pem" \
    -out "$LOCAL_TMPDIR/untrusted_cert.pem" -days 1 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
UNTRUSTED_KEY="$LOCAL_TMPDIR/untrusted_key.pem"
UNTRUSTED_CERT="$LOCAL_TMPDIR/untrusted_cert.pem"

# --- Copy all certs to trust_store/ ---
cp "$RSA_CERT"  trust_store/local_test_rsa.crt
cp "$EC256_CERT" trust_store/local_test_ec256.crt
cp "$EC384_CERT" trust_store/local_test_ec384.crt
$HAS_ED25519 && cp "$ED25519_CERT" trust_store/local_test_ed25519.crt
$HAS_ED448   && cp "$ED448_CERT"   trust_store/local_test_ed448.crt
cp "$EXPIRED_CERT"   trust_store/local_test_expired.crt
cp "$WRONGHOST_CERT" trust_store/local_test_wronghost.crt
# NOTE: untrusted cert deliberately NOT copied to trust_store

# --- Check for static RSA cipher availability (OpenSSL 3.x may disable them) ---
HAS_STATIC_RSA=false
if openssl ciphers AES128-GCM-SHA256 >/dev/null 2>&1; then
    HAS_STATIC_RSA=true
fi

# --- Helper: run a single server test ---
# Usage: run_server_test <name> <key> <cert> [extra s_server args...]
run_server_test() {
    local name="$1" key="$2" cert="$3"
    shift 3

    printf "  %-50s " "$name"

    wait_for_port_free $LOCAL_PORT

    openssl s_server -key "$key" -cert "$cert" -port $LOCAL_PORT -www \
        "$@" </dev/null >/dev/null 2>&1 &
    local srv_pid=$!
    local_cleanup_pids+=("$srv_pid")

    if wait_for_server $LOCAL_PORT; then
        run_with_timeout "$TEST_TIMEOUT" ./https_get "https://localhost:$LOCAL_PORT/"
        if [[ $TIMEOUT_RC -eq 0 ]]; then
            printf "${GRN}PASS${RST}\n"
            local_pass=$((local_pass + 1))
        else
            local reason
            reason=$(echo "$TIMEOUT_OUTPUT" | grep 'FATAL:' | head -1 || true)
            printf "${RED}FAIL${RST}  %s\n" "$reason"
            local_fail=$((local_fail + 1))
            failures+=("local $name: $reason")
        fi
    else
        printf "${RED}FAIL${RST}  server failed to start\n"
        local_fail=$((local_fail + 1))
        failures+=("local $name: server failed to start")
    fi

    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
}

# --- Helper: run a single expected-failure server test ---
# Usage: run_server_xfail <name> <key> <cert> <expected_error> [extra s_server args...]
run_server_xfail() {
    local name="$1" key="$2" cert="$3" expected_err="$4"
    shift 4

    printf "  %-50s " "$name"

    wait_for_port_free $LOCAL_PORT

    openssl s_server -key "$key" -cert "$cert" -port $LOCAL_PORT -www \
        "$@" </dev/null >/dev/null 2>&1 &
    local srv_pid=$!
    local_cleanup_pids+=("$srv_pid")

    if wait_for_server $LOCAL_PORT; then
        run_with_timeout "$TEST_TIMEOUT" ./https_get "https://localhost:$LOCAL_PORT/"
        if [[ $TIMEOUT_RC -eq 0 ]]; then
            printf "${RED}XPASS${RST}  (unexpected success!)\n"
            local_fail=$((local_fail + 1))
            failures+=("local $name: expected failure but passed")
        elif echo "$TIMEOUT_OUTPUT" | grep -qi "$expected_err"; then
            printf "${GRN}XFAIL${RST}\n"
            local_xfail=$((local_xfail + 1))
        else
            local reason
            reason=$(echo "$TIMEOUT_OUTPUT" | grep 'FATAL:' | head -1 || true)
            printf "${YLW}XFAIL${RST}  [%s]\n" "${reason:-timeout/unknown}"
            local_xfail=$((local_xfail + 1))
        fi
    else
        printf "${YLW}SKIP${RST}  server failed to start\n"
        local_skip=$((local_skip + 1))
    fi

    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
}

# --- TLS 1.3 cipher suites ---
run_server_test "TLS13 AES-128-GCM X25519" \
    "$RSA_KEY" "$RSA_CERT" \
    -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519

run_server_test "TLS13 AES-256-GCM P-256" \
    "$EC256_KEY" "$EC256_CERT" \
    -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -groups P-256

run_server_test "TLS13 ChaCha20-Poly1305 P-384" \
    "$EC384_KEY" "$EC384_CERT" \
    -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups P-384

# --- TLS 1.2 ECDHE-RSA ---
run_server_test "TLS12 ECDHE-RSA-AES128-GCM" \
    "$RSA_KEY" "$RSA_CERT" \
    -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256

run_server_test "TLS12 ECDHE-RSA-AES256-GCM" \
    "$RSA_KEY" "$RSA_CERT" \
    -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384

run_server_test "TLS12 ECDHE-RSA-AES128-CBC" \
    "$RSA_KEY" "$RSA_CERT" \
    -tls1_2 -cipher ECDHE-RSA-AES128-SHA

run_server_test "TLS12 ECDHE-RSA-AES256-CBC" \
    "$RSA_KEY" "$RSA_CERT" \
    -tls1_2 -cipher ECDHE-RSA-AES256-SHA

run_server_test "TLS12 ECDHE-RSA-CHACHA20" \
    "$RSA_KEY" "$RSA_CERT" \
    -tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305

# --- TLS 1.2 ECDHE-ECDSA ---
run_server_test "TLS12 ECDHE-ECDSA-AES128-GCM" \
    "$EC256_KEY" "$EC256_CERT" \
    -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256

run_server_test "TLS12 ECDHE-ECDSA-AES256-GCM" \
    "$EC384_KEY" "$EC384_CERT" \
    -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384

run_server_test "TLS12 ECDHE-ECDSA-AES128-CBC" \
    "$EC256_KEY" "$EC256_CERT" \
    -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA

run_server_test "TLS12 ECDHE-ECDSA-AES256-CBC" \
    "$EC384_KEY" "$EC384_CERT" \
    -tls1_2 -cipher ECDHE-ECDSA-AES256-SHA

run_server_test "TLS12 ECDHE-ECDSA-CHACHA20" \
    "$EC256_KEY" "$EC256_CERT" \
    -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305

# --- TLS 1.2 Static RSA ---
if $HAS_STATIC_RSA; then
    run_server_test "TLS12 RSA-AES128-GCM" \
        "$RSA_KEY" "$RSA_CERT" \
        -tls1_2 -cipher AES128-GCM-SHA256

    run_server_test "TLS12 RSA-AES256-GCM" \
        "$RSA_KEY" "$RSA_CERT" \
        -tls1_2 -cipher AES256-GCM-SHA384

    run_server_test "TLS12 RSA-AES128-CBC" \
        "$RSA_KEY" "$RSA_CERT" \
        -tls1_2 -cipher AES128-SHA

    run_server_test "TLS12 RSA-AES256-CBC" \
        "$RSA_KEY" "$RSA_CERT" \
        -tls1_2 -cipher AES256-SHA
else
    for name in "TLS12 RSA-AES128-GCM" "TLS12 RSA-AES256-GCM" \
                "TLS12 RSA-AES128-CBC" "TLS12 RSA-AES256-CBC"; do
        printf "  %-50s ${YLW}SKIP${RST}  (static RSA ciphers unavailable)\n" "$name"
        local_skip=$((local_skip + 1))
    done
fi

# --- Ed25519 CertificateVerify ---
if $HAS_ED25519; then
    run_server_test "Ed25519 CertificateVerify" \
        "$ED25519_KEY" "$ED25519_CERT"
else
    printf "  %-50s ${YLW}SKIP${RST}  (OpenSSL lacks Ed25519 support)\n" "Ed25519 CertificateVerify"
    local_skip=$((local_skip + 1))
fi

# --- X448 key exchange ---
if $HAS_X448; then
    run_server_test "X448 key exchange" \
        "$EC256_KEY" "$EC256_CERT" \
        -groups X448
else
    printf "  %-50s ${YLW}SKIP${RST}  (OpenSSL lacks X448 support)\n" "X448 key exchange"
    local_skip=$((local_skip + 1))
fi

# --- Ed448 CertificateVerify ---
if $HAS_ED448; then
    run_server_test "Ed448 CertificateVerify" \
        "$ED448_KEY" "$ED448_CERT"
else
    printf "  %-50s ${YLW}SKIP${RST}  (OpenSSL lacks Ed448 support)\n" "Ed448 CertificateVerify"
    local_skip=$((local_skip + 1))
fi

# --- Local expected-failure tests ---
printf "\n  ${BLD}-- Negative tests --${RST}\n"

run_server_xfail "Reject expired cert" \
    "$EXPIRED_KEY" "$EXPIRED_CERT" "has expired"

run_server_xfail "Reject wrong hostname" \
    "$WRONGHOST_KEY" "$WRONGHOST_CERT" "Hostname verification failed"

run_server_xfail "Reject untrusted cert" \
    "$UNTRUSTED_KEY" "$UNTRUSTED_CERT" "Certificate verification failed"

# TLS 1.0 (skip if openssl lacks -tls1)
if openssl s_client -help 2>&1 | grep -q '\-tls1 '; then
    run_server_xfail "Reject TLS 1.0" \
        "$RSA_KEY" "$RSA_CERT" "SKE signature truncated" -tls1
else
    printf "  %-50s ${YLW}SKIP${RST}  (OpenSSL lacks TLS 1.0 support)\n" "Reject TLS 1.0"
    local_skip=$((local_skip + 1))
fi

# TLS 1.1 (skip if openssl lacks -tls1_1)
if openssl s_client -help 2>&1 | grep -q '\-tls1_1'; then
    run_server_xfail "Reject TLS 1.1" \
        "$RSA_KEY" "$RSA_CERT" "SKE signature truncated" -tls1_1
else
    printf "  %-50s ${YLW}SKIP${RST}  (OpenSSL lacks TLS 1.1 support)\n" "Reject TLS 1.1"
    local_skip=$((local_skip + 1))
fi

fi # run_section local

# -- Summary --
printf "\n${BLD}=== Summary ===${RST}\n"
if run_section pass || run_section xfail; then
    printf "  ${GRN}Pass: %d${RST}   ${RED}Fail: %d${RST}   " "$pass" "$fail"
    printf "Expected-fail: %d   " "$xfail"
    printf "${RED}Unexpected-pass: %d${RST}\n" "$xfail_unexpected_pass"
fi
if run_section local; then
    printf "  Local crypto: ${GRN}%d pass${RST} / ${RED}%d fail${RST} / %d xfail / ${YLW}%d skip${RST}\n" \
        "$local_pass" "$local_fail" "$local_xfail" "$local_skip"
fi

exit_code=0

if [[ ${#failures[@]} -gt 0 ]]; then
    printf "\n${RED}Failures:${RST}\n"
    for f in "${failures[@]}"; do
        printf "  - %s\n" "$f"
    done
    exit_code=1
fi

if [[ ${#xfail_pass_list[@]} -gt 0 ]]; then
    printf "\n${RED}Unexpected passes (xfail tests that succeeded):${RST}\n"
    for f in "${xfail_pass_list[@]}"; do
        printf "  - %s\n" "$f"
    done
    exit_code=1
fi

if [[ $exit_code -eq 0 ]]; then
    printf "\n${GRN}All tests behaved as expected.${RST}\n"
fi
exit $exit_code
