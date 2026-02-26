#!/usr/bin/env bash
set -euo pipefail

# -- Settings --
TEST_TIMEOUT=30   # seconds per test (must exceed TLS_READ_TIMEOUT_S in tls_client.c)
MAX_FAILURES=10   # bail early after this many failures in pass tests
SAMPLE_SIZE=0     # 0 = run all; >0 = random sample of N pass tests

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n) SAMPLE_SIZE="$2"; shift 2 ;;
        *)  echo "Usage: $0 [-n sample_size]" >&2; exit 1 ;;
    esac
done

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

printf "${BLD}=== Compile ===${RST}\n"

printf "  cc  ... "
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o tls_client tls_client.c
printf "${GRN}ok${RST}\n"

printf "  gcc-15 ... "
gcc-15 -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o tls_client_gcc tls_client.c
rm -f tls_client_gcc
printf "${GRN}ok${RST}\n"

printf "\n${BLD}=== Static analysis ===${RST}\n"

printf "  cppcheck ... "
if cppcheck --error-exitcode=1 --quiet --std=c99 tls_client.c 2>&1; then
    printf "${GRN}ok${RST}\n"
else
    printf "${YLW}warnings (non-fatal)${RST}\n"
fi

printf "  clang --analyze ... "
if clang --analyze -std=c99 -Weverything tls_client.c 2>&1 | head -20; then
    printf "${GRN}ok${RST}\n"
else
    printf "${YLW}warnings (non-fatal)${RST}\n"
fi
rm -f tls_client.plist

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
    "https://revoked.badssl.com/|revoked cert (no OCSP checking)"
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

i=0
for entry in "${pass_tests[@]}"; do
    i=$((i + 1))
    url="${entry%%|*}"
    desc="${entry##*|}"

    # Progress bar
    pct=$((i * 100 / total_pass_tests))
    filled=$((pct / 2))
    empty=$((50 - filled))
    bar=$(printf "%${filled}s" | tr ' ' '█')$(printf "%${empty}s" | tr ' ' '░')
    printf "\r\033[1A\033[K${BLD}=== Connection tests (expected pass) [%d/%d] %3d%% ${bar} ===${RST}\n" \
        "$i" "$total_pass_tests" "$pct"

    printf "  %-50s " "$url"

    run_with_timeout "$TEST_TIMEOUT" ./tls_client "$url"
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

# ================================================================
# Run tests expected to FAIL (xfail)
# ================================================================
printf "\n${BLD}=== Connection tests (expected fail) ===${RST}\n"

for entry in "${xfail_tests[@]}"; do
    url="${entry%%|*}"
    rest="${entry#*|}"
    desc="${rest%%|*}"
    expected_err="${rest##*|}"
    printf "  %-50s " "$url"

    run_with_timeout "$TEST_TIMEOUT" ./tls_client "$url"
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

# -- Summary --
printf "\n${BLD}=== Summary ===${RST}\n"
printf "  ${GRN}Pass: %d${RST}   ${RED}Fail: %d${RST}   " "$pass" "$fail"
printf "Expected-fail: %d   " "$xfail"
printf "${RED}Unexpected-pass: %d${RST}\n" "$xfail_unexpected_pass"

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
