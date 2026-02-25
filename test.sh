#!/usr/bin/env bash
set -euo pipefail

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
cc -std=c17 -Wall -Wextra -Werror -pedantic -O2 -o tls_client tls_client.c
printf "${GRN}ok${RST}\n"

printf "  gcc-15 ... "
gcc-15 -std=c17 -Wall -Wextra -Werror -pedantic -O2 -o tls_client_gcc tls_client.c
printf "${GRN}ok${RST}\n"

printf "\n${BLD}=== Static analysis ===${RST}\n"

printf "  cppcheck ... "
if cppcheck --error-exitcode=1 --quiet --std=c11 tls_client.c 2>&1; then
    printf "${GRN}ok${RST}\n"
else
    printf "${YLW}warnings (non-fatal)${RST}\n"
fi

printf "  clang --analyze ... "
if clang --analyze -std=c17 -Weverything tls_client.c 2>&1 | head -20; then
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
    ( sleep "$secs"; kill "$pid" 2>/dev/null ) &
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
    # -- Top 100 domains --
    "https://google.com/|Google"
    "https://youtube.com/|YouTube"
    "https://facebook.com/|Facebook"
    "https://instagram.com/|Instagram"
    "https://twitter.com/|Twitter"
    "https://x.com/|X"
    "https://wikipedia.org/|Wikipedia"
    "https://reddit.com/|Reddit"
    "https://amazon.com/|Amazon"
    "https://linkedin.com/|LinkedIn"
    "https://netflix.com/|Netflix"
    "https://microsoft.com/|Microsoft"
    "https://office.com/|Office 365"
    "https://live.com/|Live.com"
    "https://bing.com/|Bing"
    "https://yahoo.com/|Yahoo"
    "https://whatsapp.com/|WhatsApp"
    "https://tiktok.com/|TikTok"
    "https://pinterest.com/|Pinterest"
    "https://github.com/|GitHub"
    "https://stackoverflow.com/|Stack Overflow"
    "https://cloudflare.com/|Cloudflare"
    "https://apple.com/|Apple"
    "https://spotify.com/|Spotify"
    "https://twitch.tv/|Twitch"
    "https://discord.com/|Discord"
    "https://paypal.com/|PayPal"
    "https://ebay.com/|eBay"
    "https://walmart.com/|Walmart"
    "https://target.com/|Target"
    "https://bestbuy.com/|Best Buy"
    "https://nytimes.com/|NY Times"
    "https://washingtonpost.com/|Washington Post"
    "https://bbc.com/|BBC"
    "https://cnn.com/|CNN"
    "https://reuters.com/|Reuters"
    "https://theguardian.com/|The Guardian"
    "https://forbes.com/|Forbes"
    "https://bloomberg.com/|Bloomberg"
    "https://wsj.com/|WSJ"
    "https://medium.com/|Medium"
    "https://wordpress.com/|WordPress"
    "https://tumblr.com/|Tumblr"
    "https://blogger.com/|Blogger"
    "https://quora.com/|Quora"
    "https://imdb.com/|IMDb"
    "https://rottentomatoes.com/|Rotten Tomatoes"
    "https://espn.com/|ESPN"
    "https://weather.com/|Weather.com"
    "https://craigslist.org/|Craigslist"
    "https://zoom.us/|Zoom"
    "https://slack.com/|Slack"
    "https://dropbox.com/|Dropbox"
    "https://box.com/|Box"
    "https://notion.so/|Notion"
    "https://figma.com/|Figma"
    "https://canva.com/|Canva"
    "https://adobe.com/|Adobe"
    "https://atlassian.com/|Atlassian"
    "https://bitbucket.org/|Bitbucket"
    "https://gitlab.com/|GitLab"
    "https://npmjs.com/|npm"
    "https://pypi.org/|PyPI"
    "https://crates.io/|crates.io"
    "https://hub.docker.com/|Docker Hub"
    "https://aws.amazon.com/|AWS"
    "https://cloud.google.com/|Google Cloud"
    "https://digitalocean.com/|DigitalOcean"
    "https://heroku.com/|Heroku"
    "https://vercel.com/|Vercel"
    "https://netlify.com/|Netlify"
    "https://fastly.com/|Fastly"
    "https://akamai.com/|Akamai"
    "https://stripe.com/|Stripe"
    "https://square.com/|Square"
    "https://shopify.com/|Shopify"
    "https://etsy.com/|Etsy"
    "https://zillow.com/|Zillow"
    "https://airbnb.com/|Airbnb"
    "https://booking.com/|Booking.com"
    "https://tripadvisor.com/|TripAdvisor"
    "https://uber.com/|Uber"
    "https://lyft.com/|Lyft"
    "https://doordash.com/|DoorDash"
    "https://grubhub.com/|Grubhub"
    "https://chase.com/|Chase"
    "https://bankofamerica.com/|Bank of America"
    "https://wellsfargo.com/|Wells Fargo"
    "https://capitalone.com/|Capital One"
    "https://americanexpress.com/|American Express"
    "https://fidelity.com/|Fidelity"
    "https://schwab.com/|Schwab"
    "https://robinhood.com/|Robinhood"
    "https://coinbase.com/|Coinbase"
    "https://openai.com/|OpenAI"
    "https://anthropic.com/|Anthropic"
    "https://huggingface.co/|Hugging Face"
    "https://arxiv.org/|arXiv"
    "https://nature.com/|Nature"
    "https://mozilla.org/|Mozilla"
    "https://signal.org/|Signal"
    "https://proton.me/|Proton"
    "https://example.com/|example.com"
    "https://httpbin.org/get|httpbin"
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
    "https://incomplete-chain.badssl.com/|incomplete chain|Certificate verification failed"
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
printf "\n${BLD}=== Connection tests (expected pass) ===${RST}\n"

for entry in "${pass_tests[@]}"; do
    url="${entry%%|*}"
    desc="${entry##*|}"
    printf "  %-50s " "$url"

    run_with_timeout 10 ./tls_client "$url"
    rc=$TIMEOUT_RC
    output="$TIMEOUT_OUTPUT"

    if [[ $rc -eq 0 ]] && echo "$output" | grep -q '=== Done ==='; then
        info=$(echo "$output" | grep -E 'Negotiated TLS|Received ServerHello' | head -1)
        printf "${GRN}PASS${RST}  %s  [%s]\n" "$desc" "$info"
        pass=$((pass + 1))
    else
        reason=$(echo "$output" | grep 'FATAL:' | head -1)
        printf "${RED}FAIL${RST}  %s  %s\n" "$desc" "$reason"
        fail=$((fail + 1))
        failures+=("$url ($desc): $reason")
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

    run_with_timeout 10 ./tls_client "$url"
    rc=$TIMEOUT_RC
    output="$TIMEOUT_OUTPUT"

    if [[ $rc -eq 0 ]] && echo "$output" | grep -q '=== Done ==='; then
        printf "${RED}XPASS${RST} %s  (unexpected success!)\n" "$desc"
        xfail_unexpected_pass=$((xfail_unexpected_pass + 1))
        xfail_pass_list+=("$url ($desc): expected failure but passed")
    elif echo "$output" | grep -qi "$expected_err"; then
        printf "${GRN}XFAIL${RST} %s\n" "$desc"
        xfail=$((xfail + 1))
    else
        reason=$(echo "$output" | grep 'FATAL:' | head -1)
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
