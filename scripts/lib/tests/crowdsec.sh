#!/usr/bin/env bash

###############################################################################
#
# Infrastructure-netcup Project
#
# File:
#   scripts/lib/tests/crowdsec.sh
#
# Description:
#   CrowdSec tests.
#
###############################################################################

#
# Names poured by the event. Only the section after the
# Scenarios header counts. A name printed earlier, for
# example inside the raw log line, is not a match.
#

crowdsec_explain_scenario_names()
{
    # $0 is awk's current record, not a shell expansion.
    # shellcheck disable=SC2016
    awk '
        found {
            count = split($0, fields, /[[:space:]]+/)
            if (count > 0 && fields[count] ~ /\//) {
                print fields[count]
            }
            next
        }
        $0 ~ /Scenarios$/ { found = 1 }
    '
}

crowdsec_explain_has_header()
{
    # shellcheck disable=SC2016
    awk '$0 ~ /Scenarios$/ { found = 1 } END { exit found ? 0 : 1 }'
}

#
# cscli list -o raw is name,status,version,description.
# A hub item is "name,enabled,". The local scenario is
# name,"enabled,local", because the status itself
# contains a comma. Basic regex, anchored.
#

crowdsec_raw_enabled()
{
    local listing="$1"
    local name="$2"

    if [[ "${name}" == local/* ]]; then
        grep "^${name},\"enabled,local\"," <<< "${listing}" >/dev/null
    else
        grep "^${name},enabled," <<< "${listing}" >/dev/null
    fi
}

crowdsec_raw_absent()
{
    local listing="$1"
    local name="$2"

    if grep "^${name}," <<< "${listing}" >/dev/null; then
        return 1
    fi
}

test_crowdsec()
{
    print_section "CrowdSec"

    docker_container_running "${CROWDSEC_SERVICE}"

    ok "CrowdSec container OK."

    #
    # Same hub items as deploy_crowdsec and the 1.7.8
    # image environment. The two collections below stay
    # absent because both enable the stock crawl scenario.
    #

    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/lib/deploy/crowdsec.sh"

    local parsers
    local contexts
    local collections
    local scenarios
    local name
    local inspected

    parsers="$(docker exec crowdsec cscli parsers list -o raw)"
    contexts="$(docker exec crowdsec cscli contexts list -o raw)"
    collections="$(docker exec crowdsec cscli collections list -o raw)"
    scenarios="$(docker exec crowdsec cscli scenarios list -o raw)"

    for name in "${CROWDSEC_HTTP_PARSERS[@]}"; do
        crowdsec_raw_enabled "${parsers}" "${name}" \
            || fail "Parser is not enabled: ${name}"
        ok "Enabled: ${name}"
    done

    for name in "${CROWDSEC_HTTP_CONTEXTS[@]}"; do
        crowdsec_raw_enabled "${contexts}" "${name}" \
            || fail "Context is not enabled: ${name}"
        ok "Enabled: ${name}"
    done

    for name in "${CROWDSEC_HTTP_COLLECTIONS[@]}"; do
        crowdsec_raw_enabled "${collections}" "${name}" \
            || fail "Collection is not enabled: ${name}"
        ok "Enabled: ${name}"
    done

    for name in "${CROWDSEC_HTTP_SCENARIOS[@]}"; do
        crowdsec_raw_enabled "${scenarios}" "${name}" \
            || fail "Scenario is not enabled: ${name}"
        ok "Enabled: ${name}"
    done

    crowdsec_raw_absent "${collections}" "crowdsecurity/traefik" \
        || fail "Traefik collection must stay uninstalled."
    ok "Traefik collection is not installed."

    crowdsec_raw_absent "${collections}" "crowdsecurity/base-http-scenarios" \
        || fail "base-http-scenarios must stay uninstalled."
    ok "base-http-scenarios is not installed."

    crowdsec_raw_enabled "${scenarios}" "local/http-crawl-non_statics" \
        || fail "Local crawl scenario missing."
    ok "Local crawl scenario OK."

    crowdsec_raw_absent "${scenarios}" "crowdsecurity/http-crawl-non_statics" \
        || fail "Stock crawl scenario must stay uninstalled."
    ok "Stock crawl scenario is not installed."

    docker exec crowdsec \
        sh -c 'test -f /etc/crowdsec/scenarios/http-crawl-non_statics.yaml && test ! -L /etc/crowdsec/scenarios/http-crawl-non_statics.yaml' \
        || fail "Local scenario file is missing or is a hub symlink."

    inspected="$(
        docker exec crowdsec \
            cscli scenarios inspect local/http-crawl-non_statics \
                --no-metrics \
                -o json
    )"

    grep -F '"name": "local/http-crawl-non_statics"' <<< "${inspected}" >/dev/null \
        || fail "Local scenario name is not local/http-crawl-non_statics."

    grep -F '"local_path": "/etc/crowdsec/scenarios/http-crawl-non_statics.yaml"' <<< "${inspected}" >/dev/null \
        || fail "Local scenario is not loaded from /etc/crowdsec/scenarios/http-crawl-non_statics.yaml."

    grep -F '"installed": true' <<< "${inspected}" >/dev/null \
        || fail "Local scenario is not installed."

    grep -F '"local": true' <<< "${inspected}" >/dev/null \
        || fail "Local scenario is not a local item."

    ok "Local scenario file and inspect OK."

    #
    # Representative Traefik lines.
    # One event does not overflow the leaky bucket. The
    # scenario names are taken only from the Scenarios
    # section, as exact final fields.
    #

    local explained
    local matched

    explained="$(
        docker exec crowdsec \
            cscli explain \
                --color no \
                --type traefik \
                -v \
                -l '203.0.113.10 - - [23/Nov/2026:18:00:00 +0000] "GET /remote.php/dav/files/gregor/GitHub/NixOS/.git/objects/ab/cdef123 HTTP/1.1" 200 128 "-" "git/2.43.0" 15 "nextcloud-gr@file" "-" 4ms'
    )"

    matched="$(crowdsec_explain_scenario_names <<< "${explained}" | LC_ALL=C sort)"

    if crowdsec_explain_has_header <<< "${explained}" \
        && grep -F "parser success" <<< "${explained}" >/dev/null \
        && grep -F "create evt.Meta.traefik_router_name : nextcloud-gr@file" <<< "${explained}" >/dev/null \
        && grep -F "create evt.Meta.http_path : /remote.php/dav/files/gregor/GitHub/NixOS/.git/objects/ab/cdef123" <<< "${explained}" >/dev/null \
        && grep -F "create evt.Parsed.static_ressource : false" <<< "${explained}" >/dev/null \
        && grep -F "create evt.Parsed.verb : GET" <<< "${explained}" >/dev/null \
        && [[ -z "${matched}" ]]
    then
        ok "Nextcloud Git objects are excluded."
    else
        printf '%s\n' "${matched}" >&2
        fail "Nextcloud Git objects were not excluded."
    fi

    explained="$(
        docker exec crowdsec \
            cscli explain \
                --color no \
                --type traefik \
                -v \
                -l '203.0.113.10 - - [23/Nov/2026:18:00:01 +0000] "GET /remote.php/dav/files/gregor/Documents/notes.md HTTP/1.1" 200 128 "-" "Mozilla/5.0" 16 "nextcloud-gr@file" "-" 4ms'
    )"

    matched="$(crowdsec_explain_scenario_names <<< "${explained}" | LC_ALL=C sort)"

    if crowdsec_explain_has_header <<< "${explained}" \
        && grep -F "create evt.Meta.http_path : /remote.php/dav/files/gregor/Documents/notes.md" <<< "${explained}" >/dev/null \
        && [[ "${matched}" == "local/http-crawl-non_statics" ]]
    then
        ok "Other Nextcloud paths stay in the crawl scenario."
    else
        printf '%s\n' "${matched}" >&2
        fail "Other Nextcloud paths bypass the crawl scenario."
    fi

    explained="$(
        docker exec crowdsec \
            cscli explain \
                --color no \
                --type traefik \
                -v \
                -l '203.0.113.50 - - [23/Nov/2026:18:00:02 +0000] "GET /../../etc/passwd HTTP/1.1" 404 12 "-" "curl/8.0" 3 "other@file" "-" 2ms'
    )"

    matched="$(crowdsec_explain_scenario_names <<< "${explained}" | LC_ALL=C sort)"

    if crowdsec_explain_has_header <<< "${explained}" \
        && [[ "${matched}" == "$(printf '%s\n' \
            crowdsecurity/http-path-traversal-probing \
            crowdsecurity/http-probing \
            local/http-crawl-non_statics | LC_ALL=C sort)" ]]
    then
        ok "Path traversal probing still matches."
    else
        printf '%s\n' "${matched}" >&2
        fail "Path traversal probing did not match."
    fi

    #
    # Traefik bouncer
    #

    local bouncers

    bouncers="$(docker exec crowdsec cscli bouncers list)"

    if grep -w "traefik" <<< "${bouncers}" >/dev/null
    then
        ok "Traefik bouncer OK."
    else
        fail "Traefik bouncer missing."
    fi

    #
    # Access log acquisition
    #
    # Right after a restart, CrowdSec's file tailer starts
    # reading from the END of access.log -- it has nothing
    # to report until at least one new request comes in.
    # Generate one ourselves so the check isn't racy.
    #

    docker exec traefik \
        wget --no-check-certificate -q -O /dev/null \
        "https://127.0.0.1:8443/dashboard/" \
        2>/dev/null || true

    local metrics
    acquisition_ok=false

    for _ in 1 2 3 4 5 6 7 8 9 10
    do
        metrics="$(docker exec crowdsec cscli metrics 2>/dev/null || true)"

        if grep -F "file:/logs/access.log" <<< "${metrics}" >/dev/null
        then
            acquisition_ok=true
            break
        fi

        sleep 1
    done

    if [ "${acquisition_ok}" = true ]
    then
        ok "Access log acquisition OK."
    else
        fail "Access log acquisition missing."
    fi
}
