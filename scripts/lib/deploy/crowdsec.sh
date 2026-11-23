#!/usr/bin/env bash

###############################################################################
#
# Infrastructure-netcup Project
#
# File:
#   scripts/lib/deploy/crowdsec.sh
#
# Description:
#   Install CrowdSec HTTP parsers and scenarios.
#
# The stock collections crowdsecurity/traefik and
# crowdsecurity/base-http-scenarios are intentionally
# not installed. Both enable crowdsecurity/http-crawl-non_statics.
# That behavior is replaced by the mounted local scenario
# local/http-crawl-non_statics.
#
# Keep the item lists identical to the hub environment
# variables in compose/20-crowdsec.yml. Those variables
# are what the CrowdSec 1.7.8 image installs on every
# container start. This function repairs a container that
# was not recreated and reloads only after a real change.
#
###############################################################################

###############################################################################
# Hub items
#
# crowdsecurity/http-cve is installed as a collection.
# Its scenario list is read from the installed collection
# and any missing scenario is installed afterwards.
# Installing the collection alone is not treated as proof
# that every dependency is enabled.
###############################################################################

CROWDSEC_HTTP_PARSERS=(
    "crowdsecurity/traefik-logs"
    "crowdsecurity/http-logs"
)

CROWDSEC_HTTP_CONTEXTS=(
    "crowdsecurity/http_base"
)

CROWDSEC_HTTP_COLLECTIONS=(
    "crowdsecurity/http-cve"
)

CROWDSEC_HTTP_SCENARIOS=(
    "crowdsecurity/http-probing"
    "crowdsecurity/http-bad-user-agent"
    "crowdsecurity/http-path-traversal-probing"
    "crowdsecurity/http-sensitive-files"
    "crowdsecurity/http-sqli-probing"
    "crowdsecurity/http-xss-probing"
    "crowdsecurity/http-backdoors-attempts"
    "ltsich/http-w00tw00t"
    "crowdsecurity/http-generic-bf"
    "crowdsecurity/http-open-proxy"
    "crowdsecurity/http-admin-interface-probing"
    "crowdsecurity/http-wordpress-scan"
    "crowdsecurity/http-cve-probing"
    "crowdsecurity/http-sap-interface-probing"
    "crowdsecurity/http-generic-test"
    "crowdsecurity/http-technology-probing"
)

CROWDSEC_HTTP_FORBIDDEN=(
    "collections:crowdsecurity/traefik"
    "collections:crowdsecurity/base-http-scenarios"
    "scenarios:crowdsecurity/http-crawl-non_statics"
)

CROWDSEC_HTTP_RELOAD=0

CROWDSEC_HTTP_STAMP="${CROWDSEC_DIR}/.http-protection-stamp"

CROWDSEC_LOCAL_SCENARIO="local/http-crawl-non_statics"

CROWDSEC_LOCAL_SCENARIO_FILE="/etc/crowdsec/scenarios/http-crawl-non_statics.yaml"

###############################################################################
# Reject items that would enable the stock crawl scenario
###############################################################################

crowdsec_reject_item()
{
    local name="$1"

    case "${name}" in
        crowdsecurity/traefik|\
        crowdsecurity/base-http-scenarios|\
        crowdsecurity/http-crawl-non_statics)
            fail "Refusing to install ${name}."
            ;;
    esac
}

###############################################################################
# Install one hub item
#
# cscli install is idempotent. An item that is already
# installed and not tainted prints "Nothing to install
# or remove." and is left untouched.
###############################################################################

crowdsec_install_item()
{
    local item_type="$1"
    local name="$2"
    local output

    crowdsec_reject_item "${name}"

    if ! output="$(
        docker_exec "${CROWDSEC_SERVICE}" \
            cscli "${item_type}" install "${name}" 2>&1
    )"; then
        printf '%s\n' "${output}" >&2
        fail "Unable to install ${item_type} ${name}."
    fi

    local changed=0
    local unchanged=0

    if grep -F 'is tainted' <<< "${output}" >/dev/null; then
        printf '%s\n' "${output}" >&2
        fail "Hub item is tainted and was left unchanged: ${item_type} ${name}."
    fi

    if grep -F 'Nothing to install or remove.' <<< "${output}" >/dev/null; then
        unchanged=1
    fi

    if grep -F 'enabling ' <<< "${output}" >/dev/null \
        || grep -F 'downloading ' <<< "${output}" >/dev/null; then
        changed=1
    fi

    if [[ "${changed}" -eq 1 && "${unchanged}" -eq 1 ]]; then
        printf '%s\n' "${output}" >&2
        fail "Ambiguous cscli result for ${item_type} ${name}."
    fi

    if [[ "${changed}" -eq 0 && "${unchanged}" -eq 0 ]]; then
        printf '%s\n' "${output}" >&2
        fail "Unexpected cscli result for ${item_type} ${name}."
    fi

    if [[ "${unchanged}" -eq 1 ]]; then
        ok "Already installed: ${name}"
        return 0
    fi

    printf '%s\n' "${output}"
    CROWDSEC_HTTP_RELOAD=1
    ok "Installed: ${name}"
}

###############################################################################
# Install a list of one hub type
###############################################################################

crowdsec_install_list()
{
    local item_type="$1"
    shift

    local name

    for name in "$@"; do
        crowdsec_install_item "${item_type}" "${name}"
    done
}

###############################################################################
# Scenarios declared by an installed collection
###############################################################################

crowdsec_collection_scenarios()
{
    local collection="$1"

    #
    # crowdsecurity/http-cve 3.0, the version served to
    # CrowdSec 1.7.8, looks like:
    #
    #   scenarios:
    #     - crowdsecurity/http-cve-2021-41773
    #   author: crowdsecurity
    #
    # The list ends at the next top-level key. Tags under
    # labels: are not part of it. Only author/name items
    # are emitted.
    #

    # $0 is awk's current record, not a shell expansion.
    # shellcheck disable=SC2016
    docker_exec "${CROWDSEC_SERVICE}" \
        awk '
            /^scenarios:[[:space:]]*$/ { in_scenarios = 1; next }
            in_scenarios && /^[^[:space:]#]/ { in_scenarios = 0 }
            in_scenarios && /^[[:space:]]+-[[:space:]]+/ {
                sub(/^[[:space:]]+-[[:space:]]+/, "")
                sub(/[[:space:]]+$/, "")
                if ($0 ~ /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/) {
                    print
                } else {
                    printf "invalid scenario entry: %s\n", $0 > "/dev/stderr"
                    exit 1
                }
            }
        ' "/etc/crowdsec/collections/${collection##*/}.yaml"
}

###############################################################################
# Install any collection scenario that is still missing
###############################################################################

CROWDSEC_HTTP_COLLECTION_SCENARIOS=()

crowdsec_install_collection_scenarios()
{
    local collection="$1"
    local parsed=""
    local scenario
    local found=0

    if ! parsed="$(crowdsec_collection_scenarios "${collection}")"; then
        printf '%s\n' "${parsed}" >&2
        fail "Unable to read scenarios from collection ${collection}."
    fi

    while IFS= read -r scenario; do
        [[ -n "${scenario}" ]] || continue

        crowdsec_reject_item "${scenario}"

        CROWDSEC_HTTP_COLLECTION_SCENARIOS+=("${scenario}")
        found=$((found + 1))
        crowdsec_install_item "scenarios" "${scenario}"
    done <<< "${parsed}"

    [[ "${found}" -gt 0 ]] \
        || fail "Collection declares no scenarios: ${collection}"

    ok "Collection ${collection} declares ${found} scenarios."
}

###############################################################################
# Hub inventory, fetched once per item type
###############################################################################

crowdsec_listing()
{
    local item_type="$1"

    docker_exec "${CROWDSEC_SERVICE}" \
        cscli "${item_type}" list -o raw
}

crowdsec_listing_has()
{
    local listing="$1"
    local name="$2"

    awk -F, -v item="${name}" '$1 == item { found = 1 } END { exit found ? 0 : 1 }' <<< "${listing}"
}

crowdsec_listing_enabled()
{
    local listing="$1"
    local name="$2"

    #
    # Raw status is "enabled", or "enabled,local" which CSV
    # quoting splits so the second field starts with enabled.
    #

    awk -F, -v item="${name}" '
        $1 == item && $2 ~ /^"?enabled/ { found = 1 }
        END { exit found ? 0 : 1 }
    ' <<< "${listing}"
}

###############################################################################
# Wait until the engine process is running and LAPI answers
#
# A running process is not enough: cscli is usable while the
# image entrypoint is still installing hub items, and the
# process can exist before Local API accepts authentication.
# CrowdSec 1.7.8 reports success with this exact sentence.
###############################################################################

crowdsec_lapi_status()
{
    local output=""
    local status=0

    if command -v timeout >/dev/null 2>&1; then
        output="$(
            timeout 15 docker exec "${CROWDSEC_SERVICE}" \
                cscli lapi status 2>&1
        )" || status=$?
    else
        output="$(
            docker exec "${CROWDSEC_SERVICE}" \
                cscli lapi status 2>&1
        )" || status=$?
    fi

    [[ "${status}" -eq 0 ]] || return 1

    grep -F 'You can successfully interact with Local API' <<< "${output}" >/dev/null
}

crowdsec_wait_ready()
{
    local attempt

    info "Waiting for CrowdSec..."

    for attempt in $(seq 1 90); do
        if docker_container_running "${CROWDSEC_SERVICE}" \
            && docker_exec "${CROWDSEC_SERVICE}" \
                sh -c 'grep -lx "^crowdsec$" /proc/[0-9]*/comm >/dev/null 2>&1' \
            && crowdsec_lapi_status
        then
            ok "CrowdSec engine is ready."
            return 0
        fi

        sleep 2
    done

    fail "Timed out waiting for CrowdSec."
}

###############################################################################
# Reload the running engine after a hub or scenario change
###############################################################################

crowdsec_reload()
{
    info "Reloading CrowdSec configuration..."

    # The process id is resolved inside the container.
    # shellcheck disable=SC2016
    docker_exec "${CROWDSEC_SERVICE}" \
        sh -c 'kill -HUP "$(grep -l "^crowdsec$" /proc/[0-9]*/comm | head -n 1 | cut -d/ -f3)"' \
        || fail "Unable to reload CrowdSec."

    ok "CrowdSec reloaded."
}

###############################################################################
# Local scenario file mounted into the container
###############################################################################

crowdsec_assert_local_scenario()
{
    local listing="$1"
    local inspected=""

    docker_exec "${CROWDSEC_SERVICE}" \
        sh -c "test -f '${CROWDSEC_LOCAL_SCENARIO_FILE}' && test ! -L '${CROWDSEC_LOCAL_SCENARIO_FILE}'" \
        || fail "Local scenario file is missing: ${CROWDSEC_LOCAL_SCENARIO_FILE}"

    if ! inspected="$(
        docker_exec "${CROWDSEC_SERVICE}" \
            cscli scenarios inspect "${CROWDSEC_LOCAL_SCENARIO}" \
                --no-metrics \
                -o json
    )"; then
        printf '%s\n' "${inspected}" >&2
        fail "Unable to inspect ${CROWDSEC_LOCAL_SCENARIO}."
    fi

    grep -F '"name": "local/http-crawl-non_statics"' <<< "${inspected}" >/dev/null \
        || fail "Local scenario name is not ${CROWDSEC_LOCAL_SCENARIO}."

    grep -F '"local_path": "/etc/crowdsec/scenarios/http-crawl-non_statics.yaml"' <<< "${inspected}" >/dev/null \
        || fail "Local scenario is not loaded from ${CROWDSEC_LOCAL_SCENARIO_FILE}."

    grep -F '"installed": true' <<< "${inspected}" >/dev/null \
        || fail "Local scenario is not installed."

    grep -F '"local": true' <<< "${inspected}" >/dev/null \
        || fail "Local scenario is not a local item."

    crowdsec_listing_enabled "${listing}" "${CROWDSEC_LOCAL_SCENARIO}" \
        || fail "Local scenario is not enabled: ${CROWDSEC_LOCAL_SCENARIO}"

    ok "Local scenario loaded: ${CROWDSEC_LOCAL_SCENARIO}"
}

###############################################################################
# Scenario names from the Scenarios section of cscli explain
#
# A name that only appears in the raw log line is ignored.
# $0 is awk's current record.
###############################################################################

# shellcheck disable=SC2016
crowdsec_explain_scenario_names()
{
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

crowdsec_assert_explain()
{
    local line="$1"
    local expected="$2"
    local explained=""
    local matched=""
    local required

    shift 2

    if ! explained="$(
        docker_exec "${CROWDSEC_SERVICE}" \
            cscli explain \
                --color no \
                --type traefik \
                -v \
                -l "${line}"
    )"; then
        printf '%s\n' "${explained}" >&2
        fail "cscli explain failed."
    fi

    grep -F 'parser success' <<< "${explained}" >/dev/null \
        || fail "cscli explain did not parse the sample line."

    # shellcheck disable=SC2016
    awk '$0 ~ /Scenarios$/ { found = 1 } END { exit found ? 0 : 1 }' <<< "${explained}" \
        || fail "cscli explain did not reach the Scenarios section."

    for required in "$@"; do
        grep -F "${required}" <<< "${explained}" >/dev/null \
            || fail "cscli explain is missing ${required}."
    done

    matched="$(crowdsec_explain_scenario_names <<< "${explained}" | LC_ALL=C sort)"

    if [[ "${matched}" != "${expected}" ]]; then
        printf '%s\n' "${explained}" >&2
        fail "Unexpected cscli explain result."
    fi
}

###############################################################################
# Prove the running engine loaded the local scenario
###############################################################################

crowdsec_assert_runtime_scenarios()
{
    local git_objects
    local other_path
    local traversal

    git_objects='203.0.113.10 - - [23/Nov/2026:18:00:00 +0000] "GET /remote.php/dav/files/gregor/GitHub/NixOS/.git/objects/ab/cdef123 HTTP/1.1" 200 128 "-" "git/2.43.0" 15 "nextcloud-gr@file" "-" 4ms'
    other_path='203.0.113.10 - - [23/Nov/2026:18:00:01 +0000] "GET /remote.php/dav/files/gregor/Documents/notes.md HTTP/1.1" 200 128 "-" "Mozilla/5.0" 16 "nextcloud-gr@file" "-" 4ms'
    traversal='203.0.113.50 - - [23/Nov/2026:18:00:02 +0000] "GET /../../etc/passwd HTTP/1.1" 404 12 "-" "curl/8.0" 3 "other@file" "-" 2ms'

    crowdsec_assert_explain "${git_objects}" "" \
        "create evt.Meta.traefik_router_name : nextcloud-gr@file" \
        "create evt.Meta.http_path : /remote.php/dav/files/gregor/GitHub/NixOS/.git/objects/ab/cdef123" \
        "create evt.Parsed.static_ressource : false" \
        "create evt.Parsed.verb : GET"

    crowdsec_assert_explain "${other_path}" "local/http-crawl-non_statics" \
        "create evt.Meta.traefik_router_name : nextcloud-gr@file" \
        "create evt.Meta.http_path : /remote.php/dav/files/gregor/Documents/notes.md" \
        "create evt.Parsed.static_ressource : false" \
        "create evt.Parsed.verb : GET"

    crowdsec_assert_explain "${traversal}" "$(
        printf '%s\n' \
            crowdsecurity/http-path-traversal-probing \
            crowdsecurity/http-probing \
            local/http-crawl-non_statics \
            | LC_ALL=C sort
    )"

    ok "Running engine matches the expected scenarios."
}

###############################################################################
# Record the scenario hash only after install and validation
###############################################################################

crowdsec_write_stamp()
{
    local scenario_hash="$1"
    local temporary="${CROWDSEC_HTTP_STAMP}.tmp"

    mkdir -p "${CROWDSEC_DIR}" \
        || fail "Unable to create ${CROWDSEC_DIR}."

    printf '%s\n' "${scenario_hash}" > "${temporary}" \
        || fail "Unable to write ${temporary}."

    mv "${temporary}" "${CROWDSEC_HTTP_STAMP}" \
        || fail "Unable to publish ${CROWDSEC_HTTP_STAMP}."
}

###############################################################################
# Hash of the scenario file synced into the stack
###############################################################################

crowdsec_scenario_hash()
{
    local scenario_path

    scenario_path="${STACK_DIR}/configs/crowdsec/scenarios/http-crawl-non_statics.yaml"

    [[ -f "${scenario_path}" ]] \
        || fail "Missing local scenario: ${scenario_path}"

    sha256sum "${scenario_path}" | awk '{ print $1 }'
}

###############################################################################
# Install HTTP protection
###############################################################################

deploy_crowdsec()
{
    print_section "CrowdSec HTTP"

    local scenario_hash
    local previous_hash
    local forbidden
    local item_type
    local name
    local collection
    local parsers
    local contexts
    local collections
    local scenarios
    local listing

    CROWDSEC_HTTP_RELOAD=0
    CROWDSEC_HTTP_COLLECTION_SCENARIOS=()

    crowdsec_wait_ready

    scenario_hash="$(crowdsec_scenario_hash)"
    previous_hash=""

    if [[ -f "${CROWDSEC_HTTP_STAMP}" ]]; then
        previous_hash="$(<"${CROWDSEC_HTTP_STAMP}")"
    fi

    if [[ "${scenario_hash}" != "${previous_hash}" ]]; then
        CROWDSEC_HTTP_RELOAD=1
    fi

    crowdsec_install_list "parsers" "${CROWDSEC_HTTP_PARSERS[@]}"
    crowdsec_install_list "contexts" "${CROWDSEC_HTTP_CONTEXTS[@]}"
    crowdsec_install_list "collections" "${CROWDSEC_HTTP_COLLECTIONS[@]}"
    crowdsec_install_list "scenarios" "${CROWDSEC_HTTP_SCENARIOS[@]}"

    for collection in "${CROWDSEC_HTTP_COLLECTIONS[@]}"; do
        crowdsec_install_collection_scenarios "${collection}"
    done

    parsers="$(crowdsec_listing parsers)"
    contexts="$(crowdsec_listing contexts)"
    collections="$(crowdsec_listing collections)"
    scenarios="$(crowdsec_listing scenarios)"

    for forbidden in "${CROWDSEC_HTTP_FORBIDDEN[@]}"; do
        item_type="${forbidden%%:*}"
        name="${forbidden#*:}"

        case "${item_type}" in
            parsers) listing="${parsers}" ;;
            contexts) listing="${contexts}" ;;
            collections) listing="${collections}" ;;
            scenarios) listing="${scenarios}" ;;
            *) fail "Unknown hub item type: ${item_type}" ;;
        esac

        if crowdsec_listing_has "${listing}" "${name}"; then
            fail "Forbidden ${item_type} item is installed: ${name}"
        fi

        ok "Not installed: ${name}"
    done

    crowdsec_assert_local_scenario "${scenarios}"

    for name in "${CROWDSEC_HTTP_PARSERS[@]}"; do
        crowdsec_listing_enabled "${parsers}" "${name}" \
            || fail "Missing parser: ${name}"
        ok "Enabled: ${name}"
    done

    for name in "${CROWDSEC_HTTP_CONTEXTS[@]}"; do
        crowdsec_listing_enabled "${contexts}" "${name}" \
            || fail "Missing context: ${name}"
        ok "Enabled: ${name}"
    done

    for name in "${CROWDSEC_HTTP_COLLECTIONS[@]}"; do
        crowdsec_listing_enabled "${collections}" "${name}" \
            || fail "Missing collection: ${name}"
        ok "Enabled: ${name}"
    done

    for name in "${CROWDSEC_HTTP_SCENARIOS[@]}"; do
        crowdsec_listing_enabled "${scenarios}" "${name}" \
            || fail "Missing scenario: ${name}"
        ok "Enabled: ${name}"
    done

    for name in "${CROWDSEC_HTTP_COLLECTION_SCENARIOS[@]}"; do
        crowdsec_reject_item "${name}"
        crowdsec_listing_enabled "${scenarios}" "${name}" \
            || fail "Missing collection scenario: ${name}"
    done

    if [[ "${CROWDSEC_HTTP_RELOAD}" -eq 1 ]]; then
        crowdsec_reload
        crowdsec_wait_ready
    else
        ok "CrowdSec configuration unchanged."
        crowdsec_lapi_status \
            || fail "CrowdSec stopped responding before the result was recorded."
    fi

    #
    # Explain talks to the running engine. A process or a
    # successful install is not enough. fail() exits before
    # the stamp is published.
    #

    crowdsec_assert_runtime_scenarios

    #
    # The hash is published only after every install and
    # validation above returned. fail() exits before this
    # line, so a failed run cannot look like a success.
    #

    crowdsec_write_stamp "${scenario_hash}"

    ok "CrowdSec HTTP protection ready."
}
