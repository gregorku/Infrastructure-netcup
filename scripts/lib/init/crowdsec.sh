#!/usr/bin/env bash

###############################################################################
#
# Infrastructure-netcup Project
#
# File:
#   scripts/lib/init/crowdsec.sh
#
# Description:
#   Initialize CrowdSec runtime directories.
#
###############################################################################

init_crowdsec()
{
    print_section "CrowdSec"

    ensure_directory "${CROWDSEC_DIR}"
    ensure_directory "${CROWDSEC_DIR}/db"
    ensure_directory "${CROWDSEC_DIR}/data"
    ensure_directory "${CROWDSEC_DIR}/postgres"

    ok "CrowdSec runtime ready."
}
