#!/usr/bin/env bash

###############################################################################
#
# Infrastructure-netcup Project
#
# File:
#   scripts/lib/init/watchtower.sh
#
# Description:
#   Initialize Watchtower directory structure.
#
###############################################################################

init_watchtower()
{
    print_section "Watchtower"

    ensure_directory "${WATCHTOWER_DIR}"

    ok "Watchtower layout ready."
}