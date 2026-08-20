#!/usr/bin/env bash

###############################################################################
#
# Infrastructure-netcup Project
#
# File:
#   scripts/lib/tests/summary.sh
#
# Description:
#   Print Infrastructure-netcup test summary.
#
###############################################################################

###############################################################################
# Test summary
###############################################################################

test_summary()
{
    print_section "Finished"

    ok "Infrastructure-netcup tests completed."

    echo

    info "Review the output above for warnings or failures."

    echo

    ok "Test summary completed."
}