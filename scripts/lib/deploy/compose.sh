#!/usr/bin/env bash
deploy_validate_compose() {
    print_section "Compose validation"
    check_compose_configuration
}
deploy_compose() {
    print_section "Infrastructure-netcup"
    log_info "Pulling images..."
    compose_pull
    log_info "Starting stack..."
    compose_up
    log_success "Infrastructure-netcup deployed."
}
