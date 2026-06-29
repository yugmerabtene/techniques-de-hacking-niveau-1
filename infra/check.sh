#!/bin/bash
# =====================================================================
# check.sh — Wrapper qui exécute check_all_services.sh avec docker
# =====================================================================
exec newgrp docker <<< "$(dirname "$0")/check_all_services.sh"
