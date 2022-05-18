#!/usr/bin/env bash

set -euo pipefail
[[ $TRACE_ENABLED == "true" ]] && set -x

source ${GITHUB_ACTION_PATH}/common.sh

# ------------------------------------------------------------------------------
# Running release:prepare
# ------------------------------------------------------------------------------
echo
echo "------------------------------------------------------------------------------"
echo "Executing release:prepare using -Darguments=\"${MAVEN_RELEASE_ARGUMENTS}\" ${RELEASE_ARGUMENTS}"
echo "------------------------------------------------------------------------------"
${MAVEN_BIN} -B release:prepare -Darguments="${MAVEN_RELEASE_ARGUMENTS}" ${RELEASE_ARGUMENTS}
echo "------------------------------------------------------------------------------"
set_output "executed" "true"
