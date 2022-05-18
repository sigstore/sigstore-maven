#!/usr/bin/env bash

set -euo pipefail
[[ $TRACE_ENABLED == "true" ]] && set -x

source ${GITHUB_ACTION_PATH}/common.sh

# ------------------------------------------------------------------------------
# Running release:perform
# ------------------------------------------------------------------------------
echo "------------------------------------------------------------------------------"
if [[ "${MAVEN_RELEASE_EXECUTE_PERFORM}" == "true" ]]
then
  echo
  echo "Executing release:perform using -Darguments=\"${MAVEN_RELEASE_ARGUMENTS}\""
  echo "------------------------------------------------------------------------------"
  ${MAVEN_BIN} -B release:perform -Darguments="${MAVEN_RELEASE_ARGUMENTS}"
  set_output "executed" "true"
else
  echo "Skipped release:perform"
  set_output "executed" "false"
fi
echo "------------------------------------------------------------------------------"
