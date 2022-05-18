#!/usr/bin/env bash

set -euo pipefail
[[ $TRACE_ENABLED == "true" ]] && set -x

source ${GITHUB_ACTION_PATH}/common.sh

echo "------------------------------------------------------------------------------"
if [[ (-d ${RELEASE_PRE_SCRIPTS}) && (${MAVEN_RELEASE_EXECUTE_PRE_SCRIPTS} == "true") ]]
then
  # Make the release Maven project version available to any scripts
  echo "Running release pre actions for version ${MAVEN_PROJECT_VERSION}"
  echo "------------------------------------------------------------------------------"
  for script in "${RELEASE_PRE_SCRIPTS}"/*
  do
    if [[ -x "${script}" ]]
    then
      echo "Running pre action ${script}"
      ${script} ${MAVEN_PROJECT_VERSION}
      echo "------------------------------------------------------------------------------"
    fi
  done
  set_output "executed" "true"
else
  echo "!!! Skipping running release pre actions as ${RELEASE_PRE_SCRIPTS} does not exist"
  set_output "executed" "true"
fi
echo "------------------------------------------------------------------------------"
