#!/usr/bin/env bash

set -euo pipefail
[[ $TRACE_ENABLED == "true" ]] && set -x

source ${GITHUB_ACTION_PATH}/common.sh

echo "------------------------------------------------------------------------------"
if [[ (-d ${RELEASE_POST_SCRIPTS}) && (${MAVEN_RELEASE_EXECUTE_POST_SCRIPTS} == "true") ]]
then
  # Make the release Maven project version available to any scripts
  echo "Running release post actions for version ${MAVEN_PROJECT_VERSION}"
  echo "------------------------------------------------------------------------------"
  for script in "${RELEASE_POST_SCRIPTS}"/*
  do
    if [[ -x "${script}" ]]
    then
      echo "Running post action ${script}"
      ${script} ${MAVEN_PROJECT_VERSION}
      echo "------------------------------------------------------------------------------"
    fi
  done
  set_output "executed" "true"
else
  echo "!!! Skipping running release post actions as ${RELEASE_POST_SCRIPTS} does not exist"
  set_output "executed" "true"
fi
echo "------------------------------------------------------------------------------"
