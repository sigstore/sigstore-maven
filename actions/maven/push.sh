#!/usr/bin/env bash

set -euo pipefail
[[ $TRACE_ENABLED == "true" ]] && set -x

source ${GITHUB_ACTION_PATH}/common.sh

function fail_with_msg() {
  # $1 = message
  echo "::error::${1}"
  set_output "executed" "false"
  exit 1
}

# ------------------------------------------------------------------------------
# Push the release commits and tags
# ------------------------------------------------------------------------------
echo "------------------------------------------------------------------------------"
if [[ "${MAVEN_RELEASE_PUSH_COMMITS}" == "true" ]]
then
  echo
  echo "Pushing release commits and tag"
  echo "------------------------------------------------------------------------------"
  if [[ -n ${RELEASE_BRANCH_NAME} ]]; then
    git push origin HEAD:refs/heads/${RELEASE_BRANCH_NAME} || fail_with_msg "Failed to push release commit"
  fi
  git push origin ${MAVEN_PROJECT_VERSION} || fail_with_msg "Failed to push release tag"
  set_output "executed" "true"
else
  echo "Skipped pushing release commits and tag"
  [[ -n ${RELEASE_BRANCH_NAME} ]] && echo "Branch to be pushed: origin HEAD:refs/heads/${RELEASE_BRANCH_NAME}"
  echo "Tag to be pushed: ${MAVEN_PROJECT_VERSION}"
  set_output "executed" "false"
fi
echo "------------------------------------------------------------------------------"
