#!/usr/bin/env bash

set -euo pipefail
[[ $TRACE_ENABLED == "true" ]] && set -x

source ${GITHUB_ACTION_PATH}/common.sh

# ------------------------------------------------------------------------------
# Fail is the Maven Wrapper is not present in repository we are releasing from
# ------------------------------------------------------------------------------
if [[ ! -f ${MAVEN_BIN} ]]
then
  echo
  echo "!!! Cannot perform release because the Maven Wrapper is not present in ${MAVEN_BIN}"
  exit 1
fi

# ------------------------------------------------------------------------------
# We don't want to attempt a release if the last commit is from the automation
# user that performed a release.
# ------------------------------------------------------------------------------
lastReleaseSha1=$(git log --author="${GIT_USER_NAME}" --pretty=format:"%H" -1)
if [[ "${lastReleaseSha1}" = "${GITHUB_SHA}" ]]
then
  echo "Skipping release: the latest commit ${GITHUB_SHA} is release commit from ${GIT_USER_NAME}. There are no new commits to release."
  exit 1
fi
