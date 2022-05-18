#!/usr/bin/env bash

set -euo pipefail
[[ $TRACE_ENABLED == "true" ]] && set -x

source ${GITHUB_ACTION_PATH}/common.sh

if [[ "${MAVEN_RELEASE_VERSION}" != "" ]]; then
  version="${MAVEN_RELEASE_VERSION}"
else
  version=$(mavenProjectVersion | sed 's/-SNAPSHOT//')
fi

set_output "version" "${version}"
echo "MAVEN_PROJECT_VERSION=${version}" >> $GITHUB_ENV

echo "Releasing project version ${version}"
