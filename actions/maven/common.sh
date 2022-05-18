#!/usr/bin/env bash

[[ $TRACE_ENABLED == "true" ]] && set -x

if [[ -f "${MAVEN_RELEASE_SETTINGS_XML}" ]]
then
  # Use the provided Maven settings.xml
  echo
  echo "------------------------------------------------------------------------------"
  echo "Using the provided Maven settings: ${MAVEN_RELEASE_SETTINGS_XML}"
  echo "------------------------------------------------------------------------------"
  export MAVEN_CONFIG="-s ${MAVEN_RELEASE_SETTINGS_XML}"
else
  # Use the template we provide that resides in the docker image
  echo
  echo "------------------------------------------------------------------------------"
  echo "Using the built-in Maven settings template as ${MAVEN_RELEASE_SETTINGS_XML} does not exist"
  echo "------------------------------------------------------------------------------"
  export MAVEN_CONFIG="-s ${GITHUB_ACTION_PATH}/settings.xml"
fi

RELEASE_ARGUMENTS="${RELEASE_ARGUMENTS:-}"

if [[ ! -z "${MAVEN_RELEASE_TAG}" ]];
then
  RELEASE_ARGUMENTS="${RELEASE_ARGUMENTS} -Dtag=${MAVEN_RELEASE_TAG}"
fi

if [[ ! -z "${MAVEN_RELEASE_VERSION}" ]];
then
  RELEASE_ARGUMENTS="${RELEASE_ARGUMENTS} -DreleaseVersion=${MAVEN_RELEASE_VERSION}"
fi

if [[ ! -z "${MAVEN_NEXT_DEVELOPMENT_VERSION}" ]];
then
  RELEASE_ARGUMENTS="${RELEASE_ARGUMENTS} -DdevelopmentVersion=${MAVEN_NEXT_DEVELOPMENT_VERSION}"
fi

export RELEASE_ARGUMENTS="${RELEASE_ARGUMENTS}"

function mavenCoordinateToArtifactPath() {
  # Standard format for a Maven coordinate:
  # <groupId>:<artifactId>[:<extension>[:classifier]]:<version>
  # $1 = coordinate
  IFS=':' read -ra coordinateParts <<< "$1"
  groupId=$(echo ${coordinateParts[0]} | sed 's/\./\//g')
  artifactId=${coordinateParts[1]}
  if [ ${#coordinateParts[@]} -eq 3 ]; then
    # <groupId>:<artifactId>:<version>
    version=${coordinateParts[2]}
    artifactPath="${groupId}/${artifactId}/${version}/${artifactId}-${version}.jar"
  elif [ ${#coordinateParts[@]} -eq 4 ]; then
    # <groupId>:<artifactId>:<extension>:<version>
    version=${coordinateParts[3]}
    extension=${coordinateParts[2]}
    artifactPath="${groupId}/${artifactId}/${version}/${artifactId}-${version}.${extension}"
  elif [ ${#coordinateParts[@]} -eq 5 ]; then
    # <groupId>:<artifactId>:<extension>:<classifier>:<version>
    version=${coordinateParts[4]}
    extension=${coordinateParts[2]}
    classifier=${coordinateParts[3]}
    artifactPath="${groupId}/${artifactId}/${version}/${artifactId}-${version}-${classifier}.${extension}"
  fi
  echo $artifactPath
}

function mavenMetadataPath() {
  # Standard format for a Maven coordinate:
  # <groupId>:<artifactId>[:<extension>[:classifier]]:<version>
  # $1 = coordinate
  IFS=':' read -ra coordinateParts <<< "$1"
  groupId=$(echo ${coordinateParts[0]} | sed 's/\./\//g')
  artifactId=${coordinateParts[1]}
  if [ ${#coordinateParts[@]} -eq 3 ]; then
    # <groupId>:<artifactId>:<version>
    version=${coordinateParts[2]}
    metadataPath="${groupId}/${artifactId}/maven-metadata.xml"
  elif [ ${#coordinateParts[@]} -eq 4 ]; then
    # <groupId>:<artifactId>:<extension>:<version>
    version=${coordinateParts[3]}
    extension=${coordinateParts[2]}
    metadataPath="${groupId}/${artifactId}/${version}/maven-metadata.xml"
  elif [ ${#coordinateParts[@]} -eq 5 ]; then
    # <groupId>:<artifactId>:<extension>:<classifier>:<version>
    version=${coordinateParts[4]}
    extension=${coordinateParts[2]}
    classifier=${coordinateParts[3]}
    metadataPath="${groupId}/${artifactId}/${version}/maven-metadata.xml"
  fi
  echo $metadataPath
}

function mavenProjectVersion() {
  ${MAVEN_BIN} -f ${MAVEN_PROJECT_POM} -q \
    -Dexec.executable=echo \
    -Dexec.args='${project.version}' \
    --non-recursive \
    exec:exec
}

function set_output() {
  # $1 = key
  # $2 = value
  echo "::set-output name=${1}::${2}"
}
