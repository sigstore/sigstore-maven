#!/usr/bin/env bash

# Originally taken from https://gist.github.com/romainbsl/4ab6d8c1e92d3f916eaacf77eb27e361, thanks to Romain Boisselle (@romainbsl)

if [ -f ${HOME}/.ossrh/credentials ]; then
  echo "Reading OSSRH credentials ..."
  source ${HOME}/.ossrh/credentials
fi

# ----------------------------------------------------------------------------------------------------------------------
# The findStagingRepository call returns a JSON structure that looks like the following:
#
# {
#   "data": [
#     {
#       "profileId": "3aad67c5334a6",
#       "profileName": "ca.vanzyl",
#       "profileType": "repository",
#       "repositoryId": "cavanzyl-1184",
#       "type": "open",
#       "policy": "release",
#       "userId": "jwanzyl",
#       "userAgent": "Apache-Maven/3.6.3 (Java 11.0.12; Mac OS X 11.2)",
#       "ipAddress": "136.144.17.59",
#       "repositoryURI": "https://oss.sonatype.org/content/repositories/cavanzyl-1184",
#       "created": "2022-03-22T00:26:48.586Z",
#       "createdDate": "Tue Mar 22 00:26:48 UTC 2022",
#       "createdTimestamp": 1647908808586,
#       "updated": "2022-03-22T00:26:52.233Z",
#       "updatedDate": "Tue Mar 22 00:26:52 UTC 2022",
#       "updatedTimestamp": 1647908812233,
#       "description": "Implicitly created (auto staging).",
#       "provider": "maven2",
#       "releaseRepositoryId": "releases",
#       "releaseRepositoryName": "Releases",
#       "notifications": 0,
#       "transitioning": false
#     }
#   ]
# }
#
# So just assuming there is only one staging repository and returning the repositoryId is simplistic, and we should
# see if the API allows limiting the results returned, or use a jq query that returns the information about a 
# specific staging repository.
#
# ----------------------------------------------------------------------------------------------------------------------

findStagingRepositoryId() {
  curl -s --request GET -u "$username:$password" https://oss.sonatype.org/service/local/staging/profile_repositories \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' | jq -r '.data[0].repositoryId'
}

closeRepository() {
  stagingRepositoryId=${1}
  echo "Closing staging repository ${stagingRepositoryId} ..."
  closingRepository=$(
    curl -s --request POST -u "$username:$password" \
      --url https://oss.sonatype.org/service/local/staging/bulk/close \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/json' \
      --data '{ "data" : {"stagedRepositoryIds":["'"${stagingRepositoryId}"'"], "description":"Close '"${stagingRepositoryId}"'." } }'
  )

  if [ ! -z "$closingRepository" ]; then
      echo "Error while closing repository ${stagingRepositoryId} : $closingRepository."
      exit 1
  fi
}

waitForRulesProcessiongToComplete() {
  echo "Waiting for rules to finish processing on staging repository ${stagingRepositoryId} ..."
  stagingRepositoryId=${1}
  start=$(date +%s)
  while true ; do
    # force timeout after 15 minutes
    now=$(date +%s)
    if [ $(( (now - start) / 60 )) -gt 15 ]; then
        echo "Closing process is to long, stopping the job (waiting for closing repository)."
        exit 1
    fi

    rules=$(curl -s --request GET -u "$username:$password" \
          --url https://oss.sonatype.org/service/local/staging/repository/"${stagingRepositoryId}"/activity \
          --header 'Accept: application/json' \
          --header 'Content-Type: application/json')

    closingRules=$(echo "$rules" | jq '.[] | select(.name=="close")')
    if [ -z "$closingRules" ] ; then
      continue
    fi

    rulesPassed=$(echo "$closingRules" | jq '.events | any(.name=="rulesPassed")')
    rulesFailed=$(echo "$closingRules" | jq '.events | any(.name=="rulesFailed")')

    if [ "$rulesFailed" = "true" ]; then
      echo "Staged repository [${stagingRepositoryId}] could not be closed."
      exit 1
    fi

    if [ "$rulesPassed" = "true" ]; then
        break
    else
        sleep 5
    fi
  done
}

waitForTransitionToComplete() {
  echo "Waiting for transition to complete on staging repository ${stagingRepositoryId} ..."
  stagingRepositoryId=${1}
  start=$(date +%s)
  while true ; do
    # force timeout after 5 minutes
    now=$(date +%s)
    if [ $(( (now - start) / 60 )) -gt 5 ]; then
        echo "Closing process is to long, stopping the job (waiting for transitioning state)."
        exit 1
    fi

    repository=$(curl -s --request GET -u "$username:$password" \
      --url https://oss.sonatype.org/service/local/staging/repository/"${stagingRepositoryId}" \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/json')

    type=$(echo "$repository" | jq -r '.type' )
    transitioning=$(echo "$repository" | jq -r '.transitioning' )
    if [ "$type" = "closed" ] && [ "$transitioning" = "false" ]; then
        break
    else
        sleep 1
    fi
  done
}

releaseRepository() {
  echo "Releasing staging repository ${stagingRepositoryId} ..."
  stagingRepositoryId=${1}
  release=$(curl -s --request POST -u "$username:$password" \
    --url https://oss.sonatype.org/service/local/staging/bulk/promote \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{ "data" : {"stagedRepositoryIds":["'"${stagingRepositoryId}"'"], "autoDropAfterRelease" : true, "description":"Release '"${stagingRepositoryId}"'." } }')

  if [ ! -z "$release" ]; then
      echo "Error while releasing ${stagingRepositoryId} : $release."
      exit 1
  fi
}

stagingRepositoryId=$(findStagingRepositoryId)
if [ ! -z ${stagingRepositoryId} ]; then
  echo "No staging repository found. Nothing to do. Bye bye!"
  exit
fi
echo "Found staging repository ${stagingRepositoryId}: attempting to close and release ..."
closeRepository ${stagingRepositoryId}
waitForRulesProcessiongToComplete ${stagingRepositoryId}
waitForTransitionToComplete ${stagingRepositoryId}
releaseRepository ${stagingRepositoryId}