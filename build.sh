#!/bin/bash

function cleanup() {
  exit_code=$?

  echo ": Cleaning up"
  docker-compose down

  exit $exit_code
}
trap cleanup INT TERM EXIT

set -e

docker-compose build
docker-compose run app ./test.sh
