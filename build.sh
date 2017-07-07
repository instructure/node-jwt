#!/bin/bash

function cleanup() {
  exit_code=$?

  echo ": Cleaning up"
  docker-compose stop
  docker-compose rm -f

  exit $exit_code
}
trap cleanup INT TERM EXIT

set -e

echo ": Build and start containers..."
export COMPOSE_FILE=docker-compose.test.yml
docker-compose build
docker-compose up -d

# docker-compose on mac doesn't flush stdout and stderr properly without a tty,
# so give it one if we're running under one ourselves
if [ -t 1 ]; then
  exec_command="docker-compose exec"
else
  exec_command="docker-compose exec -T"
fi

echo ": Run linters and tests..."
$exec_command app yarn run lint:check
$exec_command app yarn run coverage:run
$exec_command app yarn run coverage:check

echo ": Publish code coverage..."
# copy coverage data out of dockerland so jenkins can see it
docker cp $(docker-compose ps -q app):/usr/src/app/coverage/lcov-report/. coverage

echo ": Build successful!"
