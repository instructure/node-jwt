#!/bin/bash

function cleanup() {
  exit_code=$?

  echo ": Cleaning up"
  docker-compose down

  exit $exit_code
}
trap cleanup INT TERM EXIT

set -e

echo ": Build and start containers..."
export COMPOSE_FILE=docker-compose.test.yml
docker-compose build

# docker-compose on mac doesn't flush stdout and stderr properly without a tty,
# so give it one if we're running under one ourselves
if [ -t 1 ]; then
  DOCKER_COMPOSE_RUN="docker-compose run "
  DOCKER_EXEC="docker exec -t" # allocate tty
else
  DOCKER_COMPOSE_RUN="docker-compose run -T" # disable tty allocation
  DOCKER_EXEC="docker exec"
fi

echo ": Run linters and tests..."
$DOCKER_COMPOSE_RUN -d --name work_container app tail -f /dev/null # don't do anything, but don't exit either
$DOCKER_EXEC work_container yarn run lint:check
$DOCKER_EXEC work_container yarn run coverage:run
$DOCKER_EXEC work_container yarn run coverage:check

echo ": Publish code coverage..."
# copy coverage data out of dockerland so jenkins can see it
docker cp $(docker-compose ps -q app):/usr/src/app/coverage/lcov-report/. coverage

echo ": Build successful!"
