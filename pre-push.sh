#!/bin/sh

# You have to run a command to make git automatically run this;
# see README.md

git diff --quiet
RESULT=$?
if [ "$RESULT" -eq 1 ]; then
    echo "You have untracked changes; please commit them and try again"
    exit 1
fi

echo "Running linter..."
docker-compose run --rm app yarn run lint:fix || exit 1

git diff --quiet
RESULT=$?
if [ "$RESULT" -eq 1 ]; then
    echo "The linter has been appeased; please amend your commit and try again"
    exit 1
fi
