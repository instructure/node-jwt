#!/bin/sh

# You have to run a command to make git automatically run this;
# see README.md

git diff --quiet
RESULT=$?
if [ "$RESULT" -ne 0 ]; then
    echo "You have untracked changes; please commit them and try again"
    exit 1
fi

echo "Running linter..."
docker-compose run --rm app yarn run lint:fix
RESULT=$?
if [ "$RESULT" -ne 0 ]; then
    echo "The linter is angry; you'll need to manually fix some things before trying again"
    exit 1
fi

git diff --quiet
RESULT=$?
if [ "$RESULT" -ne 0 ]; then
    echo "The linter has been appeased; please amend your commit and try again; i.e.:"
    echo "\tgit add -A && git commit --amend --no-edit"
    exit 1
fi
