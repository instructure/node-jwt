#!/bin/bash

set -e

echo ": Run linters and tests..."
yarn run lint:check
yarn run coverage:run
yarn run coverage:check

echo ": Publish code coverage..."
mv coverage/lcov-report/* coverage

echo ": Build successful!"
