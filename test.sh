#!/bin/bash

yarn install
yarn run lint:check
yarn run coverage:run
yarn run coverage:check
