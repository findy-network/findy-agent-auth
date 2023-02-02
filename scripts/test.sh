#!/bin/bash

set -e

acator_key=$(findy-agent-cli new-key)
findy-agent-cli authn register \
  -u test \
  --url http://localhost:8088 \
  --origin http://localhost:3000 \
  --key $acator_key
findy-agent-cli authn login \
  -u test \
  --url http://localhost:8080 \
  --origin http://localhost:3000 \
  --key $acator_key
