#!/bin/bash

echo "TODO: this is very very temporal!! Until go-webauthn/webauthn pkg change"
exit 0

set -e

acator_key=$(findy-agent-cli new-key)
findy-agent-cli authn register \
  -u test \
  --url http://localhost:8088 \
  --origin http://localhost:3000 \
  --key $acator_key
findy-agent-cli authn login \
  -u test \
  --url http://localhost:8088 \
  --origin http://localhost:3000 \
  --key $acator_key
