# findy-agent-auth

[![test](https://github.com/findy-network/findy-agent-auth/actions/workflows/test.yml/badge.svg?branch=dev)](https://github.com/findy-network/findy-agent-auth/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/findy-network/findy-agent-auth/branch/dev/graph/badge.svg?token=KY0702XNS6)](https://codecov.io/gh/findy-network/findy-agent-auth)
![last-commit](https://img.shields.io/github/last-commit/findy-network/findy-agent-auth)

> Findy Agency is an open-source project for a decentralized identity agency.
> OP Lab developed it from 2019 to 2024. The project is no longer maintained,
> but the work will continue with new goals and a new mission.
> Follow [the blog](https://findy-network.github.io/blog/) for updates.

Authentication services for Findy agency.

## Getting Started

Findy Agency is a collection of services ([Core](https://github.com/findy-network/findy-agent),
[this service](https://github.com/findy-network/findy-agent-auth),
[Findy Vault](https://github.com/findy-network/findy-agent-vault) and
[Web Wallet](https://github.com/findy-network/findy-wallet-pwa)) that provide
full SSI agency along with a web wallet for individuals.
To start experimenting with Findy Agency we recommend you to start with
[the documentation](https://findy-network.github.io/) and
[set up the agency to your localhost environment](https://github.com/findy-network/findy-wallet-pwa/tree/dev/tools/env#agency-setup-for-local-development).

- [Documentation](https://findy-network.github.io/)
- [Instructions for starting agency in Docker containers](https://github.com/findy-network/findy-wallet-pwa/tree/dev/tools/env#agency-setup-for-local-development)

## Server

This project provides FIDO2/WebAuthn authentication service for findy agency clients. The service implements the WebAuthn protocol providing means to securely

- initiate user registration,
- finish user registration,
- initiate authentication and
- finish authentication.

The authentication service can be utilized for example by any web app running in [a compatible browser](https://caniuse.com/?search=webauthn).

During a successful registration the user is onboarded to [findy core agency](https://github.com/findy-network/findy-agent) and an Aries compatible cloud agent is allocated for the user. After registration, user can generate a token for findy agency with this authentication service. This token is required by [agency API](https://github.com/findy-network/findy-agent-api).

### Usage

```sh
$ go run . \
    --port 8088 \                       # port for this service
    --origin http://localhost:3000 \    # origin for browser requests
    --cors=true \                       # use CORS headers
    --agency localhost \                # core agency GRPC server address
    --gport 50051 \                     # core agency GRPC server port
    --cert-path /path/to/agency/cert \  # path to agency GRPC cert
    --jwt-secret agency-jwt-secret \    # agency JWT secret
    --admin agency-admin-id             # agency admin ID
```

## Client

This project provides also library for authenticating headless clients. Headless authenticator is needed when implementing (organisational) services needing cloud agents. Check [agency CLI](https://github.com/findy-network/findy-agent-cli) for reference implementation.
