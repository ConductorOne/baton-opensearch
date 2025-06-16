![Baton Logo](./baton-logo.png)

# `baton-opensearch` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-opensearch.svg)](https://pkg.go.dev/github.com/conductorone/baton-opensearch) ![main ci](https://github.com/conductorone/baton-opensearch/actions/workflows/main.yaml/badge.svg)

`baton-opensearch` is a connector for built using the [Baton SDK](https://github.com/conductorone/baton-sdk).

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

# Prerequisites
No prerequisites were specified for `baton-opensearch`

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-opensearch
baton-opensearch
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_DOMAIN_URL=domain_url -e BATON_API_KEY=apiKey -e BATON_USERNAME=username ghcr.io/conductorone/baton-opensearch:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-opensearch/cmd/baton-opensearch@main

baton-opensearch

baton resources
```

# Data Model

`baton-opensearch` will pull down information about the following resources:
- Users

`baton-opensearch` does not specify supporting account provisioning or entitlement provisioning.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually
building spreadsheets. We welcome contributions, and ideas, no matter how
small&mdash;our goal is to make identity and permissions sprawl less painful for
everyone. If you have questions, problems, or ideas: Please open a GitHub Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-opensearch` Command Line Usage

```
baton-opensearch

Usage:
  baton-opensearch [flags]
  baton-opensearch [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --client-id string             The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string         The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
  -f, --file string                  The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                         help for baton-opensearch
      --log-format string            The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string             The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning                 If this connector supports provisioning, this must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --ticketing                    This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                      version for baton-opensearch

Use "baton-opensearch [command] --help" for more information about a command.
```
