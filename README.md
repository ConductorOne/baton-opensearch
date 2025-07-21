![Baton Logo](./baton-logo.png)

# `baton-opensearch` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-opensearch.svg)](https://pkg.go.dev/github.com/conductorone/baton-opensearch) ![main ci](https://github.com/conductorone/baton-opensearch/actions/workflows/main.yaml/badge.svg)

`baton-opensearch` is a connector for OpenSearch built using the [Baton SDK](https://github.com/conductorone/baton-sdk). This connector syncs OpenSearch security roles and their assignments to users and groups.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Prerequisites

### Required OpenSearch Permissions

The connector requires an OpenSearch user with access to the OpenSearch Security plugin APIs.

### OpenSearch Security Plugin

The connector requires the OpenSearch Security plugin to be enabled and properly configured. The security plugin provides the authentication and authorization APIs that the connector uses.

# Getting Started

## brew

```bash
brew install conductorone/baton/baton conductorone/baton/baton-opensearch

BATON_OPENSEARCH_ADDRESS="https://opensearch.example.com" \
BATON_OPENSEARCH_USERNAME="admin" \
BATON_OPENSEARCH_PASSWORD="example" \
baton-opensearch

baton resources
```

## docker

```bash
docker run --rm \
  -v $(pwd):/out \
  -e BATON_OPENSEARCH_ADDRESS="https://opensearch.example.com" \
  -e BATON_OPENSEARCH_USERNAME="admin" \
  -e BATON_OPENSEARCH_PASSWORD="example" \
  ghcr.io/conductorone/baton-opensearch:latest \
  -f "/out/sync.c1z"

docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```bash
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-opensearch/cmd/baton-opensearch@main
BATON_OPENSEARCH_ADDRESS="https://opensearch.example.com" BATON_OPENSEARCH_USERNAME="admin" BATON_OPENSEARCH_PASSWORD="example"

baton-opensearch

baton resources
```

# Data Model

The connector syncs the following resources:

### Roles
- **Resource Type**: `role`
- **Description**: OpenSearch security roles with permissions

### Users (External)
- **Resource Type**: `user` (external)
- **Description**: Users assigned to roles
- **Note**: Users are treated as external resources since they may be managed by external identity providers

### Groups (External)
- **Resource Type**: `group` (external)
- **Description**: Groups assigned to roles
- **Note**: Groups are treated as external resources and may represent backend roles or external group mappings

## Configuration

### TLS Configuration

The connector supports flexible TLS configuration:

- **System Certificates**: Uses system certificate pool by default
- **Custom CA Certificate**: Provide via `ca-cert-path` (file path) or `ca-cert` (direct value)
- **Insecure Mode**: Set `insecure-skip-verify` to `true` for development/testing
- **Mutually Exclusive**: Only one of `ca-cert-path` or `ca-cert` can be set

### Basic Configuration Examples
```yaml
address: "https://opensearch.example.com"
username: "admin"
password: "example"
```

### With Custom CA Certificate
```yaml
address: "https://opensearch.example.com"
username: "admin"
password: "example"
ca-cert-path: "/path/to/ca-certificate.pem"
```

### With Insecure TLS (Development)
```yaml
address: "https://opensearch.example.com"
username: "admin"
password: "example"
insecure-skip-verify: true
```

### With Custom User Matching
```yaml
address: "https://opensearch.example.com"
username: "admin"
password: "example"
user-match-key: "username"
```

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
      --address string               required: The OpenSearch server address ($BATON_OPENSEARCH_ADDRESS)
      --username string              required: OpenSearch username with security API access ($BATON_OPENSEARCH_USERNAME)
      --password string              required: OpenSearch password ($BATON_OPENSEARCH_PASSWORD)
      --user-match-key string        Field name for matching users (`email`, `name`, `id`) ($BATON_OPENSEARCH_USER_MATCH_KEY) (default "email")
      --insecure-skip-verify bool    Skip TLS certification validation ($BATON_OPENSEARCH_INSECURE_SKIP_VERIFY) (default `false`)
      --ca-cert-path string          Path to PEM-encoded certificate file ($BATON_OPENSEARCH_CA_CERT_PATH)
      --ca-cert string               PEM-encoded certificate (base64 encoded for env vars) ($BATON_OPENSEARCH_CA_CERT)
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
