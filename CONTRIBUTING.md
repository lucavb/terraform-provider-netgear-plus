# Contributing

Thanks for contributing to `terraform-provider-netgear-plus`.

## Development Setup

This project is a Go-based Terraform provider.

```sh
go test ./...
go build ./...
```

For manual device testing, keep local switch configs, secrets, and CLI override files out of commits.

## Pull Requests

- Keep changes focused and include tests when practical.
- Update docs when behavior or workflows change.
- Prefer a clean history so release notes stay readable.

## Releases

Releases are created from version tags on `main` by GitHub Actions and GoReleaser.
