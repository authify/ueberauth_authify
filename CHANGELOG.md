# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-01

### Added

- Initial Ueberauth strategy for Authify, a self-hosted, multi-tenant OIDC
  identity provider, with feature parity to the Ruby `omniauth-authify` gem:
  - Organization-scoped configuration (strategy option `organization` plus
    OAuth config `site`/`client_id`/`client_secret`, with `{:system, "VAR"}`
    tuple support)
  - PKCE (S256) for the authorization code exchange, enabled by default
  - Per-login nonce bound to the ID token's `nonce` claim
  - RS256 ID token verification against the organization's JWKS endpoint,
    with a key-set refetch when the token's `kid` is missing (rotated keys)
  - ID token claim validation: `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`
    and `auth_time` (when `max_age` was requested), with configurable leeway
  - Auth hash built from the verified ID token claims, with a userinfo
    fallback when ID token verification is disabled
  - Forwarding of `prompt` and `max_age` request parameters

[Unreleased]: https://github.com/authify/ueberauth_authify/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/authify/ueberauth_authify/releases/tag/v0.1.0