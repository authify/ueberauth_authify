# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-26

### Security

- Add a runtime floor on `mint` (`>= 1.10.2`) so consumers cannot resolve a
  vulnerable `mint`. `mint` reaches consumers transitively
  (`req` → `finch` → `mint`), and the published package ships no
  `mix.lock`, so the library has to carry the constraint itself. The floor
  clears all six open `mint` advisories — EEF-CVE-2026-82729,
  EEF-CVE-2026-82672, EEF-CVE-2026-91043 (HIGH), EEF-CVE-2026-92103,
  EEF-CVE-2026-94194 and EEF-CVE-2026-82728 (HIGH) — and keeps consumers off
  the affected 1.9.3, 1.10.0 and 1.10.1
- Bump `jose` to 1.11.13 in the lock, clearing the eight open `jose`
  advisories EEF-CVE-2026-65625 through EEF-CVE-2026-65632, including the
  HIGH EEF-CVE-2026-65629

### Changed

- Bump `plug_crypto` to 2.2.1 in the lock (EEF-CVE-2026-105963)
- Bump `cowlib` to 2.21.0 in the lock, clearing EEF-CVE-2026-43971 and
  EEF-CVE-2026-43969
- Bump `mint` to 1.11.0 and `hpax` to 1.1.0 in the lock

### Documentation

- Refresh the accepted-advisory note in `AGENTS.md`: `cowlib` 2.21.0 is now
  locked and clears EEF-CVE-2026-43971 and EEF-CVE-2026-43969; only
  EEF-CVE-2026-43966 remains accepted, as no patched release exists

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

[Unreleased]: https://github.com/authify/ueberauth_authify/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/authify/ueberauth_authify/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/authify/ueberauth_authify/releases/tag/v0.1.0