# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## Project

`ueberauth_authify` is an Ueberauth strategy for
[Authify](https://github.com/authify/authify), a self-hosted, multi-tenant
OIDC identity provider. It is the Elixir sibling of the Ruby
[`omniauth-authify`](https://github.com/authify/omniauth-authify) gem; that
gem is the behavioral spec, and feature parity with it is the goal.

## Toolchain

- Elixir 1.20.4 / Erlang 29.0.5, pinned via asdf (`.tool-versions`).
- The library supports `elixir: "~> 1.14"` (ueberauth's own floor) even
  though we develop on 1.20.

## Commands

- `mix precommit` — the gate: compile with `--warnings-as-errors`, unlock
  unused deps, check formatting, run tests, `credo --strict`. Run this
  before considering any change done; CI runs the same checks.
- `mix test` — ExUnit suite. Tests drive a `Plug.Router` SpecRouter
  (see `test/test_helper.exs`) with `Plug.Test` and stub the Authify
  token/JWKS/userinfo endpoints with Bypass.
- `mix credo --strict` — style/lint (configuration in `.credo.exs`).
- `mix format` — formatting.

## Conventions

- HTTP: use `Req` for HTTP calls made by this library (never httpoison,
  tesla or httpc). `oauth2` (a fixed dependency) uses Tesla internally for
  the token exchange; we document pointing its adapter at Finch in the
  README rather than adding another HTTP client.
- Zero-warning, formatted, credo-clean code; `mix precommit` must pass.
- No Ecto, no database — CI needs no services.
- Error tuples (`{:error, reason}`) over raising in library code paths;
  the strategy converts failures into ueberauth failure errors.
- The strategy requires the session (`Plug.Session`) to carry the nonce
  and PKCE verifier between the request and callback phases; Phoenix apps
  provide this by default.

## Security-sensitive behavior (be careful changing)

- PKCE S256 and the per-login nonce are core security features; mirror the
  Ruby gem's behavior when touching the callback flow.
- ID token verification: RS256 only, kid-based key selection with a JWKS
  refetch on kid-miss, leeway on time-based claims.
- Never send the client secret or code verifier anywhere except the token
  endpoint.

## Known dependency advisory (accepted)

`mix hex.audit` reports advisories for `cowlib 2.19.0` (EEF-CVE-2026-43966,
EEF-CVE-2026-43969, EEF-CVE-2026-43971). As of 2026-09-01 there is no
patched cowlib release — 2.19.0 *is* the latest. cowlib is only a
test-scoped transitive dependency (`bypass` → `plug_cowboy`) and is never
shipped to consumers of the hex package. Accepted; re-evaluate when a
patched cowlib is published.

## Testing notes

- Tests that mutate `Application` environment are `async: false`.
- `Ueberauth.Strategy.Authify.JWKSCache.clear/0` is available to reset the
  JWKS cache between tests.
- Upstream Authify API quirks are cataloged in the owner's
  `AUTHIFY_API_NOTES.md`; append new findings there rather than opening
  issues directly.

## Publishing

Releases are tagged pushes; CI publishes to hex.pm on `v*` tag push using the
`HEX_API_KEY` repository secret (a hex.pm key with API write permission — hex.pm
has no trusted-publishing/OIDC support like rubygems.org, so a key is required).
`mix hex.publish --yes` runs in the release workflow.