# Contributing to ueberauth_authify

Thanks for your interest in contributing!

## Getting started

1. Fork the repository and clone your fork.
2. Ensure the pinned toolchain is active (`asdf install` picks up
   `.tool-versions`: Elixir 1.20.4 / Erlang 29.0.5).
3. Install dependencies and verify the suite is green:

   ```shell
   mix deps.get
   mix precommit
   ```

## Making changes

- Match the existing code style; `mix format` handles formatting.
- `mix precommit` must pass before any commit: it compiles with
  `--warnings-as-errors`, checks formatting, runs the tests and
  `mix credo --strict`.
- Add or update tests for any behavior change. The suite uses
  `Plug.Test` with a `SpecRouter` and `Bypass` to stub the Authify
  token/JWKS/userinfo endpoints — see `test/test_helper.exs` and
  `test/support/authify_test_support.exs`.
- This strategy aims for feature parity with the Ruby
  [`omniauth-authify`](https://github.com/authify/omniauth-authify) gem; if
  you are changing OAuth/OIDC flow behavior, check the Ruby gem first and
  mirror it.

## Security

The PKCE (S256) flow, the per-login nonce and RS256 ID token verification
are core security features. Changes to them must be covered by tests, and
the client secret or PKCE verifier must never leave the token exchange.

Report security vulnerabilities privately to the maintainer rather than
opening a public issue.

## Pull requests

1. Create a feature branch.
2. Make your change, with tests.
3. Run `mix precommit` and make sure it passes.
4. Open a pull request describing what changed and why.

## Releasing

Releases are tagged pushes; CI publishes to hex.pm via trusted publishing.
The maintainer bumps the version in `mix.exs` and `CHANGELOG.md`, then tags
`vX.Y.Z`.