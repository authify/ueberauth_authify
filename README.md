# ueberauth_authify

[![CI](https://github.com/authify/ueberauth_authify/actions/workflows/ci.yml/badge.svg)](https://github.com/authify/ueberauth_authify/actions/workflows/ci.yml)
[![Hex Version](https://img.shields.io/hexpm/v/ueberauth_authify.svg)](https://hex.pm/packages/ueberauth_authify)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An [Ueberauth](https://hex.pm/packages/ueberauth) strategy for
[Authify](https://github.com/authify/authify), a self-hosted, multi-tenant
identity provider implementing OpenID Connect on top of OAuth 2.0.

This is the Elixir sibling of the Ruby
[`omniauth-authify`](https://rubygems.org/gems/omniauth-authify) gem and aims
for feature parity with it.

Because Authify is multi-tenant, both the server base URL and the
organization slug are required, and every endpoint (authorize, token,
userinfo and JWKS) is scoped to the organization.

## Installation

Add `ueberauth_authify` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ueberauth_authify, "~> 0.1"}
  ]
end
```

Install the dependency:

```shell
mix deps.get
```

## Setup (Phoenix)

### 1. Configure the strategy

The site and OAuth client credentials go under the
`Ueberauth.Strategy.Authify.OAuth` namespace:

```elixir
# config/config.exs
config :ueberauth, Ueberauth.Strategy.Authify.OAuth,
  site: "https://authify.example.com",
  client_id: "YOUR_CLIENT_ID",
  client_secret: "YOUR_CLIENT_SECRET"

# config/runtime.exs (runtime configuration via environment variables)
config :ueberauth, Ueberauth.Strategy.Authify.OAuth,
  site: {:system, "AUTHIFY_SITE"},
  client_id: {:system, "AUTHIFY_CLIENT_ID"},
  client_secret: {:system, "AUTHIFY_CLIENT_SECRET"}
```

### 2. Register the provider

The organization slug is a strategy option, set alongside any other strategy
options:

```elixir
# config/config.exs
config :ueberauth, Ueberauth,
  providers: [
    authify: {Ueberauth.Strategy.Authify, [organization: "my-org"]}
  ]
```

### 3. Add the routes and plug

Add the request and callback routes to your router:

```elixir
# lib/my_app_web/router.ex
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, {MyAppWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  scope "/auth", MyAppWeb do
    pipe_through [:browser]

    get "/:provider", AuthController, :request
    get "/:provider/callback", AuthController, :callback
  end
end
```

and plug `Ueberauth` into your auth controller:

```elixir
# lib/my_app_web/controllers/auth_controller.ex
defmodule MyAppWeb.AuthController do
  use MyAppWeb, :controller

  plug Ueberauth

  def request(conn, _params) do
    # reached when a request-phase failure is assigned (e.g. missing
    # configuration); normally the strategy redirects before this runs.
    redirect(conn, to: "/login")
  end

  def callback(conn, _params) do
    case Ueberauth.auth(conn) do
      %Ueberauth.Auth{} = auth ->
        # successful login, e.g. store the user in your session
        conn
        |> put_session(:user_id, auth.uid)
        |> redirect(to: "/")

      _failure ->
        conn
        |> put_flash(:error, "Failed to authenticate.")
        |> redirect(to: "/login")
    end
  end
end
```

`Ueberauth.auth/1` returns the auth struct on success; otherwise
`conn.assigns[:ueberauth_failure]` holds an `Ueberauth.Failure` struct
describing the failure (`missing_configuration`, `invalid_credentials`,
`access_denied`, `missing_code`, `csrf_attack`, ...).

## Auth hash example

```elixir
%Ueberauth.Auth{
  provider: :authify,
  uid: "424242",
  info: %Ueberauth.Auth.Info{
    name: "Jane User",
    first_name: "Jane",
    last_name: "User",
    nickname: "jane@example.com",
    email: "jane@example.com",
    image: "https://authify.example.com/avatar.png",
    location: "America/Chicago",
    phone: "+15551234567",
    urls: %{website: "https://example.com/jane"}
  },
  credentials: %Ueberauth.Auth.Credentials{
    token: "test-access-token",
    refresh_token: "test-refresh-token",
    token_type: "Bearer",
    expires: true,
    expires_at: 1_788_322_042,
    scopes: ["openid", "profile", "email"],
    other: %{"id_token" => "eyJ..."}
  },
  extra: %Ueberauth.Auth.Extra{
    raw_info: %{
      user: %{ "iss" => "...", "sub" => "424242", ... },
      id_info: %{ "iss" => "...", "sub" => "424242", ... },
      token: %OAuth2.AccessToken{}
    }
  }
}
```

`info` is built from the (signature-verified) ID token claims, mapping
standard OpenID Connect claims: `name`, `given_name` (first name),
`family_name` (last name), `preferred_username` (nickname), `email`,
`picture` (image), `zoneinfo` (location), `phone_number` (phone) and
`website` (urls). `extra.raw_info.id_info` holds the full verified claim set
and `extra.raw_info.token` the complete `%OAuth2.AccessToken{}`.

## Strategy options

| Option             | Default                    | Description                                                             |
| ------------------ | -------------------------- | ----------------------------------------------------------------------- |
| `:organization`    | (required)                 | The Authify organization slug                                          |
| `:default_scope`   | `"openid profile email"`   | Scopes requested from Authify (`"openid"` is required for an ID token)  |
| `:uid_field`       | `:sub`                     | The ID token claim used as the uid                                      |
| `:verify_id_token` | `true`                     | Verify the ID token signature and claims (recommended)                 |
| `:leeway`          | `60`                       | Seconds of slack for time-based ID token claim checks                  |
| `:pkce`            | `true`                     | Use PKCE (S256) for the authorization code exchange                     |

```elixir
config :ueberauth, Ueberauth,
  providers: [
    authify: {Ueberauth.Strategy.Authify,
              [organization: "my-org", default_scope: "openid profile email"]}
  ]
```

## OIDC verification

On every login the strategy:

- sends a per-login `nonce` with the authorization request and validates it
  against the ID token's `nonce` claim
- uses PKCE (S256) for the authorization code exchange
- verifies the RS256 ID token signature against the organization's JWKS
  endpoint (`/{organization}/.well-known/jwks`), refetching the key set when
  the token's `kid` is missing (rotated signing keys)
- validates the `iss`, `sub`, `aud`, `exp`, `iat` and `nonce` claims (and
  `auth_time` when the login requested `max_age`), with the configured
  leeway

The request phase also forwards an optional `prompt` request parameter
(Authify honors `prompt=consent`) and an optional `max_age` parameter, e.g.
`/auth/authify?prompt=consent&max_age=300`.

## HTTP clients

The strategy uses [`oauth2`](https://hex.pm/packages/oauth2) for the OAuth
token exchange (which uses Tesla under the hood) and
[`req`](https://hex.pm/packages/req) for its own HTTP calls (JWKS). If you
want the OAuth calls to avoid the default `httpc` adapter, point oauth2 at
Finch (already in the dependency tree via `req`):

```elixir
# config/config.exs
config :oauth2, :adapter, {Tesla.Adapter.Finch, name: MyApp.Finch}

# lib/my_app/application.ex
children = [
  {Finch, name: MyApp.Finch},
  ...
]
```

## Development

```shell
mix deps.get
mix test
mix precommit  # compile (warnings as errors), format check, tests, credo --strict
```

The project pins its toolchain with asdf (see `.tool-versions`):
Elixir 1.20.4 / Erlang 29.0.5.

## License

MIT. See [LICENSE](LICENSE).