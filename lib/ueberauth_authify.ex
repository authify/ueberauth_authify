defmodule UeberauthAuthify do
  @moduledoc """
  An Ueberauth strategy for [Authify](https://github.com/authify/authify), a
  self-hosted, multi-tenant identity provider implementing OpenID Connect on
  top of OAuth 2.0.

  This is the Elixir sibling of the Ruby `omniauth-authify` gem and aims for
  feature parity with it.

  Because Authify is multi-tenant, both the server base URL and the
  organization slug are required. The `:site` (and OAuth client credentials)
  come from your application configuration:

      config :ueberauth, Ueberauth.Strategy.Authify.OAuth,
        site: "https://authify.example.com",
        client_id: "YOUR_CLIENT_ID",
        client_secret: "YOUR_CLIENT_SECRET"

  Values also support the `{:system, "ENV_VAR"}` tuple form:

      config :ueberauth, Ueberauth.Strategy.Authify.OAuth,
        site: {:system, "AUTHIFY_SITE"},
        client_id: {:system, "AUTHIFY_CLIENT_ID"},
        client_secret: {:system, "AUTHIFY_CLIENT_SECRET"}

  The organization is configured per provider, alongside any strategy
  options:

      config :ueberauth, Ueberauth,
        providers: [
          authify: {Ueberauth.Strategy.Authify, [organization: "my-org"]}
        ]

  See `Ueberauth.Strategy.Authify` for the full list of supported options and
  the flow description.
  """
end
