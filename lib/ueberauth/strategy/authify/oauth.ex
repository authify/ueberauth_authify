defmodule Ueberauth.Strategy.Authify.OAuth do
  @moduledoc """
  An OAuth2 client for Authify, scoped to an organization.

  All configuration is read from the application environment:

      config :ueberauth, Ueberauth.Strategy.Authify.OAuth,
        site: "https://authify.example.com",
        client_id: "YOUR_CLIENT_ID",
        client_secret: "YOUR_CLIENT_SECRET"

  Each value also accepts the `{:system, "ENV_VAR"}` tuple form so credentials
  can be provided at runtime.

  The organization slug itself is a strategy option (`organization`), and is
  passed into this module by `Ueberauth.Strategy.Authify`. Every endpoint is
  scoped to the organization:

      https://authify.example.com/my-org/oauth/authorize
      https://authify.example.com/my-org/oauth/token
      https://authify.example.com/my-org/oauth/userinfo
      https://authify.example.com/my-org/.well-known/jwks

  """

  use OAuth2.Strategy

  alias OAuth2.Client

  @userinfo_path "/oauth/userinfo"

  @client_option_keys [:redirect_uri, :headers, :params, :request_opts, :token]

  @doc """
  Resolves the OAuth configuration for `otp_app` (defaults to `:ueberauth`),
  expanding `{:system, "VAR"}` tuples.
  """
  @spec config(atom | nil) :: keyword()
  def config(otp_app \\ nil) do
    app = otp_app || :ueberauth
    env = Application.get_env(app, __MODULE__)

    unless env do
      raise "Expected to find settings under `config #{inspect(app)}, #{inspect(__MODULE__)}`, got nil. " <>
              "Check your config file."
    end

    [
      site: config_value(env[:site]),
      client_id: config_value(env[:client_id]),
      client_secret: config_value(env[:client_secret])
    ]
  end

  @doc """
  The configured Authify server base URL (without an organization slug).
  """
  @spec site(atom | nil) :: binary | nil
  def site(otp_app \\ nil), do: config(otp_app)[:site]

  @doc """
  The configured OAuth client ID.
  """
  @spec client_id(atom | nil) :: binary | nil
  def client_id(otp_app \\ nil), do: config(otp_app)[:client_id]

  @doc """
  The organization-scoped base URL (`site` + `organization`), with any
  trailing slashes on the site normalized away.
  """
  @spec base_url(atom | nil, binary) :: binary
  def base_url(otp_app \\ nil, organization) do
    site = site(otp_app)

    cond do
      blank?(site) ->
        raise ArgumentError, "Authify strategy requires the :site option to be configured"

      blank?(organization) ->
        raise ArgumentError, "Authify strategy requires the :organization option"

      true ->
        String.trim_trailing(String.trim(site), "/") <> "/" <> String.trim(organization)
    end
  end

  @doc """
  Builds the organization-scoped `%OAuth2.Client{}`.

  Options:

    * `:organization` - the Authify organization slug (required)
    * `:otp_app` - read config from this app instead of `:ueberauth`
    * `:token` - an existing `%OAuth2.AccessToken{}` for authenticated requests
  """
  @spec client(keyword()) :: Client.t()
  def client(opts \\ []) do
    otp_app = Keyword.get(opts, :otp_app)
    organization = Keyword.get(opts, :organization)
    base = base_url(otp_app, organization)

    [
      strategy: __MODULE__,
      site: base,
      authorize_url: base <> "/oauth/authorize",
      token_url: base <> "/oauth/token",
      client_id: config(otp_app)[:client_id],
      client_secret: config(otp_app)[:client_secret],
      serializers: %{"application/json" => Ueberauth.json_library(otp_app)}
    ]
    |> Keyword.merge(Keyword.take(opts, @client_option_keys))
    |> Client.new()
  end

  @doc """
  Builds the authorize URL for the request phase of Ueberauth. No need to call
  this usually.
  """
  @spec authorize_url!(keyword(), keyword()) :: binary
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client()
    |> Client.authorize_url!(params)
  end

  @doc """
  Exchanges an authorization code (and PKCE verifier, when present) for an
  access token.
  """
  @spec get_token(keyword(), keyword()) ::
          {:ok, Client.t()} | {:error, OAuth2.Response.t()} | {:error, OAuth2.Error.t()}
  def get_token(params \\ [], opts \\ []) do
    opts
    |> client()
    |> Client.get_token(params)
  end

  @doc """
  Fetches the OIDC userinfo claims for `token` from the organization's
  userinfo endpoint.
  """
  @spec get_userinfo(OAuth2.AccessToken.t(), keyword()) ::
          {:ok, OAuth2.Response.t()} | {:error, OAuth2.Response.t()} | {:error, OAuth2.Error.t()}
  def get_userinfo(token, opts \\ []) do
    opts
    |> Keyword.put(:token, token)
    |> client()
    |> Client.get(@userinfo_path, [{"accept", "application/json"}])
  end

  @doc false
  @impl OAuth2.Strategy
  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  @doc false
  @impl OAuth2.Strategy
  def get_token(client, params, headers) do
    client
    |> put_header("accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end

  defp config_value({:system, var}), do: System.get_env(var)
  defp config_value(value), do: value

  defp blank?(value), do: value in [nil, ""]
end
