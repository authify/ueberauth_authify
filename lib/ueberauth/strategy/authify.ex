defmodule Ueberauth.Strategy.Authify do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with
  [Authify](https://github.com/authify/authify), a self-hosted, multi-tenant
  identity provider implementing OpenID Connect on top of OAuth 2.0.

  Since Authify is multi-tenant, both the server base URL and the organization
  slug are required; all endpoints (authorize, token, userinfo and JWKS) are
  scoped to the organization. Configure the site and OAuth credentials under
  the `Ueberauth.Strategy.Authify.OAuth` namespace:

      config :ueberauth, Ueberauth.Strategy.Authify.OAuth,
        site: "https://authify.example.com",
        client_id: "YOUR_CLIENT_ID",
        client_secret: "YOUR_CLIENT_SECRET"

  and register the provider with its organization:

      config :ueberauth, Ueberauth,
        providers: [
          authify: {Ueberauth.Strategy.Authify, [organization: "my-org"]}
        ]

  ## Options

    * `:organization` (required) - the Authify organization slug
    * `:default_scope` - scopes requested from Authify; defaults to
      `"openid profile email"`. `"openid"` is required for an ID token
    * `:uid_field` - the ID token claim used as the uid; defaults to `:sub`
    * `:verify_id_token` - verify the ID token signature and claims
      (recommended, default); set to `false` to rely solely on the userinfo
      endpoint
    * `:leeway` - seconds of slack allowed when validating time-based ID
      token claims; defaults to `60`
    * `:pkce` - use PKCE (S256) for the authorization code exchange; enabled
      by default

  The request phase also forwards an optional `prompt` request parameter
  (Authify honors `prompt=consent`) and an optional `max_age` parameter to
  require a recent authentication, validated against the ID token's
  `auth_time` claim.

  ## Flow

  1. The request phase redirects to the organization's authorize endpoint
     with a per-login `nonce` and a PKCE `code_challenge`, both stored in the
     session for the callback.
  2. The callback phase exchanges the authorization code (with the PKCE
     verifier) for tokens, verifies the RS256 ID token against the
     organization's JWKS (refetching on key rotation) and validates the
     `iss`, `sub`, `aud`, `exp`, `iat`, `nonce` and (when `max_age` was
     requested) `auth_time` claims.
  3. The auth hash is built from the verified ID token claims; the raw claims
     and the full `%OAuth2.AccessToken{}` are available in
     `extra.raw_info`.

  The strategy requires the session (via `Plug.Session`) to carry the nonce
  and PKCE verifier between the two phases; Phoenix applications already
  provide this.

  Misconfiguration (a missing `:site` or `:organization`) fails the request
  phase with a `missing_configuration` error rather than redirecting the
  user to Authify with a broken URL.
  """

  use Ueberauth.Strategy,
    uid_field: :sub,
    default_scope: "openid profile email",
    organization: nil,
    verify_id_token: true,
    leeway: 60,
    pkce: true,
    oauth2_module: Ueberauth.Strategy.Authify.OAuth

  alias OAuth2.{AccessToken, Error, Response}
  alias Ueberauth.Auth.{Credentials, Extra, Info}
  alias Ueberauth.Strategy.Authify.JWTValidator

  @authorize_params_session_key "ueberauth_authify.authorize_params"

  @doc """
  Handles the redirect to the organization's Authify authorize endpoint.
  """
  @impl Ueberauth.Strategy
  def handle_request!(conn) do
    otp_app = option(conn, :otp_app)
    organization = option(conn, :organization)

    if missing_configuration?(otp_app, organization) do
      set_errors!(conn, [
        error("missing_configuration", "The :site and :organization options are required")
      ])
    else
      nonce = new_nonce()
      verifier = if option(conn, :pkce), do: new_code_verifier()
      max_age = forwarded_param(conn, "max_age")

      stored = %{nonce: nonce}
      stored = if verifier, do: Map.put(stored, :code_verifier, verifier), else: stored
      stored = if max_age, do: Map.put(stored, :max_age, max_age), else: stored

      params =
        [
          scope: option(conn, :default_scope),
          redirect_uri: callback_url(conn),
          nonce: nonce
        ]
        |> with_state_param(conn)
        |> maybe_put(:prompt, forwarded_param(conn, "prompt"))
        |> maybe_put(:max_age, max_age)
        |> put_pkce(verifier)

      conn
      |> fetch_session()
      |> put_session(@authorize_params_session_key, stored)
      |> redirect!(oauth_module(conn).authorize_url!(params, oauth_opts(conn, organization)))
    end
  end

  @doc """
  Handles the callback from Authify, exchanging the code for tokens and
  verifying the ID token while building the auth struct components.
  """
  @impl Ueberauth.Strategy
  def handle_callback!(%{params: %{"error" => error}} = conn)
      when is_binary(error) and error != "" do
    set_errors!(conn, [
      error(error, conn.params["error_description"] || conn.params["error_reason"] || "")
    ])
  end

  def handle_callback!(%{params: %{"code" => code}} = conn)
      when is_binary(code) and code != "" do
    {conn, stored} = pop_stored_authorize_params(conn)
    organization = option(conn, :organization)

    params =
      [code: code, redirect_uri: callback_url(conn)]
      |> maybe_put(:code_verifier, stored[:code_verifier])

    case oauth_module(conn).get_token(params, oauth_opts(conn, organization)) do
      {:ok, client} ->
        handle_token(conn, client.token, stored)

      {:error, %Response{body: body}} ->
        set_errors!(conn, [provider_error(body)])

      {:error, %Error{reason: reason}} ->
        set_errors!(conn, [error("invalid_credentials", reason)])
    end
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used during the callback.
  """
  @impl Ueberauth.Strategy
  def handle_cleanup!(conn) do
    conn
    |> put_private(:ueberauth_authify_token, nil)
    |> put_private(:ueberauth_authify_user, nil)
    |> put_private(:ueberauth_authify_id_info, nil)
  end

  @doc """
  The uid for the user, from the `:uid_field` claim (default `sub`).
  """
  @impl Ueberauth.Strategy
  def uid(conn) do
    user(conn)[to_string(option(conn, :uid_field))]
  end

  @doc """
  Includes the credentials from the Authify token response.
  """
  @impl Ueberauth.Strategy
  def credentials(%{private: %{ueberauth_authify_token: %AccessToken{} = token}}) do
    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      token_type: token.token_type,
      expires: not is_nil(token.expires_at),
      expires_at: token.expires_at,
      scopes: scopes(token),
      other: token.other_params
    }
  end

  def credentials(_conn), do: %Credentials{}

  @doc """
  Populates the extra section of the `Ueberauth.Auth` struct with the
  verified ID token claims and the full token.
  """
  @impl Ueberauth.Strategy
  def extra(%{private: private}) do
    %Extra{
      raw_info: %{
        token: Map.get(private, :ueberauth_authify_token),
        user: Map.get(private, :ueberauth_authify_user),
        id_info: Map.get(private, :ueberauth_authify_id_info)
      }
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth`
  struct, from the standard OIDC claims.

  Note that `location` is mapped from `zoneinfo` (an IANA timezone) and that
  `locale` deliberately does not end up there, mirroring the behavior of the
  Ruby `omniauth-authify` gem.
  """
  @impl Ueberauth.Strategy
  def info(conn) do
    user = user(conn)

    %Info{
      name: user["name"],
      first_name: user["given_name"],
      last_name: user["family_name"],
      nickname: user["preferred_username"],
      email: user["email"],
      image: user["picture"],
      location: user["zoneinfo"],
      phone: user["phone_number"],
      urls: info_urls(user)
    }
  end

  defp info_urls(%{"website" => website}) when is_binary(website) and website != "",
    do: %{website: website}

  defp info_urls(_user), do: %{}

  defp handle_token(conn, token, stored) do
    conn = put_private(conn, :ueberauth_authify_token, token)
    id_token = token.other_params["id_token"]

    if option(conn, :verify_id_token) do
      verify_id_token(conn, id_token, stored)
    else
      fetch_userinfo(conn, token)
    end
  end

  defp verify_id_token(conn, id_token, _stored)
       when not is_binary(id_token) or id_token == "" do
    set_errors!(conn, [error("invalid_credentials", "ID token is required but missing")])
  end

  defp verify_id_token(conn, id_token, stored) do
    otp_app = option(conn, :otp_app)
    organization = option(conn, :organization)
    module = oauth_module(conn)

    case JWTValidator.verify(id_token,
           client_id: module.client_id(otp_app),
           issuer: module.base_url(otp_app, organization),
           jwks_uri: module.base_url(otp_app, organization) <> "/.well-known/jwks",
           nonce: stored[:nonce],
           leeway: option(conn, :leeway),
           max_age: stored[:max_age]
         ) do
      {:ok, claims} ->
        conn
        |> put_private(:ueberauth_authify_id_info, claims)
        |> put_private(:ueberauth_authify_user, claims)

      {:error, reason} ->
        set_errors!(conn, [error("invalid_credentials", reason)])
    end
  end

  defp fetch_userinfo(conn, token) do
    otp_app = option(conn, :otp_app)
    organization = option(conn, :organization)

    case oauth_module(conn).get_userinfo(token, otp_app: otp_app, organization: organization) do
      {:ok, %Response{status_code: status, body: user}} when status in 200..399 ->
        put_private(conn, :ueberauth_authify_user, user || %{})

      {:ok, %Response{status_code: status}} ->
        set_errors!(conn, [
          error("invalid_credentials", "Fetching userinfo failed with HTTP #{status}")
        ])

      {:error, %Response{body: body}} ->
        set_errors!(conn, [provider_error(body)])

      {:error, %Error{reason: reason}} ->
        set_errors!(conn, [error("invalid_credentials", reason)])
    end
  end

  defp user(%{private: %{ueberauth_authify_user: user}}) when is_map(user), do: user
  defp user(_conn), do: %{}

  defp pop_stored_authorize_params(conn) do
    conn = fetch_session(conn)
    stored = get_session(conn, @authorize_params_session_key)

    conn =
      conn
      |> delete_session(@authorize_params_session_key)
      |> put_private(:ueberauth_authify_stored, true)

    {conn, normalize_stored(stored)}
  end

  defp normalize_stored(%{} = params) do
    %{
      nonce: param_value(params, :nonce),
      code_verifier: param_value(params, :code_verifier),
      max_age: param_value(params, :max_age)
    }
  end

  defp normalize_stored(_stored), do: %{nonce: nil, code_verifier: nil, max_age: nil}

  defp param_value(params, key) when is_map(params) do
    Map.get(params, key) || Map.get(params, to_string(key))
  end

  defp missing_configuration?(otp_app, organization) do
    module = option_module()
    blank?(module.site(otp_app)) or blank?(organization)
  end

  defp oauth_module(conn), do: option(conn, :oauth2_module)

  defp option_module do
    Keyword.get(default_options(), :oauth2_module, Ueberauth.Strategy.Authify.OAuth)
  end

  defp oauth_opts(conn, organization) do
    conn
    |> oauth_opts()
    |> Keyword.put(:organization, organization)
  end

  defp oauth_opts(conn) do
    if otp_app = option(conn, :otp_app), do: [otp_app: otp_app], else: []
  end

  defp option(conn, key) do
    default = Keyword.get(default_options(), key)
    conn |> options() |> Keyword.get(key, default)
  end

  defp forwarded_param(conn, name) do
    case conn.params do
      %{^name => value} when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp put_pkce(params, nil), do: params

  defp put_pkce(params, verifier) do
    challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)

    params
    |> Keyword.put(:code_challenge, challenge)
    |> Keyword.put(:code_challenge_method, "S256")
  end

  defp new_nonce do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp new_code_verifier do
    :crypto.strong_rand_bytes(64) |> Base.url_encode64(padding: false)
  end

  defp scopes(%AccessToken{} = token) do
    token.other_params["scope"]
    |> case do
      scope when is_binary(scope) -> String.split(scope, " ", trim: true)
      _ -> []
    end
  end

  defp provider_error(body) when is_map(body) do
    error(
      Map.get(body, "error") || "invalid_credentials",
      Map.get(body, "error_description") || "The token exchange failed"
    )
  end

  defp provider_error(_body) do
    error("invalid_credentials", "The token exchange failed")
  end

  defp maybe_put(params, _key, nil), do: params
  defp maybe_put(params, key, value), do: Keyword.put(params, key, value)

  defp blank?(value), do: value in [nil, ""]
end
