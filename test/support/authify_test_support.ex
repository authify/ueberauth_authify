defmodule SpecRouterHelpers do
  @moduledoc false

  # Plug.Test conns have a nil secret_key_base, which the cookie session store
  # requires for signing. Set one on every test conn before it hits the router.
  def call(conn) do
    conn
    |> Map.replace!(:secret_key_base, String.duplicate("t", 64))
    |> SpecRouter.call(SpecRouter.init([]))
  end
end

defmodule UeberauthAuthify.TestSupport do
  @moduledoc false

  # Helpers shared by the strategy and JWT validator test suites: RSA key
  # material, ID token signing, JWKS responses and the JSON payloads served
  # by the Bypass endpoints.

  @client_id "test_client_id"
  @organization "test-org"
  @token_requests_table :ueberauth_authify_token_requests

  def client_id, do: @client_id
  def organization, do: @organization

  @doc """
  Generates a 2048-bit RSA signing key.
  """
  def rsa_key do
    JOSE.JWK.generate_key({:rsa, 2048})
  end

  @doc """
  The public JWKS body for `jwk` with the given `kid`.
  """
  def jwks_body(jwk, kid) do
    {_jwk, public_map} = JOSE.JWK.to_public_map(jwk)

    Jason.encode!(%{"keys" => [Map.put(public_map, "kid", kid)]})
  end

  @doc """
  Signs an ID token with RS256 (and a `kid` header) for the given claims.
  """
  def make_id_token(jwk, claims, kid) do
    header = %{"alg" => "RS256", "kid" => kid}

    jwk
    |> JOSE.JWT.sign(header, claims)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  @doc """
  Builds a complete ID token claim set for the given issuer and nonce,
  overridable per test.
  """
  def id_token_claims(issuer, nonce, overrides \\ %{}) do
    now = System.system_time(:second)

    Map.merge(
      %{
        "iss" => issuer,
        "sub" => "424242",
        "aud" => @client_id,
        "exp" => now + 3600,
        "iat" => now,
        "nonce" => nonce,
        "name" => "Jane User",
        "given_name" => "Jane",
        "family_name" => "User",
        "preferred_username" => "jane@example.com",
        "email" => "jane@example.com",
        "email_verified" => true,
        "picture" => "https://authify.example.com/avatar.png",
        "locale" => "en_US",
        "zoneinfo" => "America/Chicago",
        "website" => "https://example.com/jane",
        "phone_number" => "+15551234567"
      },
      Map.new(overrides, fn {key, value} -> {to_string(key), value} end)
    )
  end

  @doc """
  The JSON body served by the Bypass token endpoint, embedding `id_token`.
  """
  def token_response(id_token, overrides \\ %{}) do
    Jason.encode!(
      Map.merge(
        %{
          "access_token" => "test-access-token",
          "token_type" => "Bearer",
          "expires_in" => 3600,
          "refresh_token" => "test-refresh-token",
          "scope" => "openid profile email",
          "id_token" => id_token
        },
        Map.new(overrides, fn {key, value} -> {to_string(key), value} end)
      )
    )
  end

  @doc """
  The JSON body served by the Bypass userinfo endpoint.
  """
  def userinfo_body do
    Jason.encode!(%{
      "sub" => "424242",
      "name" => "Jane User",
      "given_name" => "Jane",
      "family_name" => "User",
      "preferred_username" => "jane@example.com",
      "email" => "jane@example.com",
      "picture" => "https://authify.example.com/avatar.png",
      "locale" => "en_US",
      "zoneinfo" => "America/Chicago",
      "website" => "https://example.com/jane",
      "phone_number" => "+15551234567"
    })
  end

  @doc """
  Resets the public ETS table recording every token request body received by
  the Bypass token endpoint.
  """
  def start_token_capture do
    if :ets.whereis(@token_requests_table) == :undefined do
      :ets.new(@token_requests_table, [:named_table, :public, :set, read_concurrency: true])
    end

    :ets.delete_all_objects(@token_requests_table)
    :ok
  end

  @doc """
  The list of decoded request bodies sent to the token endpoint, oldest
  first.
  """
  def token_requests do
    case :ets.whereis(@token_requests_table) do
      :undefined -> []
      _ -> :ets.tab2list(@token_requests_table) |> Enum.sort() |> Enum.map(&elem(&1, 1))
    end
  end

  @doc """
  Records a token request body (called from within the Bypass process).
  """
  def record_token_request(params) do
    if :ets.whereis(@token_requests_table) != :undefined do
      :ets.insert(@token_requests_table, {System.unique_integer(), params})
    end

    :ok
  end

  @doc """
  Calls the SpecRouter with `conn`.
  """
  def call(conn) do
    SpecRouterHelpers.call(conn)
  end

  @doc """
  Builds ID token claims. An override of `nil` or `:drop` removes the claim.
  """
  def claims(issuer, nonce, overrides \\ []) do
    base = id_token_claims(issuer, nonce)

    Enum.reduce(overrides, base, fn
      {key, value}, acc when is_nil(value) or value == :drop ->
        Map.drop(acc, [to_string(key)])

      {key, value}, acc ->
        Map.put(acc, to_string(key), value)
    end)
  end

  @doc """
  Drives the request phase and returns the redirect location and its query
  params (state, nonce, code_challenge, ...).
  """
  def request_phase(provider \\ "authify", query_params \\ []) do
    query =
      case query_params do
        [] -> ""
        params -> "?" <> URI.encode_query(params)
      end

    conn = call(Plug.Test.conn(:get, "/auth/#{provider}#{query}"))

    location = Plug.Conn.get_resp_header(conn, "location") |> List.first()
    query = if location, do: URI.parse(location).query || "", else: ""

    %{
      conn: conn,
      location: location,
      params: URI.decode_query(query)
    }
  end

  @doc """
  Extracts the cookie header value from a response conn so the next request
  (the callback) carries the session and state cookies forward.
  """
  def cookie_header(conn) do
    conn.resp_cookies
    |> Enum.map_join("; ", fn {name, opts} -> "#{name}=#{opts[:value]}" end)
  end

  @doc """
  Drives a full login flow against the Bypass server: request phase, then
  the callback, which exchanges the code with the Bypass token endpoint.

  `id_token_builder` is called with `%{jwk: jwk, issuer: issuer, nonce: nonce}`
  and must return the ID token string to embed in the token response (or
  `nil` to omit it). `jwk` is the key whose public form is served by the JWKS
  endpoint; builders may sign with a different key to test failure paths.

  Returns `%{conn: conn, body: decoded_callback_body, request: request_phase_result}`.
  """
  def flow_through_callback(bypass, id_token_builder, provider \\ "authify", opts \\ []) do
    request = request_phase(provider)
    jwk = rsa_key()
    issuer = issuer(bypass)

    Bypass.expect(bypass, "POST", "/#{@organization}/oauth/token", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      record_token_request(URI.decode_query(body))

      id_token = id_token_builder.(%{jwk: jwk, issuer: issuer, nonce: request.params["nonce"]})

      id_token
      |> token_response()
      |> respond_json(conn, 200)
    end)

    if opts[:jwks] != false do
      Bypass.expect(bypass, "GET", "/#{@organization}/.well-known/jwks", fn conn ->
        respond_json(jwks_body(jwk, "test-kid"), conn, 200)
      end)
    end

    if opts[:userinfo] do
      Bypass.expect(bypass, "GET", "/#{@organization}/oauth/userinfo", fn conn ->
        respond_json(userinfo_body(), conn, 200)
      end)
    end

    callback_query =
      URI.encode_query(%{"code" => "test-code", "state" => request.params["state"]})

    conn =
      Plug.Test.conn(:get, "/auth/#{provider}/callback?#{callback_query}")
      |> Plug.Conn.put_req_header("cookie", cookie_header(request.conn))
      |> call()

    %{conn: conn, body: Jason.decode!(conn.resp_body), request: request}
  end

  @doc """
  The organization-scoped issuer for the given Bypass server.
  """
  def issuer(bypass), do: "http://localhost:#{bypass.port}/#{@organization}"

  def respond_json(body, conn, status) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.resp(status, body)
  end
end
