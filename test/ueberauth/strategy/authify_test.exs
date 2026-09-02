defmodule Ueberauth.Strategy.AuthifyTest do
  use ExUnit.Case, async: false

  import UeberauthAuthify.TestSupport

  setup do
    bypass = Bypass.open()

    Application.put_env(
      :ueberauth,
      Ueberauth.Strategy.Authify.OAuth,
      site: "http://localhost:#{bypass.port}",
      client_id: client_id(),
      client_secret: "test_client_secret"
    )

    Ueberauth.Strategy.Authify.JWKSCache.clear()
    start_token_capture()

    on_exit(fn ->
      Application.put_env(
        :ueberauth,
        Ueberauth.Strategy.Authify.OAuth,
        site: "https://authify.example.com",
        client_id: client_id(),
        client_secret: "test_client_secret"
      )
    end)

    {:ok, bypass: bypass}
  end

  describe "OAuth client configuration" do
    setup do
      Application.put_env(
        :ueberauth,
        Ueberauth.Strategy.Authify.OAuth,
        site: "https://authify.example.com",
        client_id: client_id(),
        client_secret: "test_client_secret"
      )

      :ok
    end

    test "scopes the client to the organization" do
      client = Ueberauth.Strategy.Authify.OAuth.client(organization: "acme")

      assert client.site == "https://authify.example.com/acme"
      assert client.authorize_url == "https://authify.example.com/acme/oauth/authorize"
      assert client.token_url == "https://authify.example.com/acme/oauth/token"
    end

    test "accepts a site with a trailing slash" do
      Application.put_env(
        :ueberauth,
        Ueberauth.Strategy.Authify.OAuth,
        site: "https://authify.example.com//",
        client_id: client_id(),
        client_secret: "test_client_secret"
      )

      assert Ueberauth.Strategy.Authify.OAuth.client(organization: "acme").site ==
               "https://authify.example.com/acme"
    end

    test "resolves {:system, \"VAR\"} configuration tuples" do
      System.put_env("UEBERAUTH_AUTHIFY_TEST_SITE", "https://env-authify.example.com")

      Application.put_env(
        :ueberauth,
        Ueberauth.Strategy.Authify.OAuth,
        site: {:system, "UEBERAUTH_AUTHIFY_TEST_SITE"},
        client_id: client_id(),
        client_secret: "test_client_secret"
      )

      assert Ueberauth.Strategy.Authify.OAuth.site() == "https://env-authify.example.com"
    after
      System.delete_env("UEBERAUTH_AUTHIFY_TEST_SITE")
    end

    test "raises without an organization" do
      assert_raise ArgumentError, ~r/:organization/, fn ->
        Ueberauth.Strategy.Authify.OAuth.client(organization: "")
      end
    end
  end

  describe "request phase" do
    test "redirects to the organization's authorize endpoint" do
      request = request_phase()

      assert request.conn.status == 302
      assert request.location =~ "/test-org/oauth/authorize?"

      params = request.params

      assert params["response_type"] == "code"
      assert params["client_id"] == client_id()
      assert params["scope"] == "openid profile email"
      assert params["redirect_uri"] == "http://www.example.com/auth/authify/callback"
      assert params["state"] == request.conn.private[:ueberauth_state_param]
      assert params["nonce"] =~ ~r/^[0-9a-f]{32}$/
      assert params["code_challenge_method"] == "S256"
      assert params["code_challenge"] =~ ~r/^[\w-]{43}$/
    end

    test "stores the flow parameters in the session" do
      request = request_phase()

      stored = Plug.Conn.get_session(request.conn, "ueberauth_authify.authorize_params")

      assert stored.nonce == request.params["nonce"]
      assert stored.code_verifier =~ ~r/^[\w-]{80,}$/

      challenge = :crypto.hash(:sha256, stored.code_verifier) |> Base.url_encode64(padding: false)
      assert challenge == request.params["code_challenge"]
    end

    test "forwards a prompt parameter from the request" do
      request = request_phase("authify", prompt: "consent")
      assert request.params["prompt"] == "consent"
    end

    test "forwards a max_age parameter from the request" do
      request = request_phase("authify", max_age: "300")
      assert request.params["max_age"] == "300"
    end

    test "omits PKCE parameters when PKCE is disabled" do
      request = request_phase("authify_no_pkce")

      refute Map.has_key?(request.params, "code_challenge")
      refute Map.has_key?(request.params, "code_challenge_method")
    end

    test "fails with missing_configuration without an organization" do
      conn = call(Plug.Test.conn(:get, "/auth/authify_no_org"))

      assert {:ok, %{"failure" => failure}} = Jason.decode(conn.resp_body)

      assert [%{"key" => "missing_configuration", "message" => message}] = failure["errors"]
      assert message =~ ":site and :organization"
    end
  end

  describe "callback phase" do
    test "exposes the provider and uid on a successful login", %{bypass: bypass} do
      result =
        flow_through_callback(bypass, fn %{jwk: jwk, issuer: issuer, nonce: nonce} ->
          make_id_token(jwk, id_token_claims(issuer, nonce), "test-kid")
        end)

      assert result.body["provider"] == "authify"
      assert result.body["uid"] == "424242"
    end

    test "builds info from the verified ID token claims", %{bypass: bypass} do
      result =
        flow_through_callback(bypass, fn %{jwk: jwk, issuer: issuer, nonce: nonce} ->
          make_id_token(jwk, id_token_claims(issuer, nonce), "test-kid")
        end)

      info = result.body["info"]

      assert info["name"] == "Jane User"
      assert info["first_name"] == "Jane"
      assert info["last_name"] == "User"
      assert info["nickname"] == "jane@example.com"
      assert info["email"] == "jane@example.com"
      assert info["image"] == "https://authify.example.com/avatar.png"
      assert info["location"] == "America/Chicago"
      assert info["phone"] == "+15551234567"
      assert info["urls"] == %{"website" => "https://example.com/jane"}
    end

    test "includes credentials from the token response", %{bypass: bypass} do
      result =
        flow_through_callback(bypass, fn %{jwk: jwk, issuer: issuer, nonce: nonce} ->
          make_id_token(jwk, id_token_claims(issuer, nonce), "test-kid")
        end)

      credentials = result.body["credentials"]

      assert credentials["token"] == "test-access-token"
      assert credentials["refresh_token"] == "test-refresh-token"
      assert credentials["token_type"] == "Bearer"
      assert credentials["expires"] == true
      assert is_integer(credentials["expires_at"])
      assert credentials["scopes"] == ["openid", "profile", "email"]
      assert credentials["id_token"] =~ "eyJ"
    end

    test "includes verified claims and the token in extra", %{bypass: bypass} do
      result =
        flow_through_callback(bypass, fn %{jwk: jwk, issuer: issuer, nonce: nonce} ->
          make_id_token(jwk, id_token_claims(issuer, nonce), "test-kid")
        end)

      extra = result.body["extra"]

      assert extra["id_info"]["iss"] == issuer(bypass)
      assert extra["id_info"]["sub"] == "424242"
      assert extra["user"]["zoneinfo"] == "America/Chicago"
      assert extra["has_token"] == true
    end

    test "sends the PKCE code_verifier with the authorization code", %{bypass: bypass} do
      result =
        flow_through_callback(bypass, fn %{jwk: jwk, issuer: issuer, nonce: nonce} ->
          make_id_token(jwk, id_token_claims(issuer, nonce), "test-kid")
        end)

      assert result.body["uid"] == "424242"

      [token_params] = token_requests()

      assert token_params["code"] == "test-code"
      assert token_params["code_verifier"] =~ ~r/^[\w-]{80,}$/
    end

    test "fails with invalid_credentials when the nonce does not match", %{bypass: bypass} do
      result =
        flow_through_callback(bypass, fn %{jwk: jwk, issuer: issuer, nonce: _nonce} ->
          make_id_token(jwk, id_token_claims(issuer, "mismatched-nonce"), "test-kid")
        end)

      assert [%{"key" => "invalid_credentials", "message" => message}] =
               result.body["failure"]["errors"]

      assert message =~ "Nonce (nonce) claim value mismatch"
    end

    test "fails with invalid_credentials when the signature was forged", %{bypass: bypass} do
      result =
        flow_through_callback(bypass, fn %{issuer: issuer, nonce: nonce} ->
          make_id_token(rsa_key(), id_token_claims(issuer, nonce), "test-kid")
        end)

      assert [%{"key" => "invalid_credentials", "message" => message}] =
               result.body["failure"]["errors"]

      assert message =~ "could not be verified"
    end

    test "fails with invalid_credentials when the ID token is required but missing", %{
      bypass: bypass
    } do
      result = flow_through_callback(bypass, fn _context -> nil end, "authify", jwks: false)

      assert [%{"key" => "invalid_credentials", "message" => message}] =
               result.body["failure"]["errors"]

      assert message =~ "ID token is required but missing"
    end

    test "redirects to failure with the provider's error", %{bypass: _bypass} do
      request = request_phase()

      conn =
        Plug.Test.conn(
          :get,
          "/auth/authify/callback?" <>
            URI.encode_query(%{"error" => "access_denied", "state" => request.params["state"]})
        )
        |> Plug.Conn.put_req_header("cookie", cookie_header(request.conn))
        |> call()

      assert {:ok, %{"failure" => failure}} = Jason.decode(conn.resp_body)
      assert [%{"key" => "access_denied"}] = failure["errors"]
    end

    test "fails with missing_code when no code is received", %{bypass: _bypass} do
      request = request_phase()

      conn =
        Plug.Test.conn(
          :get,
          "/auth/authify/callback?" <> URI.encode_query(%{"state" => request.params["state"]})
        )
        |> Plug.Conn.put_req_header("cookie", cookie_header(request.conn))
        |> call()

      assert {:ok, %{"failure" => failure}} = Jason.decode(conn.resp_body)
      assert [%{"key" => "missing_code"}] = failure["errors"]
    end

    test "fails with csrf_attack when the state does not match", %{bypass: _bypass} do
      request = request_phase()

      conn =
        Plug.Test.conn(:get, "/auth/authify/callback?code=test-code&state=attacker-chosen-state")
        |> Plug.Conn.put_req_header("cookie", cookie_header(request.conn))
        |> call()

      assert {:ok, %{"failure" => failure}} = Jason.decode(conn.resp_body)
      assert [%{"key" => "csrf_attack"}] = failure["errors"]
    end

    test "falls back to userinfo claims when verification is disabled and no ID token is issued",
         %{bypass: bypass} do
      result =
        flow_through_callback(
          bypass,
          fn _context -> nil end,
          "authify_no_verify",
          userinfo: true,
          jwks: false
        )

      assert result.body["uid"] == "424242"
      assert result.body["info"]["email"] == "jane@example.com"
      assert result.body["extra"]["user"]["zoneinfo"] == "America/Chicago"
      assert result.body["extra"]["id_info"] == nil
    end

    test "uses the configured uid_field", %{bypass: bypass} do
      result =
        flow_through_callback(
          bypass,
          fn %{jwk: jwk, issuer: issuer, nonce: nonce} ->
            make_id_token(jwk, id_token_claims(issuer, nonce), "test-kid")
          end,
          "authify_uid_email"
        )

      assert result.body["uid"] == "jane@example.com"
    end
  end
end
