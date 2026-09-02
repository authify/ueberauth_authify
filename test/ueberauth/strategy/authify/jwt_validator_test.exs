defmodule Ueberauth.Strategy.Authify.JWTValidatorTest do
  use ExUnit.Case, async: false

  import UeberauthAuthify.TestSupport

  alias Ueberauth.Strategy.Authify.JWKSCache
  alias Ueberauth.Strategy.Authify.JWTValidator

  @nonce "test-nonce"
  @kid "test-kid"
  @leeway 60

  setup do
    bypass = Bypass.open()

    on_exit(fn ->
      Application.put_env(
        :ueberauth,
        Ueberauth.Strategy.Authify.OAuth,
        site: "https://authify.example.com",
        client_id: client_id(),
        client_secret: "test_client_secret"
      )
    end)

    JWKSCache.clear()

    {:ok, bypass: bypass}
  end

  defp stub_jwks(bypass, jwk, kid) do
    Bypass.expect(bypass, "GET", "/#{organization()}/.well-known/jwks", fn conn ->
      respond_json(jwks_body(jwk, kid), conn, 200)
    end)
  end

  defp opts(bypass, overrides \\ []) do
    base = issuer(bypass)

    [
      client_id: client_id(),
      issuer: base,
      jwks_uri: base <> "/.well-known/jwks",
      nonce: @nonce,
      leeway: @leeway
    ]
    |> Keyword.merge(overrides)
  end

  defp valid_token(jwk, issuer) do
    make_id_token(jwk, claims(issuer, @nonce), @kid)
  end

  describe "verify/2" do
    test "verifies and returns the claims for a valid token", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      assert {:ok, claims} = JWTValidator.verify(valid_token(jwk, issuer(bypass)), opts(bypass))
      assert claims["iss"] == issuer(bypass)
      assert claims["sub"] == "424242"
    end

    test "does not refetch the JWKS when nothing changes", %{bypass: bypass} do
      jwk = rsa_key()

      parent = self()

      Bypass.expect(bypass, "GET", "/#{organization()}/.well-known/jwks", fn conn ->
        send(parent, :jwks_fetched)
        respond_json(jwks_body(jwk, @kid), conn, 200)
      end)

      token = valid_token(jwk, issuer(bypass))

      assert {:ok, _} = JWTValidator.verify(token, opts(bypass))
      assert {:ok, _} = JWTValidator.verify(token, opts(bypass))

      assert_received :jwks_fetched
      refute_received :jwks_fetched
    end

    test "refetches the JWKS when the kid is missing (rotated keys)", %{bypass: bypass} do
      jwk = rsa_key()

      parent = self()

      Bypass.expect(bypass, "GET", "/#{organization()}/.well-known/jwks", fn conn ->
        send(parent, :jwks_fetched)
        respond_json(jwks_body(jwk, "rotated-#{System.unique_integer()}"), conn, 200)
      end)

      # First verify caches a JWKS without our kid
      first_token = valid_token(jwk, issuer(bypass))

      # The kid is missing from the served JWKS, so the first verify fails
      assert {:error, _} = JWTValidator.verify(first_token, opts(bypass))

      # Now serve the matching kid: a fresh verify refetches and succeeds
      stub_jwks(bypass, jwk, @kid)
      assert {:ok, _} = JWTValidator.verify(first_token, opts(bypass))
      assert_received :jwks_fetched
      assert_received :jwks_fetched
    end

    test "raises an error when the token is missing", %{bypass: bypass} do
      assert {:error, reason} = JWTValidator.verify(nil, opts(bypass))
      assert reason =~ "required but missing"
    end

    test "rejects a malformed token", %{bypass: bypass} do
      assert {:error, reason} = JWTValidator.verify("not-a-token", opts(bypass))
      assert reason =~ "could not be decoded"

      assert {:error, reason} = JWTValidator.verify("!!!.!!.!!!", opts(bypass))
      assert reason =~ "could not be decoded"
    end

    test "rejects an unsupported algorithm", %{bypass: bypass} do
      {:ok, token, _claims} =
        Joken.generate_and_sign(
          %{},
          %{"iss" => issuer(bypass), "sub" => "1", "aud" => client_id()},
          Joken.Signer.create("HS256", "secret")
        )

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass))
      assert reason =~ "not supported"
      assert reason =~ "RS256"
    end

    test "rejects a token signed with a different key", %{bypass: bypass} do
      jwk = rsa_key()
      other_key = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token = make_id_token(other_key, claims(issuer(bypass), @nonce), @kid)

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass))
      assert reason =~ "could not be verified"
    end

    test "reports an unreachable JWKS endpoint", %{bypass: bypass} do
      Bypass.down(bypass)

      assert {:error, reason} =
               JWTValidator.verify(valid_token(rsa_key(), issuer(bypass)), opts(bypass))

      assert reason =~ "Could not fetch the Authify JWKS"
    end

    test "rejects a mismatched issuer", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token =
        make_id_token(jwk, claims(issuer(bypass), @nonce, iss: "https://evil.example.com"), @kid)

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass))
      assert reason =~ "Issuer (iss) claim mismatch"
    end

    test "rejects a mismatched audience", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token = make_id_token(jwk, claims(issuer(bypass), @nonce, aud: "OTHER_CLIENT"), @kid)

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass))
      assert reason =~ "Audience (aud) claim mismatch"
    end

    test "rejects a missing subject", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token = make_id_token(jwk, claims(issuer(bypass), @nonce, sub: nil), @kid)

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass))
      assert reason =~ "Subject (sub)"
    end

    test "rejects an expired token", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token =
        make_id_token(
          jwk,
          claims(issuer(bypass), @nonce, exp: System.system_time(:second) - 3600),
          @kid
        )

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass))
      assert reason =~ "Expiration time (exp)"
    end

    test "accepts an expired token within the leeway", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token =
        make_id_token(
          jwk,
          claims(issuer(bypass), @nonce, exp: System.system_time(:second) - 30),
          @kid
        )

      assert {:ok, _claims} = JWTValidator.verify(token, opts(bypass))
    end

    test "rejects a token issued in the future", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token =
        make_id_token(
          jwk,
          claims(issuer(bypass), @nonce, iat: System.system_time(:second) + 3600),
          @kid
        )

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass))
      assert reason =~ "Issued At (iat) claim error"
    end

    test "rejects a missing nonce", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token = make_id_token(jwk, claims(issuer(bypass), @nonce, nonce: nil), @kid)

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass))
      assert reason =~ "Nonce (nonce) claim must be"
    end

    test "rejects a mismatched nonce", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token = make_id_token(jwk, claims(issuer(bypass), "another-nonce"), @kid)

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass))
      assert reason =~ "Nonce (nonce) claim value mismatch"
    end

    test "skips the nonce check when no nonce was stored", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token = make_id_token(jwk, claims(issuer(bypass), "ignored-nonce"), @kid)

      assert {:ok, _claims} = JWTValidator.verify(token, Keyword.delete(opts(bypass), :nonce))
    end

    test "rejects a stale auth_time when max_age is specified", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token =
        make_id_token(
          jwk,
          claims(issuer(bypass), @nonce, auth_time: System.system_time(:second) - 4000),
          @kid
        )

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass, max_age: 300))
      assert reason =~ "Authentication Time (auth_time)"
    end

    test "rejects a missing auth_time when max_age is specified", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token = make_id_token(jwk, claims(issuer(bypass), @nonce, auth_time: :drop), @kid)

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass, max_age: 300))
      assert reason =~ "Authentication Time (auth_time)"
    end

    test "accepts a fresh auth_time when max_age is specified", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token =
        make_id_token(
          jwk,
          claims(issuer(bypass), @nonce, auth_time: System.system_time(:second)),
          @kid
        )

      assert {:ok, _claims} = JWTValidator.verify(token, opts(bypass, max_age: 300))
    end

    test "parses a string max_age", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      token =
        make_id_token(
          jwk,
          claims(issuer(bypass), @nonce, auth_time: System.system_time(:second) - 4000),
          @kid
        )

      assert {:error, reason} = JWTValidator.verify(token, opts(bypass, max_age: "300"))
      assert reason =~ "Authentication Time (auth_time)"
    end
  end

  describe "decode/2" do
    test "returns claims and header without claim checks", %{bypass: bypass} do
      jwk = rsa_key()
      stub_jwks(bypass, jwk, @kid)

      now = System.system_time(:second)

      token =
        make_id_token(
          jwk,
          claims(issuer(bypass), @nonce, exp: now - 999_999, iat: now - 999_999),
          @kid
        )

      assert {:ok, claims, header} = JWTValidator.decode(token, opts(bypass))
      assert claims["iss"] == issuer(bypass)
      assert header["alg"] == "RS256"
      assert header["kid"] == @kid
    end
  end
end
