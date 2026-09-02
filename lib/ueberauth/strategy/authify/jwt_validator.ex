defmodule Ueberauth.Strategy.Authify.JWTValidator do
  @moduledoc """
  Validates OpenID Connect ID tokens issued by Authify.

  Verifies the RS256 signature against the signing keys published at the
  organization's JWKS endpoint (refetching on a `kid` miss), and the standard
  ID token claims: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time` (when
  `max_age` applies) and `nonce`.

  Options:

    * `:client_id` - the expected `aud` value
    * `:issuer` - the expected `iss` value
    * `:jwks_uri` - the organization's JWKS endpoint URL
    * `:nonce` - the per-login nonce bound to the authorization request
    * `:leeway` - seconds of slack for time-based claims (defaults to `60`)
    * `:max_age` - when set, requires a fresh `auth_time` claim

  """

  alias Ueberauth.Strategy.Authify.JWKSCache

  @supported_algorithms ["RS256"]

  @doc """
  Decodes an ID token and verifies its signature and claims.

  Returns `{:ok, claims}` on success or `{:error, message}` describing the
  first failed check.
  """
  @spec verify(binary() | nil, keyword()) :: {:ok, map()} | {:error, binary()}
  def verify(token, opts \\ [])

  def verify(token, _opts) when not is_binary(token) or token == "" do
    {:error, "ID token is required but missing"}
  end

  def verify(token, opts) do
    leeway = leeway(opts)

    with {:ok, claims, _header} <- decode(token, opts),
         :ok <- verify_iss(claims, opts),
         :ok <- verify_sub(claims),
         :ok <- verify_aud(claims, opts),
         :ok <- verify_expiration(claims, leeway),
         :ok <- verify_iat(claims, leeway),
         :ok <- verify_auth_time(claims, opts, leeway),
         :ok <- verify_nonce(claims, opts) do
      {:ok, claims}
    end
  end

  @doc """
  Decodes an ID token, verifying its signature (refetching the JWKS on a `kid`
  miss) but skipping all claim checks.
  """
  @spec decode(binary(), keyword()) :: {:ok, map(), map()} | {:error, binary()}
  def decode(token, opts \\ []) when is_binary(token) do
    with {:ok, header} <- token_header(token),
         :ok <- check_algorithm(header),
         {:ok, claims} <- verify_signature(token, header, opts) do
      {:ok, claims, header}
    end
  end

  defp token_header(token) do
    case String.split(token, ".") do
      [protected, _payload, _signature] ->
        case Base.url_decode64(protected, padding: false) do
          {:ok, decoded} ->
            case Jason.decode(decoded) do
              {:ok, %{} = header} -> {:ok, header}
              _ -> {:error, "ID token could not be decoded"}
            end

          :error ->
            {:error, "ID token could not be decoded"}
        end

      _ ->
        {:error, "ID token could not be decoded"}
    end
  end

  defp check_algorithm(%{"alg" => alg}) when alg in @supported_algorithms, do: :ok

  defp check_algorithm(%{"alg" => alg}) do
    {:error,
     "Signature algorithm of #{inspect(alg)} is not supported. " <>
       "Expected the ID token to be signed with RS256"}
  end

  defp check_algorithm(_header), do: {:error, "ID token could not be decoded"}

  defp verify_signature(token, header, opts) do
    jwks_uri = Keyword.fetch!(opts, :jwks_uri)

    with {:ok, keys} <- JWKSCache.fetch(jwks_uri) do
      case attempt_verify(token, keys, header) do
        {:ok, claims} ->
          {:ok, claims}

        {:error, :no_matching_key} ->
          refetch_and_verify(token, header, jwks_uri)

        {:error, :signature_error} ->
          refetch_and_verify(token, header, jwks_uri)
      end
    end
  end

  defp refetch_and_verify(token, header, jwks_uri) do
    with {:ok, keys} <- JWKSCache.fetch(jwks_uri, force: true) do
      case attempt_verify(token, keys, header) do
        {:ok, claims} -> {:ok, claims}
        _ -> {:error, "ID token could not be verified"}
      end
    end
  end

  defp attempt_verify(token, keys, header) do
    case signer_for(keys, header["kid"]) do
      {:ok, signer} ->
        case Joken.Signer.verify(token, signer) do
          {:ok, claims} -> {:ok, claims}
          {:error, _reason} -> {:error, :signature_error}
        end

      :error ->
        {:error, :no_matching_key}
    end
  end

  defp signer_for(keys, kid) do
    candidates = Enum.filter(keys, &(is_map_key(&1, "kty") and &1["kty"] == "RSA"))

    candidates =
      if is_binary(kid) and kid != "" do
        Enum.filter(candidates, &(Map.get(&1, "kid") == kid))
      else
        candidates
      end

    case candidates do
      [key] ->
        {:ok, %Joken.Signer{alg: "RS256", jwk: JOSE.JWK.from_map(key)}}

      _ ->
        :error
    end
  end

  defp verify_iss(claims, opts) do
    expected = Keyword.get(opts, :issuer)
    found = claims["iss"]

    if found == expected do
      :ok
    else
      {:error,
       "Issuer (iss) claim mismatch in the ID token, expected (#{expected}), " <>
         "found (#{inspect(found)})"}
    end
  end

  defp verify_sub(claims) do
    if is_binary(claims["sub"]) and claims["sub"] != "" do
      :ok
    else
      {:error, "Subject (sub) claim must be a string present in the ID token"}
    end
  end

  defp verify_aud(claims, opts) do
    client_id = Keyword.get(opts, :client_id)
    audiences = aud_list(claims["aud"])

    cond do
      audiences == [] ->
        {:error,
         "Audience (aud) claim must be a string or array of strings present in the ID token"}

      client_id in audiences ->
        :ok

      true ->
        {:error,
         "Audience (aud) claim mismatch in the ID token; expected (#{client_id}), " <>
           "found (#{Enum.join(audiences, ", ")})"}
    end
  end

  defp aud_list(aud) when is_binary(aud) and aud != "", do: [aud]
  defp aud_list(aud) when is_list(aud), do: Enum.filter(aud, &is_binary/1)
  defp aud_list(_aud), do: []

  defp verify_expiration(claims, leeway) do
    case claims["exp"] do
      exp when is_integer(exp) ->
        if exp > System.system_time(:second) - leeway do
          :ok
        else
          {:error,
           "Expiration time (exp) claim error in the ID token; " <>
             "current time (#{now_string()}) is after expiration time " <>
             "(#{unix_to_string(exp + leeway)})"}
        end

      _ ->
        {:error, "Expiration time (exp) claim must be a number present in the ID token"}
    end
  end

  defp verify_iat(claims, leeway) do
    case claims["iat"] do
      iat when is_integer(iat) ->
        if iat > System.system_time(:second) + leeway do
          {:error,
           "Issued At (iat) claim error in the ID token; issued in the future " <>
             "at #{unix_to_string(iat)} (current time #{now_string()})"}
        else
          :ok
        end

      _ ->
        {:error, "Issued At (iat) claim must be a number present in the ID token"}
    end
  end

  defp verify_auth_time(claims, opts, leeway) do
    case max_age(opts) do
      nil ->
        :ok

      max_age ->
        case claims["auth_time"] do
          auth_time when is_integer(auth_time) ->
            if System.system_time(:second) > auth_time + max_age + leeway do
              {:error,
               "Authentication Time (auth_time) claim in the ID token indicates that " <>
                 "too much time has passed since the last end-user authentication"}
            else
              :ok
            end

          _ ->
            {:error,
             "Authentication Time (auth_time) claim must be a number present in the " <>
               "ID token when Max Age (max_age) is specified"}
        end
    end
  end

  defp verify_nonce(claims, opts) do
    case Keyword.get(opts, :nonce) do
      nil ->
        :ok

      nonce ->
        case claims["nonce"] do
          received when is_binary(received) and received != "" ->
            if received == nonce do
              :ok
            else
              {:error,
               "Nonce (nonce) claim value mismatch in the ID token; " <>
                 "expected (#{nonce}), found (#{received})"}
            end

          _ ->
            {:error, "Nonce (nonce) claim must be a string present in the ID token"}
        end
    end
  end

  defp leeway(opts), do: Keyword.get(opts, :leeway, 60)

  defp max_age(opts) do
    case Keyword.get(opts, :max_age) do
      nil ->
        nil

      value when is_integer(value) ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {parsed, _rest} -> parsed
          :error -> nil
        end

      _ ->
        nil
    end
  end

  defp now_string, do: unix_to_string(System.system_time(:second))

  defp unix_to_string(unix) do
    unix |> DateTime.from_unix!() |> DateTime.to_iso8601()
  end
end
