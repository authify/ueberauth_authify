defmodule Ueberauth.Strategy.Authify.JWKSCache do
  @moduledoc """
  A process-free cache for organization JWKS documents.

  Signing keys are cached per JWKS URI in a public ETS table so that repeated
  logins do not refetch the key set on every callback. The cache is refreshed
  whenever an ID token references a `kid` that is missing from the cached
  keys (rotated signing keys) or a signature check fails against them.
  """

  @table :ueberauth_authify_jwks

  @doc """
  Returns the signing keys for `jwks_uri`, fetching (and caching) them when
  not already cached or when `force: true` is passed.
  """
  @spec fetch(binary(), keyword()) :: {:ok, [map()]} | {:error, binary()}
  def fetch(jwks_uri, opts \\ []) do
    force? = Keyword.get(opts, :force, false)
    ensure_table()

    case :ets.lookup(@table, jwks_uri) do
      [{^jwks_uri, keys}] when not force? ->
        {:ok, keys}

      _ ->
        do_fetch(jwks_uri)
    end
  end

  @doc """
  Empties the cache. Intended for tests.
  """
  @spec clear() :: :ok
  def clear do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp do_fetch(jwks_uri) do
    headers = [{"accept", "application/json"}]

    case Req.get(jwks_uri, headers: headers, retry: false) do
      {:ok, %{status: 200, body: %{"keys" => keys}}} when is_list(keys) ->
        true = :ets.insert(@table, {jwks_uri, keys})
        {:ok, keys}

      {:ok, %{status: status}} ->
        {:error, "Could not fetch the Authify JWKS from #{jwks_uri}: HTTP #{status}"}

      {:error, exception} ->
        {:error,
         "Could not fetch the Authify JWKS from #{jwks_uri}: #{Exception.message(exception)}"}
    end
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      try do
        :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
      rescue
        ArgumentError -> :ok
      end
    else
      :ok
    end
  end
end
