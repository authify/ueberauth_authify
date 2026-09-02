defmodule SpecRouter do
  @moduledoc false

  require Ueberauth
  use Plug.Router

  @session_options [
    store: :cookie,
    key: "_authify_test_key",
    signing_salt: "CXlmrshG"
  ]

  plug(Plug.Session, @session_options)

  plug(:fetch_query_params)

  plug(Ueberauth, base_path: "/auth")

  plug(:match)
  plug(:dispatch)

  get "/auth/:provider" do
    send_response(conn)
  end

  get "/auth/:provider/callback" do
    send_response(conn)
  end

  defp send_response(conn) do
    case {conn.assigns[:ueberauth_auth], conn.assigns[:ueberauth_failure]} do
      {nil, nil} ->
        send_resp(conn, 200, "")

      {nil, failure} ->
        payload = %{
          failure: %{
            errors: Enum.map(failure.errors, &%{key: &1.message_key, message: &1.message})
          }
        }

        send_resp(conn, 200, Jason.encode!(payload))

      {auth, _failure} ->
        send_resp(conn, 200, Jason.encode!(auth_payload(auth)))
    end
  end

  defp auth_payload(auth) do
    %{
      provider: auth.provider,
      uid: auth.uid,
      info: %{
        name: auth.info.name,
        first_name: auth.info.first_name,
        last_name: auth.info.last_name,
        nickname: auth.info.nickname,
        email: auth.info.email,
        image: auth.info.image,
        location: auth.info.location,
        phone: auth.info.phone,
        urls: auth.info.urls
      },
      credentials: %{
        token: auth.credentials.token,
        refresh_token: auth.credentials.refresh_token,
        token_type: auth.credentials.token_type,
        expires: auth.credentials.expires,
        expires_at: auth.credentials.expires_at,
        scopes: auth.credentials.scopes,
        id_token: auth.credentials.other["id_token"]
      },
      extra: %{
        user: auth.extra.raw_info[:user],
        id_info: auth.extra.raw_info[:id_info],
        has_token: not is_nil(auth.extra.raw_info[:token])
      }
    }
  end
end

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
