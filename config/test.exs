import Config

config :ueberauth, Ueberauth,
  providers: [
    authify: {Ueberauth.Strategy.Authify, [organization: "test-org"]},
    authify_no_pkce: {Ueberauth.Strategy.Authify, [organization: "test-org", pkce: false]},
    authify_no_verify:
      {Ueberauth.Strategy.Authify, [organization: "test-org", verify_id_token: false]},
    authify_no_org: {Ueberauth.Strategy.Authify, []},
    authify_uid_email: {Ueberauth.Strategy.Authify, [organization: "test-org", uid_field: :email]}
  ]

config :ueberauth, Ueberauth.Strategy.Authify.OAuth,
  site: "https://authify.example.com",
  client_id: "test_client_id",
  client_secret: "test_client_secret"

config :oauth2, :adapter, {Tesla.Adapter.Finch, name: UeberauthAuthify.Finch}
