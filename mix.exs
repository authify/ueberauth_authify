defmodule UeberauthAuthify.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/authify/ueberauth_authify"

  def project do
    [
      app: :ueberauth_authify,
      version: @version,
      name: "Ueberauth Authify",
      description:
        "An Ueberauth strategy for Authify, a self-hosted multi-tenant OIDC identity provider.",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: docs(),
      package: package(),
      aliases: aliases()
    ]
  end

  def cli do
    [
      preferred_envs: [
        credo: :test,
        precommit: :test
      ]
    ]
  end

  # Run `mix precommit` after making changes to catch issues early.
  defp aliases do
    [
      precommit: [
        "compile --warnings-as-errors",
        "deps.unlock --unused",
        "format --check-formatted",
        "test",
        "credo --strict"
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:ueberauth, "~> 0.10"},
      {:oauth2, "~> 2.1"},
      {:joken, "~> 2.6"},
      {:jose, "~> 1.11"},
      {:req, "~> 0.7"},
      # Security floor for mint, a runtime transitive dependency
      # (req -> finch -> mint). The published package ships no mix.lock, so
      # without this constraint a consumer can resolve a vulnerable mint.
      # The floor (>= 1.10.2) clears all 6 mint advisories — EEF-CVE-2026-82729,
      # -82672, -91043 (HIGH), -92103, -94194 and -82728 (HIGH) — and forces
      # consumers off the vulnerable 1.9.3 (1.10.0/1.10.1 are affected too).
      # See ghostex-10a.
      {:mint, ">= 1.10.2"},
      # Dev/test
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:bypass, "~> 2.1", only: :test}
    ]
  end

  defp docs do
    [
      extras: [
        "CHANGELOG.md": [title: "Changelog"],
        "CONTRIBUTING.md": [title: "Contributing"],
        LICENSE: [title: "License"],
        "README.md": [title: "Overview"]
      ],
      main: "readme",
      source_url: @source_url,
      source_ref: "v#{@version}",
      formatters: ["html"]
    ]
  end

  defp package do
    [
      description:
        "An Ueberauth strategy for Authify, a self-hosted multi-tenant OIDC identity provider.",
      files: ["lib", "mix.exs", "README.md", "LICENSE", "CHANGELOG.md", "CONTRIBUTING.md"],
      licenses: ["MIT"],
      links: %{
        Changelog: "#{@source_url}/blob/main/CHANGELOG.md",
        GitHub: @source_url
      }
    ]
  end
end
