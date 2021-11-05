defmodule APIacAuthBearer.Mixfile do
  use Mix.Project

  def project do
    [
      app: :apiac_auth_bearer,
      description: "An APIac authenticator plug for API authentication using the HTTP Bearer scheme",
      version: "2.0.0",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [
        main: "readme",
        extras: ["README.md", "CHANGELOG.md"]
      ],
      package: package(),
      source_url: "https://github.com/tanguilp/apiac_auth_bearer"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:apiac, "~> 1.0"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:hackney, "~> 1.0"},
      {:jose_utils, "~> 0.3"},
      {:jwks_uri_updater, "~> 1.0"},
      {:oauth2_metadata_updater, "~> 1.0"},
      {:oauth2_utils, "~> 0.1.0"},
      {:plug, "~> 1.0"},
      {:tesla, "~> 1.0"},
      {:tesla_oauth2_client_auth, "~> 1.0"}
    ]
  end

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/apiac_auth_bearer"}
    ]
  end
end
