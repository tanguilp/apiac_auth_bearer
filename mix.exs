defmodule APISexAuthBearer.Mixfile do
  use Mix.Project

  def project do
    [
      app: :apisex_auth_bearer,
      version: "0.1.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:cowboy, "~> 2.0"},
      {:plug, "~> 1.0"},
      {:httpoison, "~> 1.0"},
      {:poison, "~> 3.1"},
      {:tesla, "~> 1.1.0"},
      {:apisex, github: "tanguilp/apisex", tag: "master"},
      {:oauth2_utils, github: "tanguilp/oauth2_utils", tag: "master"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end
end
