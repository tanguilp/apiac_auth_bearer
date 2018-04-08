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
      {:cowboy, "~> 1.0.0"},
      {:plug, "~> 1.0"},
      {:httpoison, "~> 0.13"},
      {:poison, "~> 3.1"},
      {:tesla, "1.0.0-beta.1"},
      {:apisex, git: "https://github.com/sergeypopol/apisex.git", tag: "master"}
    ]
  end
end
