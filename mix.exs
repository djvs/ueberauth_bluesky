defmodule UeberauthBluesky.MixProject do 
  use Mix.Project 
  
  def project do
    [
      app: :ueberauth_bluesky,
      description: "Ueberauth strategy for Bluesky (atproto)",
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      license: "Hippocratic-2.1"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:ueberauth, "~> 0.10"},
      {:oauth2, "~> 2.1"},
      {:jose, "~> 1.11"},
      {:uuid, "~> 1.1"},
      {:hackney, "~> 1.18"},
      {:req, "~> 0.4"}
    ]
  end
end
