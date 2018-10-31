defmodule APISexAuthBearer.Cache.ETSMock do
  @behaviour APISexAuthBearer.Cache

  @moduledoc """
  A mock cache implementation for tests

  Stores the bearer tokens in an ETS table. Do not support TTL, which means bearers will
  be stored until the application is stopped
  """

  @impl true
  def init_opts(opts), do: opts

  @impl true
  def put(bearer, attributes, _opts) do
    create_ets_table()

    :ets.insert(:apisex_auth_bearer_cache_ets_mock, {bearer, attributes})
  end

  @impl true
  def get(bearer, _opts) do
    create_ets_table()

    case :ets.lookup(:apisex_auth_bearer_cache_ets_mock, bearer) do
      [{_bearer, attrs}] ->
        attrs

      _ ->
        nil
    end
  end

  defp create_ets_table() do
    if :ets.info(:apisex_auth_bearer_cache_ets_mock) == :undefined do
      :ets.new(:apisex_auth_bearer_cache_ets_mock, [:set, :public, :named_table])
    end
  end
end
