defmodule APIacAuthBearer.Cache.NoCache do
  @moduledoc """
  Default cache module - do not cache

  Beware of using it in production environment with
  `APIacAuthBearer.Validator.Introspect` as the target authorization server will receive
  request for every API request
  """

  @behaviour APIacAuthBearer.Cache

  @impl true
  def init_opts(_), do: []

  @impl true
  def put(_bearer, _attrs, _opts) do
  end

  @impl true
  def get(_bearer, _opts), do: nil
end
