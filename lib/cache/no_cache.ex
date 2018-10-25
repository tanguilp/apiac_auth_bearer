defmodule NoCache do
  @behaviour APISexAuthBearer.Cache

  @impl true
  def init_opts(_), do: []

  @impl true
  def put(_bearer, _attrs, _opts) do
  end

  @impl true
  def get(_bearer, _opts), do: nil
end
