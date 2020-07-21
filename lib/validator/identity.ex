defmodule APIacAuthBearer.Validator.Identity do
  @behaviour APIacAuthBearer.Validator

  @moduledoc """
  Returns data passed as a parameter - used for tests
  """

  @doc """
  Returns data passed as the `:response` member of the `opts` parameter
  """

  @impl true
  def validate_opts(_), do: :ok

  @impl true
  def validate_bearer(_bearer, opts) do
    opts[:response]
  end
end
