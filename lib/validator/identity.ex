defmodule APISexAuthBearer.Validator.Identity do
  @behaviour APISexAuthBearer.Validator

  @moduledoc """
  Returns data passed as a parameter - used for tests
  """

  @doc """
  Returns data passed as the first parameter, without altering it in any way
  """
  @impl true
  def validate(data, _opts) do
    data
  end
end
