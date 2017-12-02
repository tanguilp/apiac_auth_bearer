defmodule APISexAuthBearer.Validator do
  @callback validate(binary(), map()) :: {:ok, map()} | {:error, String.t}
end
