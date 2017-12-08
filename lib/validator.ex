defmodule APISexAuthBearer.Validator do
  @type response_attributes :: %{
    optional(String.t) => String.t
  }

  @callback validate(binary(), map()) :: {:ok, __MODULE__.response_attributes} | {:error, String.t}
end
