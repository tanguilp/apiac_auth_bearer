defmodule APISexAuthBearer.Validator do
  @moduledoc """
  `APISexAuthBearer.Validator` behaviour specification

  An `APISexAuthBearer.Validator` implements a `validate/2` function that take the
  following parameters:
  - the Bearer token (a `String.t`)
  - validator-specific options

  It returns `{:ok, attributes}` where `attributes` is a map containing the relevant token data
  when the bearer token is valid. In particular, the validator is in charge of performing
  the required security checks.
  The function shall return `{:error, atom()}` when validation fails for any reason, where
  `atom()` is the error reason.
  """

  @type opts :: Keyword.t

  @type response_attributes :: %{
    optional(String.t) => String.t
  }

  @callback validate(binary(), opts) ::
    {:ok, __MODULE__.response_attributes} | {:error, atom()}
end
