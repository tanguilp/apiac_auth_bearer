defmodule APISexAuthBearer.Cache do
  @moduledoc """
  `APISexAuthBearer.Cache` behaviour specification

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

  @callback init_opts(opts) :: opts

  @callback put(APISexAuthBearer.bearer,
                APISexAuthBearer.Validator.response_attributes,
                opts) :: no_return()

  @callback get(APISexAuthBearer.bearer, opts)
    :: APISexAuthBearer.Validator.response_attributes | nil

end
