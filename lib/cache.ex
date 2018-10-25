defmodule APISexAuthBearer.Cache do
  @moduledoc """
  `APISexAuthBearer.Cache` behaviour specification
  """

  @type opts :: Keyword.t

  @doc """
  Initializes the cache options

  This function is called at compile-time when `APISexAuthBearer` is called in
  a plug pipeline. Its result will be given to `put/3` and `get/2`
  """
  @callback init_opts(opts) :: opts

  @doc """
  Stores the bearer's attributes in the cache
  """
  @callback put(APISexAuthBearer.bearer,
                APISexAuthBearer.Validator.response_attributes,
                opts) :: no_return()

  @doc """
  Returns the bearer's attributes stored in the cache

  Returns `nil` if the bearer was not found in the cache
  """
  @callback get(APISexAuthBearer.bearer, opts)
    :: APISexAuthBearer.Validator.response_attributes | nil

end
