defmodule APISexAuthBearer.Validator.Introspect do
  @behaviour APISexAuthBearer.Validator

  @moduledoc """
  An implementation of client Bearer validation conforming to [RFC7662](https://tools.ietf.org/html/rfc7662)

  This validator accepts the following options:
  - `issuer`: an OAuth2 issuer whose metadata will be resolved by `OAuth2MetadataUpdater`.
  When using this option, make sure you have added `OAuth2MetadataUpdater` in you `mix.exs` file.
  The option value is one of:
    - `"issueruri"`: metadata will be resolved directly on this URI
    - `{"issueruri", opts}`: metadata will be resolved with `opts` passed as params to OAuth2MetadataUpdater
  - `introspection_endpoint`: the URI of the introspection endpoint. Note that the `issuer`
  option has precedence over the `introspection_endpoint` option
  - `tesla_middlewares`: a list of [`Tesla.Middleware`s](https://hexdocs.pm/tesla/Tesla.Middleware.html#content)
  that will sequentially be called before requesting the introspection endpoint.
  Use it to authenticate to the OAuth2 authorization server.
  """

  @impl true
  def validate(bearer, validator_opts) do
    validator_opts = init_opts(validator_opts)

    middlewares = [
      {Tesla.Middleware.FormUrlencoded, nil},
      {Tesla.Middleware.Headers, [{"accept", "application/json"}]},
    ] ++ validator_opts[:tesla_middlewares]

    # default httpc Tesla's adapter is unsafe (does not check TLS certificates)
    http_client = Tesla.client(middlewares, Tesla.Adapter.Hackney)

    req_body = [{"token", bearer}, {"token_type_hint", "access_token"}]

    with {:ok, introspection_endpoint} <- introspection_endpoint(validator_opts),
         {:ok, %Tesla.Env{status: 200, headers: headers, body: resp_body}} <- Tesla.post(http_client, introspection_endpoint, req_body),
         :ok <- valid_content_type?(headers),
         {:ok, parsed_body} <- Poison.decode(resp_body)
    do
      case parsed_body do
        %{"active" => "true"} ->
          {:ok, parsed_body}

        _ ->
          {:error, :invalid_token}
      end
    end
  end

  defp init_opts(validator_opts) do
    if is_nil(validator_opts[:issuer]) and is_nil(validator_opts[:introspection_endpoint]) do
      raise "#{__MODULE__}: missing `issuer` or `introspection_endpoint`"
    end

    Keyword.put_new(validator_opts, :tesla_middlewares, [])
  end

  defp introspection_endpoint(validator_opts) do
    if not is_nil(validator_opts[:issuer]) do
      {issuer_uri, oa2mu_opts} =
        case validator_opts[:issuer] do
          issuer_uri when is_binary(issuer_uri) ->
            {issuer_uri, []}

          {issuer_uri, validator_opts} ->
            {issuer_uri, validator_opts}
        end

      case Oauth2MetadataUpdater.get_metadata_value(issuer_uri, "introspection_endpoint", oa2mu_opts) do
        {:ok, nil} ->
          {:error, :no_introspection_endpoint}

        {:ok, introspection_endpoint} ->
          {:ok, introspection_endpoint}

        {:error, error} ->
          {:error, error}
      end
    else
      if is_binary(validator_opts[:introspection_endpoint]) do
        validator_opts[:introspection_endpoint]
      else
        {:error, :no_introspection_endpoint}
      end
    end
  end

  defp valid_content_type?(headers) do
    if {"content-type", "application/json"} in headers do
      :ok
    else
      {:error, :invalid_content_type_returned_by_introspection_endpoint}
    end
  end
end
