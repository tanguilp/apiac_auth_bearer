defmodule APIacAuthBearer.Validator.Introspect do
  @moduledoc """
  An implementation of client Bearer validation conforming to [RFC7662](https://tools.ietf.org/html/rfc7662)

  This validator accepts the following options:
  - `:client_config` **[Mandatory]**: a `( -> %{required(String.t()) => any()})` function
  that returns the OAuth2 / OpenID Connect client configuration of the current resource
  server. This is used for client authentication using `TeslaOAuth2ClientAuth`. For
  instance, a client using the `"client_secret_basic"` authentication scheme should
  return:

        %{
          "client_id": "some_client_id",
          "client_secret": "TGcGGFGhjYpi5J5bZ3nggG4L9cM",
          "token_endpoint_auth_method": "client_secret_basic" # default, can be removed
        }

  - `issuer` **[Mandatory]**: an OAuth2 issuer whose metadata will be resolved by
  `OAuth2MetadataUpdater`
  - `:oauth2_metadata_updater_opts`: options that will be passed to `Oauth2MetadataUpdater`
  - `:server_metadata`: server metadata that takes precedence over those automatically
  retrieve from the server (requested from the issuer). Usefull when the OP does
  not support OAuth2 metadata or OpenID Connect discovery, or to override one or more
  parameters
  - `:tesla_auth_middleware_opts`: additional `Keyword.t()` options to be passed as
  options to the `TeslaOAuth2ClientAuth` authentication middleware
  - `:tesla_middlewares`: `Tesla` middlewares added to outbound request
  to the token endpoint)
  """

  @behaviour APIacAuthBearer.Validator

  @impl true
  def validate_opts(opts) do
    cond do
      not is_function(opts[:client_config], 0) ->
        {:error, "missing or invalid mandatory option `:client_config` for #{__MODULE__}"}

      not is_binary(opts[:issuer]) ->
        {:error, "missing or invalid mandatory option `:issuer` for #{__MODULE__}"}

      true ->
        :ok
    end
  end

  @impl true
  def validate_bearer(bearer, opts) do
    req_body = [{"token", bearer}, {"token_type_hint", "access_token"}]

    with %{"introspection_endpoint" => introspection_endpoint} = server_metadata <-
           server_metadata(opts),
         :ok <- is_https(introspection_endpoint),
         {:ok, middlewares} <- tesla_middlewares(server_metadata, opts),
         http_client = Tesla.client(middlewares, tesla_adapter()),
         {:ok, %Tesla.Env{status: 200, body: resp_body}} <-
           Tesla.post(http_client, introspection_endpoint, req_body) do
      case resp_body do
        %{"active" => true} ->
          {:ok, resp_body}

        _other ->
          {:error, :invalid_token}
      end
    else
      {:ok, %Tesla.Env{}} ->
        {:error, :invalid_introspect_endpoint_http_status_code}

      {:error, _} = error ->
        error

      _ ->
        {:error, :missing_introspection_endpoint}
    end
  end

  defp tesla_middlewares(server_metadata, opts) do
    client_config = opts[:client_config].()
    auth_method = client_config["token_endpoint_auth_method"] || "client_secret_basic"

    case TeslaOAuth2ClientAuth.implementation(auth_method) do
      {:ok, authenticator} ->
        middleware_opts = Map.merge(
          opts[:tesla_auth_middleware_opts] || %{},
          %{
            client_id: Map.fetch!(client_config, "client_id"),
            client_config: client_config,
            server_metadata: server_metadata
          }
        )

        {
          :ok,
          [{authenticator, middleware_opts}]
          ++ [Tesla.Middleware.FormUrlencoded]
          ++ [{Tesla.Middleware.Headers, [{"accept", "application/json"}]}]
          ++ [Tesla.Middleware.DecodeJson]
          ++ (opts[:tesla_middlewares] || [])
        }

      {:error, _} ->
        {:error, :token_endpoint_authenticator_not_found}
    end
  end

  defp server_metadata(opts) do
    Oauth2MetadataUpdater.get_metadata(
      opts[:issuer],
      opts[:oauth2_metadata_updater_opts] || []
    )
    |> case do
      {:ok, issuer_metadata} ->
        Map.merge(issuer_metadata, opts[:server_metadata] || %{})

      {:error, _} ->
        opts[:server_metadata] || %{}
    end
  end

  defp is_https(introspection_endpoint) do
    case URI.parse(introspection_endpoint) do
      %URI{scheme: "https"} ->
        :ok

      _ ->
        {:error, :invalid_scheme_for_introspection_endpoint}
    end
  end

  defp tesla_adapter(), do: Application.get_env(:tesla, :adapter, Tesla.Adapter.Hackney)
end
