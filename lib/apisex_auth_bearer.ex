defmodule APISexAuthBearer do
  @behaviour Plug
  @behaviour APISex.Authenticator

  @default_realm_name "default_realm"

  @type bearer :: String.t

  @doc """
  Plug initialization callback
  """

  @impl true
  def init(opts) do
    realm = Keyword.get(opts, :realm, @default_realm_name)

    if not is_binary(realm), do: raise "Invalid realm, must be a string"

    if not APISex.rfc7230_quotedstring?("\"#{realm}\""), do: raise "Invalid realm string (do not conform with RFC7230 quoted string)"

    required_scopes = OAuth2Utils.Scope.Set.new(Keyword.get(opts, :required_scopes, []))

    Enum.each(
      required_scopes,
      fn scope -> if not OAuth2Utils.Scope.oauth2_scope?(scope) do
        raise "Invalid scope in list required scopes"
        end
      end
    )

    %{
      realm: realm,
      bearer_validator: Keyword.get(opts, :bearer_validator, nil),
      bearer_methods: Keyword.get(opts, :bearer_methods, [:header]),
      set_authn_error_response: Keyword.get(opts, :set_authn_error_response, true),
      halt_on_authn_failure: Keyword.get(opts, :halt_on_authn_failure, true),
      required_scopes: required_scopes,
      forward_bearer: Keyword.get(opts, :forward_bearer, false),
      forward_metadata: Keyword.get(opts, :forward_metadata, []),
      cache: Keyword.get(opts, :cache, {APISex.Cache.NoCache, []})
    }
  end

  @doc """
  Plug pipeline callback
  """

  @impl true
  @spec call(Plug.Conn, Plug.opts) :: Plug.Conn
  def call(conn, opts) do
    with {:ok, conn, bearer} <- extract_credentials(conn, opts),
         {:ok, conn} <- validate_credentials(conn, bearer, opts) do
      conn
    else
      {:error, conn, %APISex.Authenticator.Unauthorized{} = error} ->
        conn =
          if opts[:set_authn_error_response] do
            set_error_response(conn, error, opts)
          else
            conn
          end

        if opts[:halt_on_authn_failure] do
          conn
          |> Plug.Conn.send_resp()
          |> Plug.Conn.halt()
        else
          conn
        end
    end
  end

  @doc """
  `APISex.Authenticator` credential extractor callback
  """

  @impl true
  def extract_credentials(conn, opts) do
    case Enum.reduce_while(
      opts[:supported_methods],
      conn,
      fn method, conn ->
        case extract_bearer(conn, method) do
          {:ok, _conn, _bearer} = ret ->
            {:halt, ret}

          {:error, conn} ->
            {:cont, conn}
        end
      end
    ) do
      %Plug.Conn{} = conn ->
        {:error, conn, %APISex.Authenticator.Unauthorized{
          authenticator: __MODULE__,
          reason: :no_bearer_found}}

      {:ok, conn, bearer} ->
        {:ok, conn, bearer}
    end
  end

  defp extract_bearer(conn, :header) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      # Only one header value should be returned
      # (https://stackoverflow.com/questions/29282578/multiple-http-authorization-headers)
      ["Bearer " <> untrimmed_bearer] ->
        # rfc7235 syntax allows multiple spaces before the base64 token
        bearer = String.trim_leading(untrimmed_bearer, " ")

        if not APISex.rfc7235_token68?(bearer), do: raise "Invalid bearer token in authorization header"

        {:ok, conn, bearer}

      _ ->
        {:error, conn}
    end
  end

  defp extract_bearer(conn, :body) do
    try do
      plug_parser_opts = Plug.Parsers.init(parsers: [:urlencoded],
                                           pass: ["application/x-www-form-urlencoded"])

      conn = Plug.Parsers.call(conn, plug_parser_opts)

      case conn.body_params["access_token"] do
        nil ->
          {:error, conn}

        bearer ->
          if not APISex.rfc7235_token68?(bearer), do: raise "Invalid bearer token in authorization header"

          {:ok, conn, bearer}
      end
    rescue
      UnsupportedMediaTypeError ->
        {:error, conn}
    end
  end

  defp extract_bearer(conn, :query) do
      conn = Plug.Conn.fetch_query_params(conn)

      case conn.query_params["access_token"] do
        nil ->
          {:error, conn}

        bearer ->
          {:ok, conn, bearer}
      end
  end

  @impl true
  def validate_credentials(conn, bearer, opts) do
    {cache, cache_opts} = opts[:cache]

    case cache.get(bearer, cache_opts) do
      bearer_data when not is_nil(bearer_data) ->
        validate_bearer_data(conn, bearer, bearer_data, opts)

      # bearer is not in cache
      nil ->
        {bearer_validator, bearer_validator_opts} = opts[:bearer_validator]

        case bearer_validator.validate(bearer, bearer_validator_opts) do
          {:ok, bearer_data} ->
            cache.put(bearer, bearer_data, cache_opts)

            validate_bearer_data(conn, bearer, bearer_data, opts)

          {:error, error} ->
            {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__,
              reason: error}}
        end
    end
  end

  defp validate_bearer_data(conn, bearer, bearer_data, opts) do
    metadata = if opts[:forward_bearer], do: %{"bearer" => bearer}, else: %{}

    if OAuth2Utils.Scope.Set.subset?(opts[:required_scopes], OAuth2Utils.Scope.Set.new(bearer_data["scope"])) do
      metadata =
        Enum.reduce(
          opts[:forward_metadata],
          metadata,
          fn attr ->
            case bearer_data[attr] do
              nil ->
                metadata

              val ->
                # put_new/3 prevents from overwriting "bearer"
                Map.put_new(metadata, attr, val)
            end
          end
        )

      conn =
        conn
        |> Plug.Conn.put_private(:apisex_authenticator, __MODULE__)
        |> Plug.Conn.put_private(:apisex_client, bearer_data["client"])
        |> Plug.Conn.put_private(:apisex_metadata, metadata)
        |> Plug.Conn.put_private(:apisex_realm, opts[:realm])

      {:ok, conn}
    else
      {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :insufficient_scope}}
    end
  end

  @doc """
  `APISex.Authenticator` error response callback
  """

  @impl true
  def set_error_response(conn, error, opts) do
    {resp_status, error_map} =
      case error do
        %APISex.Authenticator.Unauthorized{reason: :insufficient_scope} ->
          {:forbidden, %{"error" => "invalid_token",
                         "realm" => opts[:realm]}}

        %APISex.Authenticator.Unauthorized{} ->
          {:unauthorized, %{"error" => "insufficient_scope",
                            "scope" => OAuth2Utils.Scope.Set.to_scope_param(opts[:required_scopes]),
                            "realm" => opts[:realm]}}
      end

    conn
    |> APISex.set_WWWauthenticate_challenge("Bearer", error_map)
    |> Plug.Conn.resp(resp_status, "")
  end
end
