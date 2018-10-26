defmodule APISexAuthBearer do
  @behaviour Plug
  @behaviour APISex.Authenticator

  @moduledoc """
  An `APISex.Authenticator` plug for API authentication using the OAuth2 `Bearer` scheme

  The OAuth2 `Bearer` scheme is documented in
  [RFC6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
  and consists in sending an OAuth2 access token in the HTTP request. Any party
  in possession of that token can use it on the API, hence its name: 'Bearer'.

  ```http
  GET /api/accounts HTTP/1.1
  Host: example.com
  Authorization: Bearer NLdtYEY8Y4Q09kKBUnsYy9mExGQnBy
  Accept: */*
  ```

  That bearer token has been granted beforehand by an OAuth2 authorization server to the
  client making the API request (typically through one of the 4
  [RFC6749](https://tools.ietf.org/html/rfc6749) flows or one of the 3
  [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) flows).

  Note that according to the specification, the bearer can be sent:
  - in the `Authorization` HTTP header
  - in the request body (assuming the request has one)
  - as a query parameter

  The `bearer_methods` plug option allows to specify where to seek the bearer.

  Bearer tokens are usually:
  - opaque tokens, to be validated against the OAuth2 authorization server that has released it
  - self-contained signed JWT tokens, that can be verified locally by the API

  ## Validating the access token

  This plug provides with the `APISexAuthBearer.Validator.Introspect` bearer validator,
  that implements the only standard for bearer validation:
  [RFC7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)

  A validator must implement the `APISexAuthBearer.Validator` behaviour.

  ## Caching

  A bearer token may be used many times on an API in a short time-frame,
  which is why caching is important
  when using `APISexAuthBearer.Validator.Introspect` or a similar mechanism as a
  back pressure mechanism for the authorization server. This plug comes with 4 caching
  implementations:

  | Caching implementation         | Repository | Use-case                                                                                                                                                    |
  |--------------------------------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
  | APISexAuthBearer.Cache.NoCache | Built-in   | No caching, for testing purpose or when using a custom validator that doesn't require caching                                                               |
  | APISexAuthBearer.Cache.ETSMock | Built-in   | Local cache in ETS table, for testing purpose, development environment, etc. Does not have a token expiration clean-up code: the cache will grow endlessly  |
  | APISexAuthBearer-Cache-Cachex  | TBC        | Production ready cache, for a single instance or a small cluster of nodes                                                                                   |
  | APISexAuthBearer-Cache-Riak    | TBC        | Production ready cache, for larger clusters of nodes                                                                                                        |

  A cache implements the `APISexAuthBearer.Cache` behaviour.

  ## Validation flow sequence diagram

  ![SVG sequence diagram of the validation flow](success_flow.svg)

  ## Plug options

  - `realm`: a mandatory `String.t` that conforms to the HTTP quoted-string syntax, however without
  the surrounding quotes (which will be added automatically when needed). Defaults to `default_realm`
  - `bearer_validator`: a `{validator_module, validator_options}` tuple where `validator_module` is
  a module implementing the `APISexAuthBearer.Validator` behaviour and `validator_options`
  module-specific options that will be passed to the validator when called. No default
  value, mandatory parameter
  - `bearer_methods`: a list of methods that will be tried to extract the bearer token, among
  `:header`, `:body` and `:query`. Methods will be tried in the list order.
  Defaults to `[:header]`
  - `set_authn_error_response`: if `true`, sets the error response accordingly to the standard:
  changing the HTTP status code to `401` or `403` and setting the `WWW-Authenticate` value.
  If false, does not change them. Defaults to `true`
  - `halt_on_authn_failure`: if set to `true`, halts the connection and directly sends the
  response when authentication fails. When set to `false`, does nothing and therefore allows
  chaining several authenticators. Defaults to `true`
  - `required_scopes`: a list of scopes required to access this API. Defaults to `[]`.
  When the bearer's granted scope are
  not sufficient, an HTTP 403 response is sent with the `insufficient_scope` RFC6750 error
  - `forward_bearer`: if set to `true`, the bearer is saved in the `Plug.Conn` APISex
  metadata (under the "bearer" key) and can be later be retrieved using `APISex.metadata/1`.
  Defaults to `false`
  - `forward_metadata`: in addition to the bearer's `client` and `subject`, list of the
  validator's response to set in the APISex metadata.
  For example: `["username", "aud"]`. Defaults to `[]`
  - `cache`: a `{cache_module, cache_options}` tuple where `cache_module` is
  a module implementing the `APISexAuthBearer.Cache` behaviour and `cache_options`
  module-specific options that will be passed to the cache when called.
  The cache expiration ttl can be set thanks to the `:ttl` option (which is set to 200
  seconds by default).
  Defaults to `{APISex.Cache.NoCache, [ttl: 200]}`

  ## Example

  ```elixir
  Plug APISexAuthBearer, bearer_validator: {APISexAuthBearer,[
                                                              issuer: "https://example.com/auth"
                                                              tesla_middleware:[
                                                              {Tesla.Middleware.BasicAuth, [username: "client_id_123", password: "WN2P3Ci+meSLtVipc1EZhbFm2oZyMgWIx/ygQhngFbo"]}
                                                              ]
                                                              ]},
                          bearer_methods: [:query, :header],
                          required_scopes: ["article:write", "comments:moderate"],
                          forward_bearer: true,
                          cache: {APISexAuthBearer-Cache-Cachex, #TODO}

  ```

  ## Security considerations

  """

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

    if opts[:bearer_validator] == nil, do: raise "Missing mandatory option `bearer_validator`"

    {cache_module, cache_opts} = Keyword.get(opts, :cache, {APISex.Cache.NoCache, []})
    cache_opts = Keyword.put_new(cache_opts, :ttl, 200)

    %{
      realm: realm,
      bearer_validator: Keyword.get(opts, :bearer_validator, nil),
      bearer_methods: Keyword.get(opts, :bearer_methods, [:header]),
      set_authn_error_response: Keyword.get(opts, :set_authn_error_response, true),
      halt_on_authn_failure: Keyword.get(opts, :halt_on_authn_failure, true),
      required_scopes: required_scopes,
      forward_bearer: Keyword.get(opts, :forward_bearer, false),
      forward_metadata: Keyword.get(opts, :forward_metadata, []),
      cache: {cache_module, cache_module.init(cache_opts)}
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
          {:forbidden, %{"error" => "insufficient_scope",
                         "scope" => OAuth2Utils.Scope.Set.to_scope_param(opts[:required_scopes]),
                         "realm" => opts[:realm]}}

        %APISex.Authenticator.Unauthorized{} ->
          {:unauthorized, %{"error" => "invalid_token",
                         "realm" => opts[:realm]}}
      end

    conn
    |> APISex.set_WWWauthenticate_challenge("Bearer", error_map)
    |> Plug.Conn.resp(resp_status, "")
  end
end
