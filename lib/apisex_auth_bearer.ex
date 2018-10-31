defmodule APISexAuthBearer do
  @behaviour Plug
  @behaviour APISex.Authenticator

  alias OAuth2Utils.Scope, as: Scope
  alias OAuth2Utils.Scope.Set, as: ScopeSet

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

  The `bearer_extract_methods` plug option allows to specify where to seek the bearer.

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
  |--------------------------------|:----------:|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
  | APISexAuthBearer.Cache.NoCache | Built-in   | No caching, for testing purpose or when using a custom validator that doesn't require caching                                                               |
  | APISexAuthBearer.Cache.ETSMock | Built-in   | Local cache in ETS table, for testing purpose, development environment, etc. Does not have a token expiration clean-up code: the cache will grow endlessly  |
  | APISexAuthBearerCacheCachex  | [github](https://github.com/tanguilp/apisex_auth_bearer_cache_cachex) | Production ready cache, for a single instance or a small cluster of nodes                                                                                   |
  | APISexAuthBearerCacheRiak    | Work in progress | Production ready cache, for larger clusters of nodes                                                                                                        |

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
  - `bearer_extract_methods`: a list of methods that will be tried to extract the bearer token, among
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
  validator's response to set in the APISex metadata, or the `:all` atom to forward all
  of the response's data.
  For example: `["username", "aud"]`. Defaults to `[]`
  - `resource_server_name`: the name of the resource server as a String, to be
  checked against the `aud` attribute returned by the validator. This is an optional
  security mecanism. See the security consideration sections. Defaults to `nil`, i.e.
  no check of this parameter
  - `cache`: a `{cache_module, cache_options}` tuple where `cache_module` is
  a module implementing the `APISexAuthBearer.Cache` behaviour and `cache_options`
  module-specific options that will be passed to the cache when called.
  The cached entry expiration ttl can be set thanks to the `:ttl` option. It is set to
  200 seconds by default, but is shortened when the bearer's lifetime is less than 200
  seconds (as indicated by its expiration timestamp of the `"exp"` member of bearer
  metadata returned by the validator)
  Defaults to `{APISexAuthBearer.Cache.NoCache, [ttl: 200]}`

  ## Error responses

  This plug, conforming to RFC6750, responds with the following status and parameters
  in case of authentication failure:

  | Error                                   | HTTP status | Included WWW-Authenticate parameters |
  |-----------------------------------------|:-----------:|--------------------------------------|
  | No bearer token found                   | 401         | - realm                              |
  | Invalid bearer                          | 401         | - realm<br>- error                   |
  | Bearer doesn't have the required scopes | 403         | - realm<br>- error<br>- scope        |

  ## Example

  ```elixir
  Plug APISexAuthBearer, bearer_validator: {APISexAuthBearer,[
                                                              issuer: "https://example.com/auth"
                                                              tesla_middleware:[
                                                              {Tesla.Middleware.BasicAuth, [username: "client_id_123", password: "WN2P3Ci+meSLtVipc1EZhbFm2oZyMgWIx/ygQhngFbo"]}
                                                              ]
                                                              ]},
                          bearer_extract_methods: [:header, :body],
                          required_scopes: ["article:write", "comments:moderate"],
                          forward_bearer: true,
                          resource_server_name: "https://example.com/api/data"
                          cache: {APISexAuthBearerCacheCachex, []}

  ```

  ## Security considerations

  ### HTTPS
  As the bearer token is sent in an HTTP header, use of HTTPS is **mandatory**
  (but however not verfified by this Plug).

  ### Bearer methods
  As stated by RFC6750, section 2:

  >  This section defines three methods of sending bearer access tokens in
  >  resource requests to resource servers.  Clients **MUST NOT** use more
  >  than one method to transmit the token in each request.

  This plug does not check whether several methods are used or not. It will
  only deal with the first bearer (valid or not) found following the order
  of the `bearer_extract_methods`.

  ### Form-Encoded Body Parameter
  RFC6750, section 2.2, demands that the following conditions are met for
  form-encoded body bearer access token:

  > o  The HTTP request entity-header includes the "Content-Type" header
  >    field set to "application/x-www-form-urlencoded".
  >
  > o  The entity-body follows the encoding requirements of the
  >    "application/x-www-form-urlencoded" content-type as defined by
  >    HTML 4.01 [W3C.REC-html401-19991224].
  >
  > o  The HTTP request entity-body is single-part.
  >
  > o  The content to be encoded in the entity-body MUST consist entirely
  >    of ASCII [USASCII] characters.
  >
  > o  The HTTP request method is one for which the request-body has
  >    defined semantics.  In particular, this means that the "GET"
  >    method MUST NOT be used.

  This plug, however:
  - doesn't verify that the HTTP request entity-body is single-part
  - the content is entirely US-ASCCI (the plug parser checks that it
  is [utf8](https://github.com/elixir-plug/plug/blob/master/lib/plug/parsers/urlencoded.ex#L31)

  ### Audience
  RFC6750, section 5.2, states that:

  > To deal with token redirect, it is important for the authorization
  > server to include the identity of the intended recipients (the
  > audience), typically a single resource server (or a list of resource
  > servers), in the token.  Restricting the use of the token to a
  > specific scope is also RECOMMENDED.

  Consider implementing it using the `resource_server_name` parameter.

  ### URI Query Parameter
  According to RFC6750, section 2.3,:

  > Clients using the URI Query Parameter method SHOULD also send a
  > Cache-Control header containing the "no-store" option.  Server
  > success (2XX status) responses to these requests SHOULD contain a
  > Cache-Control header with the "private" option.

  This plug does set the `cache-control` to `private` when such a method
  is used. Beware, however, of not overwriting it later unless you
  know what you're doing.

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

    required_scopes = ScopeSet.new(Keyword.get(opts, :required_scopes, []))

    Enum.each(
      required_scopes,
      fn scope -> if not Scope.oauth2_scope?(scope) do
        raise "Invalid scope in list required scopes"
        end
      end
    )

    if opts[:bearer_validator] == nil, do: raise "Missing mandatory option `bearer_validator`"

    {cache_module, cache_opts} = Keyword.get(opts, :cache, {APISexAuthBearer.Cache.NoCache, []})
    cache_opts = Keyword.put_new(cache_opts, :ttl, 200)

    %{
      realm: realm,
      bearer_validator: Keyword.get(opts, :bearer_validator, nil),
      bearer_extract_methods: Keyword.get(opts, :bearer_extract_methods, [:header]),
      set_authn_error_response: Keyword.get(opts, :set_authn_error_response, true),
      halt_on_authn_failure: Keyword.get(opts, :halt_on_authn_failure, true),
      required_scopes: required_scopes,
      forward_bearer: Keyword.get(opts, :forward_bearer, false),
      forward_metadata: Keyword.get(opts, :forward_metadata, []),
      cache: {cache_module, cache_module.init_opts(cache_opts)}
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
      opts[:bearer_extract_methods],
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

        if APISex.rfc7235_token68?(bearer) do
          {:ok, conn, bearer}
        else
          {:error, :invalid_bearer_format}
        end

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
          if APISex.rfc7235_token68?(bearer) do
            {:ok, conn, bearer}
          else
            {:error, :invalid_bearer_format}
          end

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
          if APISex.rfc7235_token68?(bearer) do
            #RFC6750 - section 2.3:
            #  Clients using the URI Query Parameter method SHOULD also send a
            #  Cache-Control header containing the "no-store" option.  Server
            #  success (2XX status) responses to these requests SHOULD contain a
            #  Cache-Control header with the "private" option.

            conn = Plug.Conn.put_resp_header(conn, "cache-control", "private")

            {:ok, conn, bearer}
          else
            {:error, :invalid_bearer_format}
          end
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
            try do
              # let's lower the ttl when the "exp" member of the bearer's data
              # says the bearer expires before the current cache ttl
              exp = String.to_integer(bearer_data["exp"])

              if exp - :os.system_time(:second) < cache_opts[:ttl] do
                cache.put(bearer, bearer_data, Map.put(cache_opts, :ttl, :os.system_time(:second)))
              else
                cache.put(bearer, bearer_data, cache_opts)
              end
            rescue
              _ ->
                cache.put(bearer, bearer_data, cache_opts)
            end

            validate_bearer_data(conn, bearer, bearer_data, opts)

          {:error, error} ->
            {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__,
              reason: error}}
        end
    end
  end

  defp validate_bearer_data(conn, bearer, bearer_data, opts) do
    metadata = if opts[:forward_bearer], do: %{"bearer" => bearer}, else: %{}

    with :ok <- verify_scopes(conn, bearer_data, opts),
         :ok <- verify_audience(conn, bearer_data, opts)
    do
      metadata =
        case opts[:forward_metadata] do
          :all ->
            Map.merge(bearer_data, metadata)

          attrs when is_list(attrs) ->
            Enum.reduce(
              attrs,
              metadata,
              fn attr, metadata ->
                case bearer_data[attr] do
                  nil ->
                    metadata

                  val ->
                    # put_new/3 prevents from overwriting "bearer"
                    Map.put_new(metadata, attr, val)
                end
              end
            )
        end

      conn =
        conn
        |> Plug.Conn.put_private(:apisex_authenticator, __MODULE__)
        |> Plug.Conn.put_private(:apisex_client, bearer_data["client_id"])
        |> Plug.Conn.put_private(:apisex_subject, bearer_data["sub"])
        |> Plug.Conn.put_private(:apisex_metadata, metadata)
        |> Plug.Conn.put_private(:apisex_realm, opts[:realm])

      {:ok, conn}
    end
  end

  defp verify_scopes(conn, bearer_data, opts) do
    if ScopeSet.subset?(opts[:required_scopes], ScopeSet.new(bearer_data["scope"])) do
      :ok
    else
      {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :insufficient_scope}}
    end
  end

  defp verify_audience(conn, bearer_data, opts) do
    if opts[:resource_server_name] != nil do
      case bearer_data["aud"] do
        aud when is_binary(aud) ->
          if opts[:resource_server_name] == aud do
            :ok
          else
            {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :invalid_audience}}
          end

        aud_list when is_list(aud_list) ->
          if opts[:resource_server_name] in aud_list do
            :ok
          else
            {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :invalid_audience}}
          end

        _ ->
          {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :invalid_audience}}
      end
    else
      :ok
    end
  end

  @doc """
  `APISex.Authenticator` error response callback
  """

  @impl true
  def set_error_response(conn, error, opts) do
    {resp_status, error_map} =
      case error do
        %APISex.Authenticator.Unauthorized{reason: :no_bearer_found} ->
          {:unauthorized, %{"realm" => opts[:realm]}}

        %APISex.Authenticator.Unauthorized{reason: :insufficient_scope} ->
          {:forbidden, %{"error" => "insufficient_scope",
                         "scope" => ScopeSet.to_scope_param(opts[:required_scopes]),
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
