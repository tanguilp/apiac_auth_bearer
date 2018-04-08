defmodule APISexAuthBearer do
  @behaviour Plug

  @default_wwwauthenticate_attributes [:realm, :scope, :error]
  @default_supported_methods [:authorization_header]

  @spec init(Plug.opts) :: Plug.opts
  def init(opts) do
    opts = %{
      token_validator: Keyword.get(opts, :token_validator, nil),
      cache: Keyword.get(opts, :cache, nil),
      supported_methods: Keyword.get(opts, :supported_methods, @default_supported_methods),
      advertise_wwwauthenticate_header: Keyword.get(opts, :advertise_wwwauthenticate_header, true),
      wwwauthenticate_included_attributes: Keyword.get(opts, :wwwauthenticate_included_attributes, @default_wwwauthenticate_attributes),
      realm: Keyword.get(opts, :realm, nil),
      halt_on_authentication_failure: Keyword.get(opts, :halt_on_authentication_failure, true),
      required_scopes: Keyword.get(opts, :scope, []),
      forward_token: Keyword.get(opts, :scope, false),
      client_attributes: Keyword.get(opts, :client_attributes, []),
      subject_attributes: Keyword.get(opts, :subject_attributes, [])
    }

    #TODO: check scopes' well-formedness

    # https://tools.ietf.org/html/rfc7235#section-2.2
    #
    #    For historical reasons, a sender MUST only generate the quoted-string
    #    syntax.  Recipients might have to support both token and
    #    quoted-string syntax for maximum interoperability with existing
    #    clients that have been accepting both notations for a long time.
    if Regex.match?(APISex.Utils.rfc7230_quotedstring_regex(), opts[:realm]) do
      opts
    else
      raise "Invalid realm string (do not conform with RFC7230 quoted string)"
    end
  end

  @spec call(Plug.Conn, Plug.opts) :: Plug.Conn
  def call(conn, %{} = opts) do
    case call_parse_authorization_header(conn, opts) do
      {conn, token} ->  validate_token(conn, opts, token)
      :error -> case call_parse_body_parameter(conn, opts) do
        {conn, token} -> validate_token(conn, opts, token)
        :error -> case  call_parse_uri_parameter(conn, opts) do
          {conn, token} -> validate_token(conn, opts, token)
          :error -> authenticate_failure(conn, opts, :invalid_request, "No Bearer token found in request")
        end
      end
    end
  end

  defp call_parse_authorization_header(conn, opts) do
    if Enum.member?(opts[:supported_methods], :authorization_header) do
      case Plug.Conn.get_req_header(conn, "authorization") do
        ["Bearer " <> token] -> {conn, token}
        _ -> :error
      end
    else
      :error
    end
  end

  defp call_parse_body_parameter(conn, opts) do
    if Enum.member?(opts[:supported_methods], :body_parameter) do
    #TODO : conform with spec on
    #
    #   o  The content to be encoded in the entity-body MUST consist entirely
    #         of ASCII [USASCII] characters.
    #
      if ["application/x-www-form-urlencoded"] = Plug.Conn.get_req_header(conn, "content-type")
        and conn.method in ["POST", "PUT", "PATCH"] do
        conn = Plug.Parsers.call(conn,
                                 Plug.Parsers.init(
                                                   parsers: [:urlencoded],
                                                   pass: ["application/x-www-form-urlencoded"]
                                                 ))
          case conn.body_params["access_token"] do
            nil -> :error
            token -> {conn, token}
          end
      else
        :error
      end
    else
      :error
    end
  end

  defp call_parse_uri_parameter(conn, opts) do
    if Enum.member?(opts[:supported_methods], :uri_parameter) do
      conn = Plug.Conn.fetch_query_params(conn)

      case conn.query_params["access_token"] do
        nil -> :error
        token -> {conn, token}
      end
    else
      :error
    end
  end

  defp validate_token(conn, opts, token) do
    {token_validator_fun, token_validator_opts} = opts[:token_validator]

    case token_validator_fun.(token, token_validator_opts) do
      {:ok, token_data} -> check_scopes(conn, opts, token, token_data)
      {:error, error_desc} -> authenticate_failure(conn, opts, :invalid_token, error_desc)
    end
  end

  defp check_scopes(conn, %{required_scopes: required_scopes} = opts, token, token_data) do
    case {required_scopes, token_data["scope"]} do
      {[], _} -> authenticate_success(conn, opts, token, token_data)
      {required_scopes, response_scopes} ->
        req_scope_set = MapSet.new(required_scopes)
        res_scope_set = MapSet.new(response_scopes)
        if MapSet.subset?(req_scope_set, res_scope_set) do
          authenticate_success(conn, opts, token, token_data)
        else
          authenticate_failure(conn, opts, :insufficient_scope, "Insufficient scope (in request: #{response_scopes}, required: #{required_scopes})")
        end
    end
  end

  defp authenticate_success(conn, opts, token, token_data) do
    result = %APISex.Authn{
      auth_scheme: __MODULE__,
      client: token_data["client_id"],
      client_attributes: Map.take(token_data, opts[:client_attributes]),
      subject: token_data["sub"],
      subject_attributes: Map.take(token_data, opts[:subject_attributes]),
      realm: opts[:realm],
      scopes: token_data["scope"]
    }

    Plug.Conn.put_private(conn, :apisex, result)
  end

  defp authenticate_failure(conn,
                            %{
                              advertise_wwwauthenticate_header: true,
                              halt_on_authentication_failure: true
                            } = opts,
                            error,
                            error_desc) do
    conn
    |> set_WWWAuthenticate_challenge(opts, error, error_desc)
    |> Plug.Conn.put_status(error_to_status(:error))
    |> Plug.Conn.halt
  end

  defp authenticate_failure(conn,
                            %{
                              advertise_wwwauthenticate_header: false,
                              halt_on_authentication_failure: true
                            },
                            _error,
                            _error_desc) do
    conn
    |> Plug.Conn.put_status(error_to_status(:error))
    |> Plug.Conn.halt
  end

  defp authenticate_failure(conn,
                            %{
                              advertise_wwwauthenticate_header: true,
                              halt_on_authentication_failure: false
                            } = opts,
                            error,
                            error_desc) do
    conn
    |> set_WWWAuthenticate_challenge(opts, error, error_desc)
  end

  defp authenticate_failure(conn, _opts, _error, _error_desc) do
    conn
  end

  defp error_to_status(:invalid_request), do: 400
  defp error_to_status(:invalid_token), do: 401
  defp error_to_status(:insufficient_scope), do: 403

  defp set_WWWAuthenticate_challenge(conn, opts, error, error_desc) do
    wwwauthenticate_val = wwwauthenticate_params(opts, error, error_desc)

    case Plug.Conn.get_resp_header(conn, "www-authenticate") do
      [] -> Plug.Conn.put_resp_header(conn, "www-authenticate", wwwauthenticate_val)
      [header_val|_] -> Plug.Conn.put_resp_header(conn, "www-authenticate", header_val <> ", " <> wwwauthenticate_val)
    end
  end

  defp wwwauthenticate_params(%{
                                wwwauthenticate_included_attributes: wwwauthenticate_included_attributes,
                                realm: realm,
                                scope: scope
                                },
                                error,
                                error_desc) do
  params = []

  params = if Enum.member?(wwwauthenticate_included_attributes, :realm) do
    params ++ ["realm=\"#{realm}\""]
  else
    params
  end

  params = if Enum.member?(wwwauthenticate_included_attributes, :scope) do
    params ++ ["scope=\"#{Enum.join(scope, " ")}\""]
  else
    params
  end

  params = if Enum.member?(wwwauthenticate_included_attributes, :error) do
    params ++ ["error=\"#{error}\""]
  else
    params
  end

  params = if Enum.member?(wwwauthenticate_included_attributes, :error_description) do
    params ++ ["error_description=\"#{error_desc}\""]
  else
    params
  end

  "Bearer " <> Enum.join(params, ", ")
  end
end
