defmodule APISexAuthBearer do
  @behaviour Plug

  @default_realm_name nil
  @default_wwwauthenticate_attributes [:realm, :scope, :error]
  @default_authorized_methods [:authorization_header]

  @spec init(Plug.opts) :: Plug.opts
  def init(opts) do
    opts = %{
      verify: Keyword.get(opts, :verify, nil),
      cache: Keyword.get(opts, :cache, nil),
      allowed_methods: Keyword.get(opts, :authorized_methods, @default_authorized_methods),
      advertise_wwwauthenticate_header: Keyword.get(opts, :advertise_wwwauthenticate_header, true),
      wwwauthenticate_included_attributes: Keyword.get(opts, :wwwauthenticate_included_attributes, @default_wwwauthenticate_attributes),
      realm: Keyword.get(opts, :realm, @default_realm_name),
      halt_on_authentication_failure: Keyword.get(opts, :halt_on_authentication_failure, true),
      scope: Keyword.get(opts, :scope, nil)
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
      {conn, token} ->  verify_token(conn, opts, token)
      :error -> case call_parse_body_parameter(conn, opts) do
        {conn, token} -> verify_token(conn, opts, token)
        :error -> case  call_parse_uri_parameter(conn, opts) do
          {conn, token} -> verify_token(conn, opts, token)
          :error -> authenticate_failure(conn, opts, :invalid_request, "No Bearer token found in request")
        end
      end
    end
  end

  defp call_parse_authorization_header(conn, opts) do
    if Enum.member?(opts[:allowed_methods], :authorization_header) do
      case Plug.Conn.get_req_header(conn, "authorization") do
        ["Bearer " <> token] -> {conn, token}
        _ -> :error
      end
    else
      :error
    end
  end

  defp call_parse_body_parameter(conn, opts) do
    if Enum.member?(opts[:allowed_methods], :body_parameter) do
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
    if Enum.member?(opts[:allowed_methods], :uri_parameter) do
      conn = Plug.Conn.fetch_query_params(conn)

      case conn.query_params["access_token"] do
        nil -> :error
        token -> {conn, token}
      end
    else
      :error
    end
  end

  defp verify_token(conn, %{verify: {:introspection_endpoint, introspect_uri}} = opts, token) do
    conn
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
    |> Plug.Conn.put_status(:unauthorized)
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
    |> Plug.Conn.put_status(:unauthorized)
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

  defp authenticate_failure(conn, _opts, _error, _error_desc), do: conn

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
