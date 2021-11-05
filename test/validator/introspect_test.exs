defmodule APIacAuthBearerTest.Validator.Introspect do
  use ExUnit.Case, async: true

  import Tesla.Mock

  alias APIacAuthBearer.Validator.Introspect

  @server_metadata %{
    "introspection_endpoint" => "https://example.com/introspect"
  }

  @opts [
    client_config: &__MODULE__.client_config/0,
    issuer: "https://example.com",
    server_metadata: @server_metadata,
    #tesla_middlewares: [Tesla.Middleware.Logger]
  ]

  @valid_bearer "fcdhesjxghksw"

  setup_all do
    mock_global(fn
      %{method: :get, url: "https://example.com/.well-known/openid-configuration"} ->
        # returning nothing because returning a valid metadata response is actually
        # hard. Relying on custom server metadata instead
        json(%{})

      %{
        method: :post,
        url: "https://example.com/introspect",
        headers: headers,
        body: body
      } ->
        Enum.find(headers, fn {k, v} ->
          String.downcase(k) == "authorization" and v == "Basic " <> authz_header_value()
        end)
        |> case do
          {_, _} ->
            case URI.decode_query(body) do
              %{"token" => @valid_bearer} ->
                json(%{"active" => true})

              _ ->
                json(%{"active" => false})
            end

          nil ->
            %Tesla.Env{status: 404}
        end
    end)

    :ok
  end

  describe ".validate_opts" do
    test "valid opts" do
      assert Introspect.validate_opts(@opts) == :ok
    end

    test "missing client config" do
      assert {:error, _} = Introspect.validate_opts(@opts |> Keyword.delete(:client_config))
    end

    test "missing issuer" do
      assert {:error, _} = Introspect.validate_opts(@opts |> Keyword.delete(:issuer))
    end
  end

  describe ".validate_bearer/2" do
    test "valid bearer token" do
      assert {:ok, %{"active" => true}} = Introspect.validate_bearer(@valid_bearer, @opts)
    end

    test "invalid bearer token" do
      assert {:error, _} = Introspect.validate_bearer("invalid", @opts)
    end

    test "invalid client credentials" do
      assert {:error, _} = Introspect.validate_bearer("invalid", Keyword.put(@opts, :client_config, &__MODULE__.client_config_invalid_secret/0))
    end
  end

  def client_config() do
    %{
      "client_id" => "some_client",
      "client_secret" => "some very secret secret"
    }
  end

  def client_config_invalid_secret(),
    do: Map.put(client_config(), "client_secret", "invalid")

  def authz_header_value() do
    client_config()["client_id"] <> ":" <> client_config()["client_secret"]
    |> Base.encode64()
  end
end
