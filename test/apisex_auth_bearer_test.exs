defmodule APISexAuthBearerTest do
  use ExUnit.Case, async: true
  doctest APISexAuthBearer
  use Plug.Test

  test "valid bearer, check APISex attributes are correctly set" do
    opts = APISexAuthBearer.init([
      bearer_validator: {APISexAuthBearer.Validator.Identity,
        [
          response: {:ok, %{"active" => true, "client_id" => "testclient", "sub" => "jean-paul" }}
        ]}
    ])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Bearer ynGTFjuTJMmLKQA")
      |> APISexAuthBearer.call(opts)

    refute conn.status in [401, 403]
    refute conn.halted
    assert APISex.authenticated?(conn) == true
    assert APISex.machine_to_machine?(conn) == false
    assert APISex.authenticator(conn) == APISexAuthBearer
    assert APISex.client(conn) == "testclient"
    assert APISex.subject(conn) == "jean-paul"
  end

  test "invalid bearer, check error response" do
    opts = APISexAuthBearer.init([
      realm: "realm9",
      bearer_validator: {APISexAuthBearer.Validator.Identity,
        [
          response: {:error, %{"active" => false}}
        ]}
    ])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Bearer ynGTFjuTJMmLKQA")
      |> APISexAuthBearer.call(opts)

    assert conn.status == 401
    assert conn.halted
    refute APISex.authenticated?(conn) == true
    assert APISex.client(conn) == nil
    assert APISex.subject(conn) == nil
    assert Plug.Conn.get_resp_header(conn, "www-authenticate") in [
      ["Bearer realm=\"realm9\", error=\"invalid_token\""],
      ["Bearer error=\"invalid_token\", realm=\"realm9\""]
    ]
  end

  test "a bearer in the body can be retreived and validated" do
    opts = APISexAuthBearer.init([
      bearer_validator: {APISexAuthBearer.Validator.Identity,
        [
          response: {:ok, %{"active" => true}},
        ]},
      bearer_extract_methods: [:header, :query, :body],
      forward_bearer: true
    ])

    conn =
      conn(:get, "/")
      |> put_body_params(%{"param1" => "value1", "access_token" => "9z41XZ1ep2MF0d6eMX7X"})
      |> APISexAuthBearer.call(opts)

    refute conn.status in [401, 403]
    refute conn.halted
    assert APISex.authenticated?(conn) == true
    assert APISex.machine_to_machine?(conn) == false
    assert APISex.authenticator(conn) == APISexAuthBearer
    assert APISex.metadata(conn)["bearer"] == "9z41XZ1ep2MF0d6eMX7X"
  end

  test "a bearer in the query can be retreived and validated" do
    opts = APISexAuthBearer.init([
      bearer_validator: {APISexAuthBearer.Validator.Identity,
        [
          response: {:ok, %{"active" => true}},
        ]},
      bearer_extract_methods: [:body, :header, :query],
      forward_bearer: true
    ])

    conn =
      conn(:get, "/")
      |> put_query_params(%{"param1" => "value1", "access_token" => "9z41XZ1ep2MF0d6eMX7X"})
      |> APISexAuthBearer.call(opts)

    refute conn.status in [401, 403]
    refute conn.halted
    assert APISex.authenticated?(conn) == true
    assert APISex.machine_to_machine?(conn) == false
    assert APISex.authenticator(conn) == APISexAuthBearer
    assert APISex.metadata(conn)["bearer"] == "9z41XZ1ep2MF0d6eMX7X"
  end

  test "a bearer with sufficient scopes" do
    opts = APISexAuthBearer.init([
      realm: "Pays des merveilles",
      bearer_validator: {APISexAuthBearer.Validator.Identity,
        [

          response: {:ok, %{"active" => true,
            "scope" => ["scope1", "scope6", "scope3", "scope10", "scope5",
                        "scope2", "scope7", "scope8", "scope9", "scope4"]}},
        ]},
      required_scopes: ["scope1", "scope2", "scope3", "scope4", "scope5", "scope6"]
    ])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Bearer ynGTFjuTJMmLKQA")
      |> APISexAuthBearer.call(opts)

    refute conn.status in [401, 403]
    refute conn.halted
    assert APISex.authenticated?(conn) == true
    assert APISex.authenticator(conn) == APISexAuthBearer
  end

  test "a bearer with insufficient scopes" do
    opts = APISexAuthBearer.init([
      realm: "Pays des merveilles",
      bearer_validator: {APISexAuthBearer.Validator.Identity,
        [

          response: {:ok, %{"active" => true,
            "scope" => ["scope1", "scope3", "scope5"]}},
        ]},
      required_scopes: ["scope1", "scope2", "scope3", "scope4", "scope5", "scope6"]
    ])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Bearer ynGTFjuTJMmLKQA")
      |> APISexAuthBearer.call(opts)

    assert conn.status == 403
    assert conn.halted
    refute APISex.authenticated?(conn) == true
    assert Plug.Conn.get_resp_header(conn, "www-authenticate") in [
      ["Bearer realm=\"Pays des merveilles\", error=\"insufficient_scope\", scope=\"scope1 scope2 scope3 scope4 scope5 scope6\""],
      ["Bearer realm=\"Pays des merveilles\", scope=\"scope1 scope2 scope3 scope4 scope5 scope6\", error=\"insufficient_scope\""],
      ["Bearer error=\"insufficient_scope\", realm=\"Pays des merveilles\", scope=\"scope1 scope2 scope3 scope4 scope5 scope6\""],
      ["Bearer error=\"insufficient_scope\", scope=\"scope1 scope2 scope3 scope4 scope5 scope6\", realm=\"Pays des merveilles\""],
      ["Bearer scope=\"scope1 scope2 scope3 scope4 scope5 scope6\", realm=\"Pays des merveilles\", error=\"insufficient_scope\""],
      ["Bearer scope=\"scope1 scope2 scope3 scope4 scope5 scope6\", error=\"insufficient_scope\", realm=\"Pays des merveilles\""]
    ]
  end

  test "metadata are correctly forwarded" do
    opts = APISexAuthBearer.init([
      bearer_validator: {APISexAuthBearer.Validator.Identity,
        [
          response: {:ok, %{"active" => true, "username" => "Hugo", "non_standard_attr" => "something", "not_forwarded" => "never ever"}}
        ]},
      forward_metadata: ["username", "non_standard_attr"]
    ])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Bearer ynGTFjuTJMmLKQA")
      |> APISexAuthBearer.call(opts)

    refute conn.status in [401, 403]
    refute conn.halted
    assert APISex.authenticated?(conn) == true
    assert APISex.authenticator(conn) == APISexAuthBearer
    assert APISex.metadata(conn)["username"] == "Hugo"
    assert APISex.metadata(conn)["non_standard_attr"] == "something"
    refute APISex.metadata(conn)["not_forwarded"] == "never ever"
  end

  test "cache interface works with another cache" do
    opts = APISexAuthBearer.init([
      bearer_validator: {APISexAuthBearer.Validator.Identity,
        [
          response: {:ok, %{"active" => true, "client_id" => "testclient", "sub" => "jean-paul" }}
        ]},
      cache: {APISexAuthBearer.Cache.ETSMock, []}
    ])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Bearer ynGTFjuTJMmLKQA")
      |> APISexAuthBearer.call(opts)

    refute conn.status in [401, 403]
    refute conn.halted
    assert APISex.authenticated?(conn) == true
    assert APISex.machine_to_machine?(conn) == false
    assert APISex.authenticator(conn) == APISexAuthBearer
    assert APISex.client(conn) == "testclient"
    assert APISex.subject(conn) == "jean-paul"
  end

  defp put_body_params(conn, body_params) do
    %{conn | body_params: body_params}
  end

  defp put_query_params(conn, query_params) do
    %{conn | query_params: query_params}
  end
end
