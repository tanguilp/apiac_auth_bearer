defmodule APISexAuthBearer.Validator.Introspect do
  @behaviour APISexAuthBearer.Validator
  

  def validate(token, %{introspect_endpoint: introspect_endpoint} = validator_opts) do
    http_client = Tesla.build_client({Tesla.Middleware.FormUrlencoded, nil} ++
                                     validator_opts[:middlewares])

    body = [{"token", token}, {"token_type_hint", "access_token"}]

    case Tesla.post(http_client, introspect_endpoint, body, headers: %{"accept" => "application/json"}) do
      {:ok, %Tesla.Env{status: 200, headers: headers, body: body}} ->
        if {"content-type", "application/json"} in headers do
          parse_response(body)
        else
          {:error, "Invalid content-type returned from introspection endpoint"}
        end
      {:ok, _} ->
        {:error, "Invalid HTTP response code returned from introspection endpoint"}
      {:error, _} ->
        {:error, "Request to introspection endpoint failed"}
    end
  end

  defp parse_response(body) do
    case Poison.decode(body) do
      {:ok, %{"active": "true"} = response} -> {:ok, response}
      {:ok, _} -> {:error, "Invalid token"}
      {:error, _} -> {:error, "Error decoding json returned by introspection endpoint"}
    end
  end
end
