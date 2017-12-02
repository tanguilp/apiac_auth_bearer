defmodule APISexAuthBearer.Validator.Introspect do
  @behaviour APISexAuthBearer.Validator
  @introspect_request_headers [{"accept", "application/json"}, {"content-type", "application/x-www-form-urlencoded"}]
  @mandatory_resp_headers {"content-type", "application/json"}

  def validate(token, %{introspect_endpoint: introspect_endpoint} = validator_opts) do
    body = [{"token", token}, {"token_type_hint", "access_token"}]

    case HTTPoison.post(introspect_endpoint, body, @introspect_request_headers) do
      {:ok, %HTTPoison.Response{status_code: 200, headers: headers} = response} ->
        if @mandatory_resp_headers in headers do
          parse_response(response, token, validator_opts)
        else
          {:error, "Invalid content-type returned from introspection endpoint"}
        end
      {:ok, _} ->
        {:error, "Invalid HTTP response code returned from introspection endpoint"}
      {:error, _} ->
        {:error, "Request to introspection endpoint failed"}
    end
  end

  defp parse_response(%HTTPoison.Response{body: body}, token, validator_opts) do
    case Poison.decode(body) do
      {:ok, json} -> {:ok, json}
      {:error, _} -> {:error, "Error decoding json returned by introspection endpoint"}
    end
  end
end
