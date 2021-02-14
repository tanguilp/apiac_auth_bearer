defmodule APIacAuthBearer.Validator.JWT do
  @moduledoc """
  An implementation of [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-07).

  This validator accepts the following options:
  - `:issuer` **[Mandatory]**: an OAuth2 issuer whose metadata and keys will be resolved
  automatically
  - `:client_config`: a `(APIacAuthBearer.Validator.opts() -> %{required(String.t()) => any()})`
  function that returns the RS (*resource server*) configuration in case encryption is used. The
  following fields are to be set:
    - `"at_encrypted_response_alg"` [**mandatory**]]: the algorithm used to decrypt
    bearer token
    - `"jwks"` or `"jwks_uri"`: RS' symmetric or asymmetric keys used to decrypt the token

          %{
            "at_encrypted_response_alg" => "ECDH-ES",
            "jwks" => %{
              "keys" => [
                %{
                  "crv" => "P-256",
                  "d" => "cNX22qgnyRI_3Ue6-2HRENiomTR6XzDK-VWtF9KJd5I",
                  "kty" => "EC",
                  "x" => "Kg0BnGxocTYC6X2kSdzEM61G-h-l70d-Xq97ZMq7RWY",
                  "y" => "htuiRWbDtzeZyAvezbWE31oEZiorhQiCa-792CWmPdY"
                }
              ]
            }
          }

  - `:oauth2_metadata_updater_opts`: options that will be passed to
  `Oauth2MetadataUpdater`
  - `:server_metadata`: server metadata that takes precedence over those automatically
  retrieve from the server (requested from the issuer). Useful when the OP does
  not support OAuth2 metadata or OpenID Connect discovery, or to override one or more
  parameters

  Note that the `"at_encrypted_response_alg"` parameter is **not** registered at the IANA. This
  is because an OAuth2 RS is not specified as an OAuth2 client. This can be a special case of
  an OAuth2 client, and is by certain AS implementations, but it's not specified as such. This
  library uses the terms `:client_config` and `"at_encrypted_response_alg"` to make it easier
  to use with backends that do indeed treat RSes as a special type of OAuth2 client.

  The `APIacAuthBearer` `:resource_indicator` is also **mandatory** for this validator per the
  specification.
  """

  @behaviour APIacAuthBearer.Validator

  @all_enc_enc [
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
    "A128GCM",
    "A192GCM",
    "A256GCM"
  ]

  @impl true
  def validate_opts(opts) do
    cond do
      not is_binary(opts[:issuer]) ->
        {:error, "missing or invalid mandatory option `:issuer` for #{__MODULE__}"}

      not is_binary(opts[:resource_indicator]) ->
        {:error, "missing or invalid mandatory option `:resource_indicator` for #{__MODULE__}"}

      true ->
        :ok
    end
  end

  @impl true
  def validate_bearer(bearer, opts) do
    with :ok <- verify_typ(bearer),
         {:ok, jws} <- maybe_decrypt(bearer, opts),
         {:ok, payload_str} <- verify_signature(jws, opts),
         {:ok, payload} <- Jason.decode(payload_str),
         :ok <- verify_issuer(payload, opts),
         # audience is verified in the main module
         :ok <- verify_expiration(payload) do
      {:ok, payload}
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, :invalid_jwt_inner_json_content}

      {:error, _} = error ->
        error

      _ ->
        {:error, :invalid_client_configuration}
    end
  end

  defp verify_typ(bearer) do
    cond do
      JOSEUtils.is_jws?(bearer) ->
        case JOSEUtils.JWS.peek_header(bearer) do
          {:ok, %{"typ" => type}} when type in ["at+jwt", "application/at+jwt"] ->
            :ok

          _ ->
            {:error, :invalid_jws_typ_header_parameter}
        end

      JOSEUtils.is_jwe?(bearer) ->
        case JOSEUtils.JWE.peek_header(bearer) do
          {:ok, %{"typ" => type}} when type in ["at+jwt", "application/at+jwt"] ->
            :ok

          _ ->
            {:error, :invalid_jwe_typ_header_parameter}
        end

      true ->
        {:error, :invalid_jwt_bearer}
    end
  end

  defp maybe_decrypt(bearer, opts) do
    cond do
      opts[:client_config] && JOSEUtils.is_jwe?(bearer) ->
        do_decrypt(bearer, opts)

      JOSEUtils.is_jwe?(bearer) ->
        {:error, :no_client_config_for_encrypted_token}

      true ->
        {:ok, bearer}
    end
  end

  defp do_decrypt(jwe, opts) do
    client_config = %{"at_encrypted_response_alg" => enc_alg} = opts[:client_config].(opts)

    with {:ok, jwks} <- client_jwks(client_config) do
      case JOSEUtils.JWE.decrypt(jwe, jwks, [enc_alg], @all_enc_enc) do
        {:ok, {jws, _}} ->
          {:ok, jws}

        :error ->
          {:error, :jwe_decryption_failure}
      end
    end
  end

  defp verify_signature(jws, opts) do
    with {:ok, jwks} <- server_jwks(opts),
         {:ok, %{"alg" => sig_alg}} <- JOSEUtils.JWS.peek_header(jws),
         true <- sig_alg != "none",
         {:ok, {payload_str, _}} <- JOSEUtils.JWS.verify(jws, jwks, [sig_alg]) do
      {:ok, payload_str}
    else
      false ->
        {:error, :illegal_use_of_sig_alg_none}

      :error ->
        {:error, :jws_signature_verification_failure}

      {:error, %_{}} ->
        {:error, :invalid_jws_header}

      {:error, _} = error ->
        error
    end
  end

  defp verify_issuer(%{"iss" => iss}, opts),
    do: if iss == opts[:issuer], do: :ok, else: {:error, :invalid_issuer}

  defp verify_expiration(%{"exp" => exp}),
    do: if exp >= System.system_time(:second), do: :ok, else: {:error, :expired_jwt_bearer}

  defp client_jwks(client_config) do
    case client_config do
      %{"jwks" => %{"keys" => jwks}} when is_list(jwks) ->
        {:ok, jwks}

      %{"jwks_uri" => jwks_uri} ->
        JWKSURIUpdater.get_keys(jwks_uri)

      _ ->
        {:error, :client_has_no_jwks_configured}
    end
  end

  defp server_jwks(opts) do
    server_metadata = opts[:server_metadata] || %{}
    issuer = opts[:issuer]

    case server_metadata do
      %{"jwks" => %{"keys" => jwks}} when is_list(jwks) ->
        {:ok, jwks}

      %{"jwks_uri" => jwks_uri} ->
        JWKSURIUpdater.get_keys(jwks_uri)

      _ ->
        Oauth2MetadataUpdater.get_metadata(
          issuer,
          opts[:oauth2_metadata_updater_opts] || []
        )
        |> case do
          {:ok, %{"jwks" => %{"keys" => jwks}}} when is_list(jwks) ->
            {:ok, jwks}

          {:ok, %{"jwks_uri" => jwks_uri}} ->
            JWKSURIUpdater.get_keys(jwks_uri)

          {:ok, _} ->
            {:error, :server_has_no_jwks_configured}

          {:error, _} = error ->
            error
        end
    end
  end
end
