defmodule APIacAuthBearerTest.Validator.JWT do
  use ExUnit.Case, async: true

  alias APIacAuthBearer.Validator.JWT

  @client_keys [
    JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_map() |> elem(1),
    JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1),
    JOSE.JWK.generate_key({:oct, 32}) |> JOSE.JWK.to_map() |> elem(1)
  ]

  @server_metadata %{
    "jwks" => %{
      "keys" => [
        JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_map() |> elem(1),
        JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1),
        JOSE.JWK.generate_key({:okp, :Ed25519}) |> JOSE.JWK.to_map() |> elem(1),
      ]
      # it wouldn't usually be added to server metadata (since it's a private key) but
      # we add it here for convenience
      ++ JOSEUtils.JWKS.filter(@client_keys, kty: "oct")
    }
  }

  @default_jwt_header %{"typ" => "at+jwt"}

  @valid_jwt_payload %{
    "iss" => "some issuer",
    "exp" => System.system_time(:second) + 30,
    "aud" => "some resource indicator",
    "sub" => "some subject",
    "iat" => System.system_time(:second),
    "jti" => :crypto.strong_rand_bytes(20) |> Base.encode64(),
    "some other field" => 42
  }

  @valid_options [
    issuer: "some issuer",
    resource_indicator: "some resource indicator",
    server_metadata: @server_metadata
  ]

  describe ".validate_opts" do
    test "valid opts" do
      assert JWT.validate_opts(@valid_options) == :ok
    end

    test "missing issuer" do
      assert {:error, _} = JWT.validate_opts(@valid_options |> Keyword.delete(:issuer))
    end

    test "missing resource_indicator" do
      assert {:error, _} = JWT.validate_opts(@valid_options |> Keyword.delete(:resource_indicator))
    end
  end

  describe ".validate_bearer/2" do
    test "valid signed AT with RSA signature is accepted" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256")

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "valid signed AT with EC signature is accepted" do
      bearer = @valid_jwt_payload |> gen_jwt("ES256")

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "valid signed AT with EdDSA signature is accepted" do
      bearer = @valid_jwt_payload |> gen_jwt("EdDSA")

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "valid signed AT with HS256 MACing is accepted" do
      bearer = @valid_jwt_payload |> gen_jwt("HS256")

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "unsigned AT is rejected" do
      bearer = @valid_jwt_payload |> gen_jwt("none")

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with invalid typ is rejected" do
      bearer = @valid_jwt_payload |> gen_jwt("ES256", %{"typ" => "invalid+jwt"})

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with nill typ is rejected" do
      bearer = @valid_jwt_payload |> gen_jwt("ES256", %{"typ" => nil})

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with invalid issuer is rejected" do
      bearer = @valid_jwt_payload |> Map.put("iss", "invalid") |> gen_jwt("ES256")

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with expired JWT is rejected" do
      bearer = @valid_jwt_payload |> Map.put("exp", now() - 1) |> gen_jwt("ES256")

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with invalid signature is rejected" do
      bearer = @valid_jwt_payload |> gen_jwt("ES256") |> Kernel.<>("z")

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "encrypted AT with missing client config is rejected" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A128GCM")

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "valid encrypted then signed AT with RSA encryption is accepted" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A128GCM")
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_rsa_oaep/1)

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, opts)
    end

    test "valid encrypted then signed AT with ECDH-ES encryption is accepted" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "ECDH-ES", "A128GCM")
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_ecdh_es/1)

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, opts)
    end

    test "valid encrypted then signed AT with dir symmetric encryption is accepted" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "dir", "A256GCM")
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_dir/1)

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, opts)
    end

    test "encrypted then signed AT with invalid at_encrypted_response_alg value is rejected" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A256GCM")
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_dir/1)

      assert {:error, _} = JWT.validate_bearer(bearer, opts)
    end

    test "encrypted then signed AT with invalid type is rejected" do
      bearer =
        @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A128GCM", %{"typ" => "x("})
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_rsa_oaep/1)

      assert {:error, _} = JWT.validate_bearer(bearer, opts)
    end

    test "encrypted then signed AT with nil type is rejected" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A128GCM", %{"typ" => nil})
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_rsa_oaep/1)

      assert {:error, _} = JWT.validate_bearer(bearer, opts)
    end

    test "encrypted then signed AT with invalid encryption is rejected" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A128GCM")
      [header, encrypted_key, iv, ciphertext, tag] = String.split(bearer, ".")
      bearer = Enum.join([header, encrypted_key, iv, ciphertext <> "invalid", tag])
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_rsa_oaep/1)

      assert {:error, _} = JWT.validate_bearer(bearer, opts)
    end
  end

  defp gen_jwt(payload, sig_alg, additional_headers \\ %{})

  defp gen_jwt(payload, "none", additional_headers) do
    payload
    |> Jason.encode!()
    |> JOSEUtils.JWS.sign!(%{}, "none", Map.merge(@default_jwt_header, additional_headers))
  end

  defp gen_jwt(payload, sig_alg, additional_headers) do
    [signing_key | _] =
      @server_metadata["jwks"]["keys"]
      |> JOSEUtils.JWKS.signature_keys()
      |> JOSEUtils.JWKS.filter(alg: sig_alg)

    payload
    |> Jason.encode!()
    |> JOSEUtils.JWS.sign!(signing_key, sig_alg, Map.merge(@default_jwt_header, additional_headers))
  end

  defp gen_jwt(
    payload, sig_alg, enc_alg, enc_enc, additional_headers \\ %{}
  ) do
    jws = gen_jwt(payload, sig_alg, %{})

    [encryption_key | _] =
      @client_keys
      |> JOSEUtils.JWKS.encryption_keys()
      |> JOSEUtils.JWKS.filter(alg: enc_alg)

    jwk =
      if String.starts_with?(enc_alg, "ECDH-ES") do
        [server_key | _] =
          @server_metadata["jwks"]["keys"]
          |> JOSEUtils.JWKS.signature_keys()
          |> JOSEUtils.JWKS.filter(kty: "EC")

        {encryption_key, server_key}
      else
        encryption_key
      end

    JOSEUtils.JWE.encrypt!(jws, jwk, enc_alg, enc_enc, Map.merge(@default_jwt_header, additional_headers))
  end

  def client_config_enc_rsa_oaep(_opts),
    do: %{"at_encrypted_response_alg" => "RSA-OAEP", "jwks" => %{"keys" => @client_keys}}

  def client_config_enc_ecdh_es(_opts),
    do: %{"at_encrypted_response_alg" => "ECDH-ES", "jwks" => %{"keys" => @client_keys}}

  def client_config_enc_dir(_opts),
    do: %{"at_encrypted_response_alg" => "dir", "jwks" => %{"keys" => @client_keys}}

  defp now(), do: System.system_time(:second)
end
