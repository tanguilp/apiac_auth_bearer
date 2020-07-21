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
    client_config: &__MODULE__.client_config/0,
    issuer: "some issuer",
    resource_indicator: "some resource indicator",
    server_metadata: @server_metadata
  ]

  describe ".validate_opts" do
    test "valid opts" do
      assert JWT.validate_opts(@valid_options) == :ok
    end

    test "missing client config" do
      assert {:error, _} = JWT.validate_opts(@valid_options |> Keyword.delete(:client_config))
    end

    test "missing issuer" do
      assert {:error, _} = JWT.validate_opts(@valid_options |> Keyword.delete(:issuer))
    end

    test "missing resource_indicator" do
      assert {:error, _} = JWT.validate_opts(@valid_options |> Keyword.delete(:resource_indicator))
    end
  end

  describe ".validate_bearer/2" do
    test "valid signed AT with RSA signature" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256")

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "valid signed AT with EC signature" do
      bearer = @valid_jwt_payload |> gen_jwt("ES256")

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "valid signed AT with EdDSA signature" do
      bearer = @valid_jwt_payload |> gen_jwt("EdDSA")

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "valid signed AT with HS256 MACing" do
      bearer = @valid_jwt_payload |> gen_jwt("HS256")

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with invalid typ" do
      bearer = @valid_jwt_payload |> gen_jwt("ES256", %{"typ" => "invalid+jwt"})

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with missing typ" do
      bearer = @valid_jwt_payload |> gen_jwt("ES256", %{})

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with invalid issuer" do
      bearer = @valid_jwt_payload |> Map.put("iss", "invalid") |> gen_jwt("ES256")

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with expired JWT" do
      bearer = @valid_jwt_payload |> Map.put("exp", now() - 1) |> gen_jwt("ES256")

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "signed with invalid signature" do
      bearer = @valid_jwt_payload |> gen_jwt("ES256") |> Kernel.<>("z")

      assert {:error, _} = JWT.validate_bearer(bearer, @valid_options)
    end

    test "valid encrypted then signed AT with RSA encryption" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A128GCM")
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_rsa_oaep/0)

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, opts)
    end

    test "valid encrypted then signed AT with ECDH-ES encryption" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "ECDH-ES", "A128GCM")
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_ecdh_es/0)

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, opts)
    end

    test "valid encrypted then signed AT with dir symmetric encryption" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "dir", "A256GCM")
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_dir/0)

      assert {:ok, @valid_jwt_payload} = JWT.validate_bearer(bearer, opts)
    end

    test "encrypted then signed AT with invalid at_encrypted_response_alg value" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A256GCM")
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_dir/0)

      assert {:error, _} = JWT.validate_bearer(bearer, opts)
    end

    test "encrypted then signed AT with invalid type" do
      bearer =
        @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A128GCM", %{"typ" => "x("})
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_rsa_oaep/0)

      assert {:error, _} = JWT.validate_bearer(bearer, opts)
    end

    test "encrypted then signed AT with missing type" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A128GCM", %{})
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_rsa_oaep/0)

      assert {:error, _} = JWT.validate_bearer(bearer, opts)
    end

    test "encrypted then signed AT with invalid encryption" do
      bearer = @valid_jwt_payload |> gen_jwt("RS256", "RSA-OAEP", "A128GCM")
      [header, encrypted_key, iv, ciphertext, tag] = String.split(bearer, ".")
      bearer = Enum.join([header, encrypted_key, iv, ciphertext <> "invalid", tag])
      opts = Keyword.put(@valid_options, :client_config, &client_config_enc_rsa_oaep/0)

      assert {:error, _} = JWT.validate_bearer(bearer, opts)
    end
  end

  defp gen_jwt(payload, sig_alg, additional_headers \\ %{"typ" => "at+jwt"}) do
    [signing_key | _] =
      @server_metadata["jwks"]["keys"]
      |> JOSEUtils.JWKS.signature_keys()
      |> JOSEUtils.JWKS.filter(alg: sig_alg)

    payload
    |> Jason.encode!()
    |> JOSEUtils.JWS.sign!(signing_key, sig_alg, additional_headers)
  end

  defp gen_jwt(
    payload, sig_alg, enc_alg, enc_enc, additional_headers \\ %{"typ" => "at+jwt"}
  ) do
    jws = gen_jwt(payload, sig_alg, %{})

    [encryption_key | _] =
      client_config()["jwks"]["keys"]
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

    JOSEUtils.JWE.encrypt!(jws, jwk, enc_alg, enc_enc, additional_headers)
  end

  def client_config() do
    %{
      "jwks" => %{
        "keys" => @client_keys
      }
    }
  end

  def client_config_enc_rsa_oaep(),
    do: %{"at_encrypted_response_alg" => "RSA-OAEP"} |> Map.merge(client_config())

  def client_config_enc_ecdh_es(),
    do: %{"at_encrypted_response_alg" => "ECDH-ES"} |> Map.merge(client_config())

  def client_config_enc_dir(),
    do: %{"at_encrypted_response_alg" => "dir"} |> Map.merge(client_config())

  defp now(), do: System.system_time(:second)
end
