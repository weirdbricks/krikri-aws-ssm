require "./spec_helper"

module KmsSpecData
  CREDS           = KrikriAwsSsm::Credentials.new("AKIDEXAMPLE", "secretEXAMPLEKEY")
  PLAINTEXT       = Bytes.new(64) { |index| (index + 1).to_u8 }
  CIPHERTEXT_BLOB = Bytes[1_u8, 2_u8, 3_u8, 9_u8]
end

describe KrikriAwsSsm::Kms do
  it "calls GenerateDataKey with the pinned request shape and decodes the key" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, JSON.build do |json|
        json.object do
          json.field "Plaintext", Base64.strict_encode(KmsSpecData::PLAINTEXT)
          json.field "CiphertextBlob", Base64.strict_encode(KmsSpecData::CIPHERTEXT_BLOB)
          json.field "KeyId", "key-1"
        end
      end)
    end
    begin
      kms = KrikriAwsSsm::Kms.new(KmsSpecData::CREDS, "us-east-1",
        endpoint_url: server.url, allow_insecure_endpoint: true)
      data_key = kms.generate_data_key("key-1", "s-123", "i-456")

      request = receive_with_timeout(server.requests)
      assert_equal "TrentService.GenerateDataKey", request.headers["X-Amz-Target"]
      assert_equal "application/x-amz-json-1.1", request.headers["Content-Type"]
      body = JSON.parse(request.body || "")
      assert_equal "key-1", body["KeyId"].as_s
      assert_equal 64, body["NumberOfBytes"].as_i
      assert_equal "s-123", body["EncryptionContext"]["aws:ssm:SessionId"].as_s
      assert_equal "i-456", body["EncryptionContext"]["aws:ssm:TargetId"].as_s

      assert_equal KmsSpecData::PLAINTEXT, data_key.plaintext
      assert_equal KmsSpecData::CIPHERTEXT_BLOB, data_key.ciphertext_blob
    ensure
      server.close
    end
  end

  it "surfaces a KMS denial as a typed API error with the service message" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(400,
        %({"__type":"AccessDeniedException","message":"not allowed to generate data keys"}))
    end
    begin
      kms = KrikriAwsSsm::Kms.new(KmsSpecData::CREDS, "us-east-1",
        endpoint_url: server.url, allow_insecure_endpoint: true)
      error = assert_raises(KrikriAwsSsm::AccessDenied) do
        kms.generate_data_key("key-1", "s-123", "i-456")
      end
      assert_includes error.message.to_s, "not allowed to generate data keys"
    ensure
      server.close
    end
  end

  it "rejects a data key that is not 64 bytes" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, JSON.build do |json|
        json.object do
          json.field "Plaintext", Base64.strict_encode(Bytes[1_u8, 2_u8])
          json.field "CiphertextBlob", Base64.strict_encode(Bytes[3_u8])
        end
      end)
    end
    begin
      kms = KrikriAwsSsm::Kms.new(KmsSpecData::CREDS, "us-east-1",
        endpoint_url: server.url, allow_insecure_endpoint: true)
      assert_raises(KrikriAwsSsm::ProtocolError) do
        kms.generate_data_key("key-1", "s-123", "i-456")
      end
    ensure
      server.close
    end
  end
end
