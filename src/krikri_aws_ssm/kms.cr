require "base64"
require "json"
require "./aws_json"
require "./credentials"
require "./errors"

# KMS `GenerateDataKey` for session encryption.
#
# Pinned from `aws/session-manager-plugin` `src/encryption/kmsservice.go`
# (Apache-2.0; see NOTICE): a 64-byte data key, with the encryption context
# `{"aws:ssm:SessionId":..., "aws:ssm:TargetId":...}`. The response is plain
# JSON 1.1 signed over `kms` with target prefix `TrentService`.
module KrikriAwsSsm
  class Kms
    KEY_SIZE_BYTES = 64
    TARGET_PREFIX  = "TrentService"

    struct DataKey
      getter plaintext : Bytes
      getter ciphertext_blob : Bytes

      def initialize(@plaintext : Bytes, @ciphertext_blob : Bytes)
      end

      # The plaintext is key material; `inspect` (used by `p`/`pp` and
      # exception dumps) would otherwise print it as a byte list.
      def to_s(io : IO) : Nil
        io << "DataKey(plaintext=" << @plaintext.size << " bytes, ciphertext=" \
                                                          << @ciphertext_blob.size << " bytes)"
      end

      def inspect(io : IO) : Nil
        to_s(io)
      end
    end

    def initialize(@credentials : Credentials | Proc(Credentials), @region : String,
                   endpoint_url : String? = nil, allow_insecure_endpoint : Bool = false,
                   retries : Int32 = 3, connect_timeout : Time::Span = 60.seconds,
                   read_timeout : Time::Span = 60.seconds,
                   transport : AwsJson::Transport? = nil, aws_json : AwsJson? = nil)
      @aws_json = aws_json || AwsJson.new("kms", @region, @credentials,
        endpoint_url: endpoint_url, target_prefix: TARGET_PREFIX,
        retries: retries, allow_insecure_endpoint: allow_insecure_endpoint,
        connect_timeout: connect_timeout, read_timeout: read_timeout,
        transport: transport)
    end

    def generate_data_key(key_id : String, session_id : String, target_id : String) : DataKey
      response = @aws_json.call("GenerateDataKey", request_body(key_id, session_id, target_id))
      plaintext = decode_bytes(response, "Plaintext")
      ciphertext_blob = decode_bytes(response, "CiphertextBlob")
      unless plaintext.size == KEY_SIZE_BYTES
        raise ProtocolError.new(
          "KMS returned a #{plaintext.size}-byte data key, expected #{KEY_SIZE_BYTES}")
      end
      DataKey.new(plaintext, ciphertext_blob)
    end

    private def request_body(key_id : String, session_id : String, target_id : String) : String
      JSON.build do |json|
        json.object do
          json.field "KeyId", key_id
          json.field "NumberOfBytes", KEY_SIZE_BYTES
          json.field "EncryptionContext" do
            json.object do
              json.field "aws:ssm:SessionId", session_id
              json.field "aws:ssm:TargetId", target_id
            end
          end
        end
      end
    end

    private def decode_bytes(response : JSON::Any, field : String) : Bytes
      # `as_h?` first: a non-object body would make `#[]?` raise a bare
      # `Exception` instead of the typed `ProtocolError`.
      encoded = response.as_h?.try(&.[field]?).try(&.as_s?)
      raise ProtocolError.new("KMS response is missing #{field}") unless encoded
      Base64.decode(encoded)
    rescue ex : Base64::Error
      raise ProtocolError.new("KMS response #{field} is not valid base64: #{ex.message}")
    end
  end
end
