require "digest/sha256"
require "http/request"
require "krikri-aws-signer"
require "../credentials"

module KrikriAwsSsm::Testing
  # Verifies an incoming SigV4-signed request with known test credentials.
  # This is the cheapest detector for the Host/port and signed-header class of
  # bugs: the fake gateway rejects any request whose signature does not match
  # the exact set of headers it claims to have signed.
  module SigV4
    record Result,
      access_key : String,
      scope : String,
      signed_headers : Array(String),
      signature : String

    class VerificationError < Exception
    end

    PRESIGNED_PARAMS = {
      "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
      "X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Security-Token",
    }

    extend self

    def presigned?(uri : URI | String) : Bool
      query = URI.parse(uri.to_s).query || ""
      params = query.split('&').map(&.split('=', 2).first)
      params.any? { |name| PRESIGNED_PARAMS.includes?(name) }
    end

    def verify(request : HTTP::Request, credentials : Credentials,
               region : String, service : String) : Result
      authorization = request.headers["Authorization"]?
      raise VerificationError.new("missing Authorization header") unless authorization
      fields = parse_authorization(authorization)
      access_key, date, scope_region, scope_service, _terminator = fields[:credential].split('/')

      unless access_key == credentials.access_key
        raise VerificationError.new("signed with unexpected access key #{access_key}")
      end
      unless scope_region == region && scope_service == service
        raise VerificationError.new("unexpected scope #{scope_region}/#{scope_service}")
      end

      signed_names = fields[:signed_headers].split(';')
      signed = signed_headers_for(request, signed_names)
      amz_date = signed["X-Amz-Date"]? || raise VerificationError.new("X-Amz-Date is not signed")
      payload_hash = request.headers["X-Amz-Content-Sha256"]? ||
                     Digest::SHA256.hexdigest(request_body(request))
      path, _, query = request.resource.partition('?')
      path = "/" if path.empty?

      canonical_headers = KrikriAwsSigner::Canonical.headers(signed)
      expected_signed = canonical_headers[1]
      unless expected_signed == fields[:signed_headers]
        raise VerificationError.new(
          "SignedHeaders #{fields[:signed_headers]} does not match canonical " \
          "headers #{expected_signed}")
      end

      canonical_request = KrikriAwsSigner::Canonical.request(
        request.method, path, query, canonical_headers, payload_hash)
      string_to_sign = KrikriAwsSigner::Signature.string_to_sign(
        amz_date, KrikriAwsSigner::Signature.credential_scope(date, region, service),
        canonical_request)
      expected = KrikriAwsSigner::Signature.signature(
        credentials.secret_key, date, region, service, string_to_sign)

      unless expected == fields[:signature]
        raise VerificationError.new(
          "signature mismatch for #{request.method} #{path}: expected #{expected}, " \
          "got #{fields[:signature]}")
      end

      Result.new(access_key, "#{date}/#{scope_region}/#{scope_service}/aws4_request",
        signed_names, fields[:signature])
    end

    private def parse_authorization(value : String) : NamedTuple(
      credential: String, signed_headers: String, signature: String)
      unless value.starts_with?(KrikriAwsSigner::ALGORITHM)
        raise VerificationError.new("unexpected Authorization scheme")
      end
      credential = signed_headers = signature = nil
      value.split(',').each do |part|
        part = part.strip
        key, _, val = part.partition('=')
        case key
        when "AWS4-HMAC-SHA256 Credential"
          credential = val
        when "SignedHeaders"
          signed_headers = val
        when "Signature"
          signature = val
        end
      end
      unless credential && signed_headers && signature
        raise VerificationError.new("Authorization is missing Credential, SignedHeaders or Signature")
      end
      {credential: credential, signed_headers: signed_headers, signature: signature}
    end

    private def signed_headers_for(request : HTTP::Request, names : Array(String)) : HTTP::Headers
      headers = HTTP::Headers.new
      names.each do |name|
        values = request.headers.get?(name)
        raise VerificationError.new("SignedHeaders names #{name} but the request does not carry it") unless values
        values.each { |value| headers.add(name, value) }
      end
      headers
    end

    private def request_body(request : HTTP::Request) : String
      case body = request.body
      when String then body
      when Bytes  then String.new(body)
      else
        body.try(&.gets_to_end) || ""
      end
    end
  end
end
