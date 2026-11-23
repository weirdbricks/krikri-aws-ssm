require "json"
require "uri"
require "../errors"
require "./config"
require "./types"

module KrikriAwsSsm
  class CredentialChain
    # EC2 instance metadata credentials. A PUT fetches an IMDSv2 session
    # token, then every role/credential GET carries it. When the token PUT is
    # rejected (an `HttpTokens=optional` instance), the GETs are retried
    # without the token unless `AWS_EC2_METADATA_V1_DISABLED` forbids it.
    # Short timeouts and no proxy keep a non-EC2 machine from stalling the
    # chain.
    #
    # Provenance: paths, the `X-aws-ec2-metadata-token-ttl-seconds` header and
    # response field names pinned from `botocore.utils.InstanceMetadataFetcher`
    # (Apache-2.0).
    class Imds
      TOKEN_PATH       = "/latest/api/token"
      ROLE_PATH        = "/latest/meta-data/iam/security-credentials/"
      TOKEN_TTL_HEADER = "X-aws-ec2-metadata-token-ttl-seconds"
      TOKEN_HEADER     = "X-aws-ec2-metadata-token"
      TOKEN_TTL        = "21600"

      def initialize(@config : Config)
      end

      def credentials : Credentials?
        endpoint = URI.parse(@config.imds_endpoint)
        # One keep-alive client for the token + two GETs when the real HTTP
        # client is used; the injected transport seam gets one call per
        # request as before.
        client = metadata_client(endpoint)
        begin
          token = session_token(endpoint, client)
          return if token.nil? && @config.imds_v1_disabled?

          role = role_name(endpoint, token, client)
          return unless role

          read_credentials(endpoint, token, role, client)
        ensure
          client.try(&.close)
        end
      rescue IO::Error
        nil
      end

      private def metadata_client(endpoint : URI) : HTTP::Client?
        return if @config.imds_transport_or_default
        client = HTTP::Client.new(endpoint)
        client.connect_timeout = @config.connect_timeout
        client.read_timeout = @config.read_timeout
        client
      end

      private def session_token(endpoint : URI, client : HTTP::Client?) : String?
        headers = HTTP::Headers{
          "Host"           => HTTPTransport.authority(endpoint),
          TOKEN_TTL_HEADER => TOKEN_TTL,
        }
        response = perform("PUT", endpoint, path(endpoint, TOKEN_PATH), headers, client)
        return unless response.success?
        token = response.body.strip
        token.empty? ? nil : token
      end

      private def role_name(endpoint : URI, token : String?, client : HTTP::Client?) : String?
        response = perform("GET", endpoint, path(endpoint, ROLE_PATH),
          token_headers(endpoint, token), client)
        return unless response.success?
        response.body.each_line do |line|
          name = line.strip
          return name unless name.empty?
        end
        nil
      end

      private def read_credentials(endpoint : URI, token : String?, role : String,
                                   client : HTTP::Client?) : Credentials?
        response = perform("GET", endpoint, path(endpoint, "#{ROLE_PATH}#{role}"),
          token_headers(endpoint, token), client)
        return unless response.success?

        json = JSON.parse(response.body).as_h?
        return unless json
        access_key = json["AccessKeyId"]?.try(&.as_s?)
        secret_key = json["SecretAccessKey"]?.try(&.as_s?)
        session_token = json["Token"]?.try(&.as_s?)
        expiration = json["Expiration"]?.try(&.as_s?)
        unless access_key && secret_key && session_token && expiration
          return
        end
        Credentials.new(access_key, secret_key, session_token, Time.parse_rfc3339(expiration))
      rescue JSON::ParseException | Time::Format::Error
        nil
      end

      private def token_headers(endpoint : URI, token : String?) : HTTP::Headers
        headers = HTTP::Headers{"Host" => HTTPTransport.authority(endpoint)}
        headers[TOKEN_HEADER] = token if token
        headers
      end

      private def perform(method : String, endpoint : URI, resource : String,
                          headers : HTTP::Headers,
                          client : HTTP::Client?) : HTTP::Client::Response
        attempts = @config.imds_attempts
        attempt = 0
        loop do
          attempt += 1
          begin
            request = HTTP::Request.new(method, resource, headers)
            return exec(request, endpoint, client)
          rescue ex : IO::Error
            raise ex if attempt >= attempts
          end
        end
      end

      private def exec(request : HTTP::Request, endpoint : URI,
                       client : HTTP::Client?) : HTTP::Client::Response
        if client
          response = client.exec(request)
          return HTTP::Client::Response.new(response.status_code, response.body,
            response.headers, response.status_message)
        end
        HTTPTransport.perform(request, endpoint, @config.imds_transport_or_default,
          @config.connect_timeout, @config.read_timeout)
      end

      private def path(endpoint : URI, suffix : String) : String
        HTTPTransport.join_path(endpoint, suffix)
      end
    end
  end
end
