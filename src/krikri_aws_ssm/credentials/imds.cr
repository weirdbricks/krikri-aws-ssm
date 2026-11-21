require "json"
require "uri"
require "../errors"
require "./config"
require "./types"

module KrikriAwsSsm
  class CredentialChain
    # EC2 instance metadata credentials (IMDSv2). A PUT fetches a session
    # token, then every role/credential GET carries it. Short timeouts and no
    # proxy keep a non-EC2 machine from stalling the chain.
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
        token = session_token(endpoint)
        return unless token

        role = role_name(endpoint, token)
        return unless role

        read_credentials(endpoint, token, role)
      rescue IO::Error
        nil
      end

      private def session_token(endpoint : URI) : String?
        headers = HTTP::Headers{
          "Host"           => HTTPTransport.authority(endpoint),
          TOKEN_TTL_HEADER => TOKEN_TTL,
        }
        response = perform("PUT", endpoint, path(endpoint, TOKEN_PATH), headers)
        return unless response.success?
        token = response.body.strip
        token.empty? ? nil : token
      end

      private def role_name(endpoint : URI, token : String) : String?
        response = perform("GET", endpoint, path(endpoint, ROLE_PATH), token_headers(endpoint, token))
        return unless response.success?
        response.body.each_line do |line|
          name = line.strip
          return name unless name.empty?
        end
        nil
      end

      private def read_credentials(endpoint : URI, token : String, role : String) : Credentials?
        response = perform("GET", endpoint, path(endpoint, "#{ROLE_PATH}#{role}"),
          token_headers(endpoint, token))
        return unless response.success?

        json = JSON.parse(response.body)
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

      private def token_headers(endpoint : URI, token : String) : HTTP::Headers
        HTTP::Headers{
          "Host"       => HTTPTransport.authority(endpoint),
          TOKEN_HEADER => token,
        }
      end

      private def perform(method : String, endpoint : URI, resource : String,
                          headers : HTTP::Headers) : HTTP::Client::Response
        request = HTTP::Request.new(method, resource, headers)
        HTTPTransport.perform(request, endpoint, @config.imds_transport_or_default,
          @config.connect_timeout, @config.read_timeout)
      end

      private def path(endpoint : URI, suffix : String) : String
        HTTPTransport.join_path(endpoint, suffix)
      end
    end
  end
end
