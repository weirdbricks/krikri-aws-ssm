require "json"
require "uri"
require "../errors"
require "./config"
require "./types"

module KrikriAwsSsm
  class CredentialChain
    # ECS/EC2-container credential endpoint
    # (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `_FULL_URI`), with the
    # botocore rule that a full URI must be https or a loopback address.
    #
    # Provenance: env var names, the loopback guard and response fields pinned
    # from `botocore.credentials.ContainerProvider` / `botocore.utils`
    # (Apache-2.0).
    class Ecs
      RELATIVE_ENV        = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
      FULL_ENV            = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
      AUTH_TOKEN_ENV      = "AWS_CONTAINER_AUTHORIZATION_TOKEN"
      AUTH_TOKEN_FILE_ENV = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"

      def initialize(@config : Config)
      end

      # True when the container env vars select an endpoint. A configured
      # but broken endpoint must fail loudly rather than fall through to
      # instance-role credentials (botocore's ContainerProvider does the same).
      def configured? : Bool
        !endpoint_url.nil?
      end

      def credentials : Credentials?
        endpoint = endpoint_url
        return unless endpoint
        headers = HTTP::Headers{"Host" => HTTPTransport.authority(endpoint)}
        if token = authorization_token
          headers["Authorization"] = token
        end
        path = endpoint.path.empty? ? "/" : endpoint.path
        request = HTTP::Request.new("GET", path, headers)
        response = HTTPTransport.perform(request, endpoint,
          @config.ecs_transport_or_default, @config.connect_timeout, @config.read_timeout)
        return unless response.success?
        parse_credentials(response.body)
      rescue IO::Error
        nil
      end

      private def endpoint_url : URI?
        env = @config.env
        if relative = env[RELATIVE_ENV]?
          base = @config.container_metadata_endpoint || Config::DEFAULT_CONTAINER_ENDPOINT
          suffix = relative.starts_with?('/') ? relative : "/#{relative}"
          URI.parse(base.rstrip('/') + suffix)
        elsif full = env[FULL_ENV]?
          HTTPTransport.parse_endpoint(full, @config.allow_insecure_endpoint,
            "ECS container", allow_loopback_http: true)
        end
      end

      private def authorization_token : String?
        env = @config.env
        return env[AUTH_TOKEN_ENV]?.presence if env[AUTH_TOKEN_ENV]?
        return unless path = env[AUTH_TOKEN_FILE_ENV]?
        File.read(path).strip.presence
      rescue IO::Error
        nil
      end

      private def parse_credentials(body : String) : Credentials?
        json = JSON.parse(body)
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
    end
  end
end
