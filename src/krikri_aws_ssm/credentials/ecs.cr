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
        request = HTTP::Request.new("GET", request_target(endpoint), headers)
        response = perform(request, endpoint)
        return unless response.success?
        parse_credentials(response.body)
      rescue IO::Error
        nil
      end

      # The full URL is sent, including its query string: botocore forwards
      # the endpoint as configured and some container endpoints need `?…`.
      private def request_target(endpoint : URI) : String
        path = endpoint.path.empty? ? "/" : endpoint.path
        endpoint.query ? "#{path}?#{endpoint.query}" : path
      end

      # Botocore gives the container endpoint 2 s and three attempts; the
      # 250 ms IMDS budget failed a remote https FULL_URI on a slow link.
      private def perform(request : HTTP::Request,
                          endpoint : URI) : HTTP::Client::Response
        attempts = @config.container_attempts
        attempt = 0
        loop do
          attempt += 1
          begin
            return HTTPTransport.perform(request, endpoint, @config.ecs_transport_or_default,
              @config.container_timeout, @config.container_timeout)
          rescue ex : IO::Error
            raise ex if attempt >= attempts
            sleep 1.second
          end
        end
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

      # Botocore checks the file first, then the env var, strips the token,
      # and rejects one containing a line break (a multi-line token would
      # split the header).
      private def authorization_token : String?
        env = @config.env
        token = if path = env[AUTH_TOKEN_FILE_ENV]?
                  begin
                    File.read(path)
                  rescue IO::Error
                    nil
                  end
                else
                  env[AUTH_TOKEN_ENV]?
                end
        return unless token
        token = token.strip
        return if token.empty?
        if token.includes?('\r') || token.includes?('\n')
          raise CredentialsError.new(
            "container authorization token is invalid: it contains a line break")
        end
        token
      end

      private def parse_credentials(body : String) : Credentials?
        json = JSON.parse(body).as_h?
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
    end
  end
end
