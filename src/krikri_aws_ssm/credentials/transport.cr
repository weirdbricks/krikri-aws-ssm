require "http/client"
require "uri"
require "../errors"

module KrikriAwsSsm
  class CredentialChain
    # Injected transport seam: takes the request and the endpoint URI it is
    # destined for, and returns a fully-read response.
    alias Transport = Proc(HTTP::Request, URI, HTTP::Client::Response)

    # Shared endpoint validation and HTTP plumbing for the credential
    # providers. Tests inject a `Transport` or point an endpoint at a local
    # HTTP server; production uses `HTTP::Client`.
    module HTTPTransport
      extend self

      def perform(request : HTTP::Request, endpoint : URI, transport : Transport?,
                  connect_timeout : Time::Span, read_timeout : Time::Span) : HTTP::Client::Response
        return transport.call(request, endpoint) if transport

        client = HTTP::Client.new(endpoint)
        client.connect_timeout = connect_timeout
        client.read_timeout = read_timeout
        begin
          response = client.exec(request)
          body = response.body
          HTTP::Client::Response.new(response.status_code, body, response.headers,
            response.status_message)
        ensure
          client.close
        end
      end

      def authority(uri : URI) : String
        host = uri.host
        raise ConfigurationError.new("#{uri} has no host") unless host
        port = uri.port
        default_port = uri.scheme == "https" ? 443 : 80
        port && port != default_port ? "#{host}:#{port}" : host
      end

      # Validate an endpoint override. Plain HTTP is refused unless the caller
      # explicitly allowed it, or *allow_loopback_http* is set and the host is
      # a container metadata host (the metadata services and local test
      # servers).
      def parse_endpoint(url : String, allow_insecure : Bool, service : String,
                         allow_loopback_http : Bool = false) : URI
        uri = URI.parse(url)
        scheme = uri.scheme
        host = uri.host
        raise ConfigurationError.new("#{service} endpoint #{url} has no host") unless host
        unless scheme == "https" ||
               (allow_insecure && scheme == "http") ||
               (allow_loopback_http && scheme == "http" && allowed_metadata_http?(host))
          raise ConfigurationError.new(
            "#{service} endpoint #{url} must use https " \
            "(http is only allowed for a container metadata address or with " \
            "allow_insecure_endpoint)")
        end
        uri
      end

      # Hosts botocore accepts over plain HTTP for container credentials: its
      # loopback set plus the ECS and EKS Pod Identity agent addresses. The
      # EKS Pod Identity default endpoint is
      # `http://169.254.170.23/v1/credentials`, so refusing it made that
      # provider unusable here.
      ALLOWED_METADATA_HTTP_HOSTS = Set{
        "169.254.170.2", "169.254.170.23", "fd00:ec2::23", "[fd00:ec2::23]",
      }

      def allowed_metadata_http?(host : String) : Bool
        loopback?(host) || ALLOWED_METADATA_HTTP_HOSTS.includes?(host)
      end

      def loopback?(host : String) : Bool
        host == "localhost" || host == "127.0.0.1" || host == "::1" ||
          host == "[::1]" || host.starts_with?("127.")
      end

      def join_path(endpoint : URI, suffix : String) : String
        base = endpoint.path.rstrip('/')
        path = base.empty? ? suffix : base + suffix
        path.starts_with?('/') ? path : "/#{path}"
      end
    end
  end
end
