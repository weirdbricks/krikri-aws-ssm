require "uri"
require "./errors"

module KrikriAwsSsm
  # StreamUrl handling: signing decisions, the Host header that must be signed
  # verbatim, and the production host allow-list.
  module StreamUrl
    extend self

    # `IsPresignedURL` in `src/communicator/websocketchannel.go`.
    PRESIGNED_PARAMS = {
      "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
      "X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Security-Token",
    }

    AWS_SUFFIXES = {".amazonaws.com", ".amazonaws.com.cn"}

    def parse(raw : String) : URI
      uri = URI.parse(raw)
      raise ProtocolError.new("StreamUrl has no scheme") unless uri.scheme
      host = uri.host
      # `wss:///path` parses with an empty (not nil) host.
      raise ProtocolError.new("StreamUrl has no host") if host.nil? || host.empty?
      raise ProtocolError.new("StreamUrl must not carry userinfo") if uri.user
      uri
    rescue ex : URI::Error
      raise ProtocolError.new("StreamUrl is not a valid URI: #{ex.message}")
    end

    def presigned?(uri : URI | String) : Bool
      query = uri.is_a?(URI) ? uri.query : parsed_query(uri)
      return false unless query
      # Query names are percent-decoded before matching, as the reference
      # does; a malformed escape is left as written rather than raising a
      # raw URI error out of a boolean predicate.
      names = query.split('&').map do |pair|
        name = pair.split('=', 2).first
        URI.decode_www_form(name)
      rescue URI::Error
        name
      end
      names.any? { |name| PRESIGNED_PARAMS.includes?(name) }
    end

    private def parsed_query(url : String) : String?
      URI.parse(url).query
    rescue URI::Error
      nil
    end

    # Refuse non-TLS URLs unless an explicit test endpoint is configured, and
    # refuse production hosts outside the AWS suffixes.
    def validate!(uri : URI, allow_insecure : Bool) : Nil
      case uri.scheme
      when "wss"
      when "ws"
        raise ProtocolError.new("plain ws:// StreamUrl #{redact(uri)} is not allowed") unless allow_insecure
      else
        raise ProtocolError.new("unsupported StreamUrl scheme #{uri.scheme.inspect}")
      end
      return if allow_insecure
      host = uri.host
      raise ProtocolError.new("StreamUrl has no host") unless host
      unless AWS_SUFFIXES.any? { |suffix| host.ends_with?(suffix) }
        raise ProtocolError.new("StreamUrl host #{host.inspect} is not an AWS Session Manager endpoint")
      end
    end

    # Exact Host header value to send and sign: the host alone on the default
    # port, otherwise host:port.
    def authority(uri : URI) : String
      host = uri.host
      raise ProtocolError.new("StreamUrl has no host") unless host
      port = uri.port
      default_port = uri.scheme == "https" || uri.scheme == "wss" ? 443 : 80
      port && port != default_port ? "#{host}:#{port}" : host
    end

    def request_target(uri : URI) : String
      target = uri.request_target
      target.empty? ? "/" : target
    end

    # Never log the query: a presigned URL carries the signature and token.
    def redact(uri : URI) : String
      "#{uri.scheme}://#{uri.host}#{uri.port ? ":#{uri.port}" : ""}#{uri.path.empty? ? "/" : uri.path}"
    end
  end
end
