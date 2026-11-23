require "http/client"
require "json"
require "uri"
require "krikri-aws-signer"
require "./credentials"
require "./errors"

module KrikriAwsSsm
  # Signed AWS JSON 1.1 POST helper, shared by SSM and (from phase 5/6) KMS,
  # STS and SSO. SigV4 comes from `krikri-aws-signer`.
  class AwsJson
    JSON_CONTENT_TYPE = "application/x-amz-json-1.1"

    alias Transport = Proc(HTTP::Request, URI, HTTP::Client::Response)

    getter service : String
    getter region : String
    getter target_prefix : String

    @endpoint : URI

    def initialize(@service : String, @region : String,
                   @credentials : Credentials | Proc(Credentials),
                   endpoint_url : String? = nil, @target_prefix : String = "AmazonSSM",
                   @retries : Int32 = 3, @allow_insecure_endpoint : Bool = false,
                   @connect_timeout : Time::Span = 60.seconds,
                   @read_timeout : Time::Span = 60.seconds,
                   @transport : Transport? = nil)
      @endpoint = resolve_endpoint(endpoint_url)
    end

    # Call *action* and return the parsed JSON body (nil for an empty body).
    #
    # Only failures that happen before the request is on the wire are retried:
    # a connect/DNS failure or a TLS handshake error cannot have reached the
    # service, while a read timeout or reset may have (StartSession is not
    # idempotent, so replaying it would leak a session). Service throttling is
    # retried too, matching botocore's standard mode.
    def call(action : String, body : String = "") : JSON::Any
      attempt = 0
      loop do
        return handle_response(perform(action, body))
      rescue ex : Socket::ConnectError | Socket::Addrinfo::Error | OpenSSL::SSL::Error | Throttling
        attempt += 1
        raise ex if attempt > @retries
        sleep(retry_delay(attempt))
      end
    end

    private def perform(action : String, body : String) : HTTP::Client::Response
      request = build_request(action, body)
      if transport = @transport
        transport.call(request, @endpoint)
      else
        http_post(request)
      end
    end

    private def build_request(action : String, body : String) : HTTP::Request
      headers = HTTP::Headers{
        "Host"         => authority(@endpoint),
        "Content-Type" => JSON_CONTENT_TYPE,
        "X-Amz-Target" => "#{@target_prefix}.#{action}",
      }
      request = HTTP::Request.new("POST", request_path, headers, body)
      signer.sign(request)
      request
    end

    private def http_post(request : HTTP::Request) : HTTP::Client::Response
      client = HTTP::Client.new(@endpoint)
      client.connect_timeout = @connect_timeout
      client.read_timeout = @read_timeout
      begin
        response = client.exec(request)
        body = response.body
        HTTP::Client::Response.new(response.status_code, body, response.headers, response.status_message)
      ensure
        client.close
      end
    end

    private def handle_response(response : HTTP::Client::Response) : JSON::Any
      unless response.success?
        raise api_error(response)
      end
      body = response.body
      return JSON::Any.new(nil) if body.empty?
      JSON.parse(body)
    rescue ex : JSON::ParseException
      raise ProtocolError.new("#{@service} #{response.status_code} response was not JSON: #{ex.message}")
    end

    private def api_error(response : HTTP::Client::Response) : ApiError
      body = response.body
      parsed = begin
        body.empty? ? nil : JSON.parse(body)
      rescue JSON::ParseException
        nil
      end
      # `JSON::Any#[]?` raises a bare `Exception` on a non-object body (an
      # array, a scalar, an HTML page that parsed as JSON), which would mask
      # the real API error and status; `as_h?` keeps the typed surface.
      object = parsed.try(&.as_h?)
      code = object.try(&.["__type"]?).try(&.as_s?) ||
             response.headers["x-amzn-errortype"]? ||
             "UnknownError"
      message = object.try(&.["message"]?).try(&.as_s?) ||
                object.try(&.["Message"]?).try(&.as_s?) ||
                body
      ApiError.from_code(code, message, response.status_code, response.headers["x-amzn-RequestId"]?)
    end

    private def signer : KrikriAwsSigner::Signer
      # A long-lived client (resume/terminate/KMS) must sign with the current
      # credentials, not the snapshot taken when it was built.
      credentials = current_credentials
      KrikriAwsSigner::Signer.new(@service, @region, credentials.access_key,
        credentials.secret_key, credentials.session_token)
    end

    private def current_credentials : Credentials
      credentials = @credentials
      credentials.is_a?(Proc(Credentials)) ? credentials.call : credentials
    end

    private def resolve_endpoint(endpoint_url : String?) : URI
      uri = if endpoint_url
              parsed = begin
                URI.parse(endpoint_url)
              rescue ex : URI::Error
                raise ConfigurationError.new(
                  "#{@service} endpoint #{endpoint_url} is not a valid URL: #{ex.message}")
              end
              unless parsed.scheme == "https" || (@allow_insecure_endpoint && parsed.scheme == "http")
                raise ConfigurationError.new(
                  "#{@service} endpoint #{endpoint_url} must use https " \
                  "(http is only allowed with allow_insecure_endpoint)")
              end
              parsed
            else
              URI.parse("https://#{@service}.#{@region}.#{aws_domain}")
            end
      raise ConfigurationError.new("#{@service} endpoint #{uri} has no host") unless uri.host
      uri
    end

    # AWS partitions share the JSON 1.1 API but not the domain.
    private def aws_domain : String
      @region.starts_with?("cn-") ? "amazonaws.com.cn" : "amazonaws.com"
    end

    private def request_path : String
      path = @endpoint.path
      path.empty? ? "/" : path
    end

    private def authority(uri : URI) : String
      host = uri.host
      raise ConfigurationError.new("#{@service} endpoint #{uri} has no host") unless host
      port = uri.port
      default_port = uri.scheme == "https" ? 443 : 80
      port && port != default_port ? "#{host}:#{port}" : host
    end

    private def retry_delay(attempt : Int32) : Time::Span
      # Int64 and a capped shift: with @retries >= 32 an Int32 `1 << n`
      # wrapped negative and produced a negative sleep.
      base = 100.milliseconds * (1_i64 << (attempt - 1).clamp(0, 6))
      capped = base > 5.seconds ? 5.seconds : base
      capped + rand(capped.total_milliseconds.to_i + 1).milliseconds
    end
  end
end
