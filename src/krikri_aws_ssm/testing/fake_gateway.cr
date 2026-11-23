require "base64"
require "http/server"
require "http/web_socket"
require "json"
require "../credentials"
require "./fake_agent"
require "./sigv4_verifier"

module KrikriAwsSsm::Testing
  # An in-process SSM control plane plus data-channel gateway.
  #
  # Every control-plane call and every websocket upgrade is SigV4-verified
  # against the known test credentials, and the exact SignedHeaders set is
  # recorded, so a Host/port or signing-order regression fails the connection
  # rather than passing silently.
  class FakeGateway
    getter port : Int32
    getter session_id = "s-fake-1"
    property agent_options : FakeAgent::Options
    property? presigned : Bool
    property credentials : Credentials
    property kms_plaintext_key : Bytes
    property kms_ciphertext_blob : Bytes
    # When set, every SSM control-plane action answers with this status and
    # body instead of its normal reply, so a spec can pin the client's
    # error mapping (TargetNotConnected, AccessDeniedException, ...).
    property control_failure : {Int32, String}? = nil
    # Replaces the data-channel URL in StartSession/ResumeSession, so a spec
    # can point the client at a non-responding peer.
    property stream_url_override : String? = nil

    # Capacities are generous: a handler blocks the server fiber on `send`
    # once a channel is full, so a busy spec must not stall the fake gateway.
    getter control_requests = Channel(HTTP::Request).new(1024)
    getter upgrade_requests = Channel(HTTP::Request).new(64)
    getter upgrade_results = Channel(SigV4::Result).new(64)
    getter upgrade_errors = Channel(String).new(64)
    getter agents = Channel(FakeAgent).new(64)
    getter resumed_sessions = Channel(String).new(64)
    getter terminated_sessions = Channel(String).new(64)
    getter kms_requests = Channel(HTTP::Request).new(256)

    # Waits for the next websocket upgrade's verified signed-header set.
    #
    # Do not poll `upgrade_results` with `empty?`: a Channel is an Iterator
    # here, so `empty?` is Enumerable#empty? - it consumes one result and
    # then blocks forever on the now empty channel. This helper is the
    # non-destructive wait, returning nil after *timeout*.
    def next_upgrade_result(timeout : Time::Span = 3.seconds) : SigV4::Result?
      select
      when result = upgrade_results.receive
        result
      when timeout(timeout)
        nil
      end
    end

    @server : HTTP::Server
    @token_sequence = 0
    @connection_sequence = 0
    @mutex = Mutex.new

    def initialize(@credentials : Credentials,
                   @agent_options : FakeAgent::Options = FakeAgent::Options.new,
                   @presigned : Bool = false, @region : String = "us-east-1")
      @kms_plaintext_key = @agent_options.kms_plaintext_key
      @kms_ciphertext_blob = Bytes[9_u8, 8_u8, 7_u8, 6_u8]
      @server = HTTP::Server.new do |context|
        if upgrade?(context.request)
          handle_upgrade(context)
        else
          handle_control(context)
        end
      end
      @port = @server.bind_tcp("127.0.0.1", 0).port
      spawn { @server.listen }
    end

    def url : String
      "http://127.0.0.1:#{@port}"
    end

    def stream_url : String
      if override = @stream_url_override
        return override
      end
      base = "ws://127.0.0.1:#{@port}/data-channel/#{@session_id}"
      presigned? ? "#{base}?X-Amz-Signature=stub&X-Amz-Credential=stub" : base
    end

    def close : Nil
      @server.close
    end

    private def upgrade?(request : HTTP::Request) : Bool
      request.headers["Upgrade"]?.try(&.downcase) == "websocket"
    end

    private def handle_control(context : HTTP::Server::Context) : Nil
      request = context.request
      body = request.body.try(&.gets_to_end) || ""
      captured = HTTP::Request.new(request.method, request.resource, request.headers, body)
      @control_requests.send(captured)

      action = request.headers["X-Amz-Target"]?.try(&.split('.').last) || ""
      service = request.headers["X-Amz-Target"]?.try(&.starts_with?("TrentService.")) ? "kms" : "ssm"

      begin
        SigV4.verify(captured, @credentials, @region, service)
      rescue ex : SigV4::VerificationError
        respond(context, 400,
          %({"__type":"SignatureDoesNotMatch","message":#{ex.message.to_json}}))
        return
      end

      if service == "kms"
        handle_kms(context, action, body)
        return
      end

      if failure = @control_failure
        respond(context, failure[0], failure[1])
        return
      end

      case action
      when "StartSession"
        respond(context, 200, session_payload)
      when "ResumeSession"
        @resumed_sessions.send(session_id)
        respond(context, 200, session_payload)
      when "TerminateSession"
        @terminated_sessions.send(session_id)
        respond(context, 200, "{}")
      when "DescribeSessions"
        respond(context, 200, %({"Sessions":[{"SessionId":#{session_id.to_json},"Status":"Connected"}]}))
      else
        respond(context, 400,
          %({"__type":"InvalidAction","message":"unsupported action #{action}"}))
      end
    end

    private def handle_kms(context : HTTP::Server::Context, action : String, body : String) : Nil
      request = context.request
      captured = HTTP::Request.new(request.method, request.resource, request.headers, body)
      @kms_requests.send(captured)
      unless action == "GenerateDataKey"
        respond(context, 400,
          %({"__type":"InvalidAction","message":"unsupported KMS action #{action}"}))
        return
      end
      respond(context, 200, JSON.build do |json|
        json.object do
          json.field "CiphertextBlob", Base64.strict_encode(kms_ciphertext_blob)
          json.field "KeyId", "arn:aws:kms:#{@region}:123456789012:key/fake"
          json.field "Plaintext", Base64.strict_encode(kms_plaintext_key)
        end
      end)
    end

    private def handle_upgrade(context : HTTP::Server::Context) : Nil
      request = context.request
      @upgrade_requests.send(
        HTTP::Request.new(request.method, request.resource, request.headers))

      if presigned?
        # A presigned URL must carry its signature and must not be signed
        # again; otherwise the presigned path is never actually exercised.
        query = URI::Params.parse(request.resource.split('?', 2)[1]? || "")
        unless query["X-Amz-Signature"]?
          @upgrade_errors.send("presigned upgrade is missing X-Amz-Signature")
          respond(context, 403,
            %({"__type":"InvalidRequest","message":"presigned upgrade is missing X-Amz-Signature"}))
          return
        end
        if request.headers["Authorization"]?
          @upgrade_errors.send("presigned upgrade must not carry Authorization")
          respond(context, 403,
            %({"__type":"InvalidRequest","message":"presigned upgrade must not carry Authorization"}))
          return
        end
      else
        begin
          result = SigV4.verify(request, @credentials, @region, "ssmmessages")
          @upgrade_results.send(result)
        rescue ex : SigV4::VerificationError
          @upgrade_errors.send(ex.message.to_s)
          respond(context, 403,
            %({"__type":"SignatureDoesNotMatch","message":#{ex.message.to_json}}))
          return
        end
      end

      key = request.headers["Sec-WebSocket-Key"]?
      unless key
        respond(context, 400, %({"__type":"InvalidRequest","message":"missing Sec-WebSocket-Key"}))
        return
      end

      context.response.status_code = 101
      context.response.headers["Connection"] = "Upgrade"
      context.response.headers["Upgrade"] = "websocket"
      context.response.headers["Sec-WebSocket-Accept"] =
        HTTP::WebSocket::Protocol.key_challenge(key)

      context.response.upgrade do |io|
        ws = HTTP::WebSocket.new(io)
        agent = FakeAgent.new(ws, io, @agent_options)
        @agents.send(agent)
        agent.run
      end
    end

    private def session_payload : String
      token = @mutex.synchronize do
        @token_sequence += 1
        "fake-token-#{@token_sequence}"
      end
      JSON.build do |json|
        json.object do
          json.field "SessionId", session_id
          json.field "StreamUrl", stream_url
          json.field "TokenValue", token
        end
      end
    end

    private def respond(context : HTTP::Server::Context, status : Int32, body : String) : Nil
      context.response.status_code = status
      context.response.headers["Content-Type"] = "application/x-amz-json-1.1"
      context.response.print(body)
    end
  end
end
