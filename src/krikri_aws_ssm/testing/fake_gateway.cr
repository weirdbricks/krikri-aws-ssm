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

    getter control_requests = Channel(HTTP::Request).new(32)
    getter upgrade_requests = Channel(HTTP::Request).new(8)
    getter upgrade_results = Channel(SigV4::Result).new(8)
    getter upgrade_errors = Channel(String).new(8)
    getter agents = Channel(FakeAgent).new(8)
    getter resumed_sessions = Channel(String).new(8)
    getter terminated_sessions = Channel(String).new(8)

    @server : HTTP::Server
    @token_sequence = 0
    @connection_sequence = 0
    @mutex = Mutex.new

    def initialize(@credentials : Credentials,
                   @agent_options : FakeAgent::Options = FakeAgent::Options.new,
                   @presigned : Bool = false)
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

      begin
        SigV4.verify(captured, @credentials, "us-east-1", "ssm")
      rescue ex : SigV4::VerificationError
        respond(context, 400,
          %({"__type":"SignatureDoesNotMatch","message":#{ex.message.to_json}}))
        return
      end

      action = request.headers["X-Amz-Target"]?.try(&.split('.').last) || ""
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

    private def handle_upgrade(context : HTTP::Server::Context) : Nil
      request = context.request
      @upgrade_requests.send(
        HTTP::Request.new(request.method, request.resource, request.headers))

      unless presigned?
        begin
          result = SigV4.verify(request, @credentials, "us-east-1", "ssmmessages")
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
