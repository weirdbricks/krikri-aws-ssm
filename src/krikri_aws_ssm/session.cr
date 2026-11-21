require "base64"
require "http/web_socket"
require "json"
require "openssl"
require "uri"
require "./chunker"
require "./client"
require "./credentials"
require "./errors"
require "./handshake"
require "./message"
require "./reliability"
require "./settings"
require "./stream_url"

module KrikriAwsSsm
  enum Stream
    Stdout
    Stderr
  end

  record Output, stream : Stream, bytes : Bytes

  enum CloseReason
    Clean
    AgentClosed
    NetworkLost
    SessionTimeout
    ProtocolError
    Terminated
  end

  # A byte-stream Session Manager session.
  #
  # One reader fiber pumps frames, one writer contract (`write` is
  # mutex-protected), and retransmit/ping/idle fibers keep the channel alive.
  # `read?` returns nil once the session is closed and drained.
  class Session
    getter session_id : String
    getter client_id : String
    getter close_reason : CloseReason?
    getter exit_code : Int32?
    # `channel_closed` Output text, verbatim from the agent.
    getter channel_output : String?
    # Last transport/protocol error, for callers that report unreachable text.
    getter error : Exception?
    getter session_type : String?

    @output = Channel(Output).new
    @inbound = InboundSequencer(Message).new
    @reliability = Reliability.new
    @write_mutex = Mutex.new
    @send_mutex = Mutex.new
    @state_mutex = Mutex.new
    @closed = false
    @terminated = false
    @handshake_complete = false
    @handshake_notified = false
    @handshake_done = Channel(Nil).new(1)
    @handshake_error : Exception?
    @pause_channel : Channel(Nil)?
    @last_inbound = Time.monotonic
    @generation = 0
    @ws : HTTP::WebSocket?
    @io : IO?

    def self.open(settings : Settings, chain : CredentialChain = CredentialChain.default,
                  client : Client? = nil) : Session
      client ||= Client.new(settings, chain)
      info = client.start_session
      new(settings, client, info).tap(&.connect)
    end

    def initialize(@settings : Settings, @client : Client, @info : SessionInfo)
      @session_id = @info.session_id
      @client_id = UUID.random.to_s
    end

    # Dial the data channel, send the token in the open message and wait for
    # the agent handshake to complete.
    def connect : Nil
      open_channel(@info)
      send_open_message(@info)
      await_handshake
    end

    def write(bytes : Bytes) : Nil
      raise_closed if closed?
      wait_for_publication
      return if bytes.empty?

      Chunker.chunks(bytes, @settings.chunk_size).each do |chunk|
        # The reference plugin rewrites a lone LF to CR for the pty.
        chunk = Bytes[13_u8] if chunk == Bytes[10_u8]
        send_input(PayloadType::Output.value, chunk)
      end
    end

    def write(text : String) : Nil
      write(text.to_slice)
    end

    # Ordered stdout/stderr bytes, or nil once closed and drained.
    def read? : Output?
      @output.receive?
    end

    def closed? : Bool
      @state_mutex.synchronize { @closed }
    end

    # Terminate the session on the control plane and close the channel.
    # Idempotent.
    def terminate : Nil
      first = @state_mutex.synchronize do
        next false if @terminated
        @terminated = true
        true
      end
      if first && !closed?
        begin
          @client.terminate_session(@session_id)
        rescue ex : ApiError
          @error = ex
        end
      end
      close!(CloseReason::Terminated)
    end

    # Redial after a dropped channel: ResumeSession for a fresh URL/token, then
    # reopen and re-send the open message. Matching the reference plugin,
    # sequence numbers, buffers and (phase 5) encryption state survive and the
    # handshake is not replayed.
    def resume : Nil
      raise ChannelClosed.new("session was not closed") unless closed?
      raise ChannelClosed.new("session was terminated") if @terminated
      info = @client.resume_session(@session_id)
      @info = info
      reset_for_reconnect
      open_channel(info)
      send_open_message(info)
    end

    private def reset_for_reconnect : Nil
      @state_mutex.synchronize do
        @closed = false
        @close_reason = nil
        @error = nil
        @pause_channel = nil
        @output = Channel(Output).new
        @handshake_done = Channel(Nil).new(1)
        @handshake_notified = false
        @handshake_complete = true
      end
    end

    # --- transport ---------------------------------------------------------

    private def open_channel(info : SessionInfo) : Nil
      uri = StreamUrl.parse(info.stream_url)
      StreamUrl.validate!(uri, @settings.allow_insecure_endpoint?)
      io = dial(uri)
      @io = io
      @last_inbound = Time.monotonic
      ws = HTTP::WebSocket.new(HTTP::WebSocket::Protocol.new(io, masked: true, sync_close: true))
      @ws = ws
      ws.on_binary { |bytes| handle_frame(bytes) }
      generation = @state_mutex.synchronize do
        @generation += 1
      end
      ws.on_close { |_code, _message| close!(CloseReason::NetworkLost) if current?(generation) }
      spawn { read_loop(ws, generation) }
      spawn { retransmit_loop(generation) }
      spawn { ping_loop(generation) }
      spawn { liveness_loop(generation) }
    end

    private def dial(uri : URI) : IO
      host = uri.host
      raise ProtocolError.new("StreamUrl has no host") unless host
      port = uri.port || (uri.scheme == "wss" ? 443 : 80)
      tcp = TCPSocket.new(host, port)
      io = if uri.scheme == "wss"
             context = OpenSSL::SSL::Context::Client.new
             OpenSSL::SSL::Socket::Client.new(tcp, context: context, sync_close: true,
               hostname: host)
           else
             tcp
           end

      headers = HTTP::Headers{"Host" => StreamUrl.authority(uri)}
      request = HTTP::Request.new("GET", StreamUrl.request_target(uri), headers)
      unless StreamUrl.presigned?(uri)
        signer = KrikriAwsSigner::Signer.new("ssmmessages", @settings.region,
          @client.credentials.access_key, @client.credentials.secret_key,
          @client.credentials.session_token)
        signer.sign(request, add_sha: false)
      end

      key = Base64.strict_encode(Random::Secure.random_bytes(16))
      request.headers["Connection"] = "Upgrade"
      request.headers["Upgrade"] = "websocket"
      request.headers["Sec-WebSocket-Version"] = "13"
      request.headers["Sec-WebSocket-Key"] = key

      request.to_io(io)
      io.flush
      response = HTTP::Client::Response.from_io(io, ignore_body: true)
      unless response.status.switching_protocols?
        quietly { io.close }
        raise HandshakeFailed.new(
          "data-channel upgrade to #{StreamUrl.redact(uri)} returned HTTP #{response.status_code}")
      end
      expected = HTTP::WebSocket::Protocol.key_challenge(key)
      unless response.headers["Sec-WebSocket-Accept"]? == expected
        quietly { io.close }
        raise HandshakeFailed.new("data-channel upgrade did not return a valid Sec-WebSocket-Accept")
      end
      io
    rescue ex : Socket::Error | OpenSSL::SSL::Error | IO::Error
      raise HandshakeFailed.new(
        "failed to open data channel #{StreamUrl.redact(uri)}: #{ex.message}", cause: ex)
    end

    private def send_open_message(info : SessionInfo) : Nil
      payload = JSON.build do |json|
        json.object do
          json.field "MessageSchemaVersion", "1.0"
          json.field "RequestId", UUID.random.to_s
          json.field "TokenValue", info.token_value
          json.field "ClientId", @client_id
          json.field "ClientVersion", @settings.client_version
        end
      end
      send_text(payload)
    end

    private def read_loop(ws : HTTP::WebSocket, generation : Int32) : Nil
      ws.run
    rescue ex : IO::Error | Socket::Error | OpenSSL::SSL::Error
      @error = ex if current?(generation)
    ensure
      close!(CloseReason::NetworkLost) if current?(generation)
    end

    private def current?(generation : Int32) : Bool
      !closed? && @state_mutex.synchronize { @generation == generation }
    end

    private def retransmit_loop(generation : Int32) : Nil
      while current?(generation)
        sleep 100.milliseconds
        next unless current?(generation)
        begin
          if frame = @reliability.retransmission
            send_raw(frame)
          end
        rescue ex : Reliability::RetransmissionTimeout
          @error = ex
          close!(CloseReason::ProtocolError)
        end
      end
    end

    private def ping_loop(generation : Int32) : Nil
      while current?(generation)
        sleep @settings.ping_interval
        next unless current?(generation)
        quietly { @ws.try(&.ping) }
      end
    end

    private def liveness_loop(generation : Int32) : Nil
      while current?(generation)
        sleep 1.second
        next unless current?(generation)
        last_inbound = @state_mutex.synchronize { @last_inbound }
        if Time.monotonic - last_inbound > @settings.idle_timeout
          close!(CloseReason::SessionTimeout)
        end
      end
    end

    # --- inbound -----------------------------------------------------------

    private def handle_frame(bytes : Bytes) : Nil
      message = Message.decode(bytes)
      @state_mutex.synchronize { @last_inbound = Time.monotonic }
      case message.message_type
      when MessageType::OUTPUT_STREAM_DATA
        handle_output_stream(message)
      when MessageType::ACKNOWLEDGE
        ack = AcknowledgeContent.from_json(String.new(message.payload))
        @reliability.acknowledge(ack.sequence_number)
      when MessageType::CHANNEL_CLOSED
        @channel_output = ChannelClosedContent.from_json(String.new(message.payload)).output
        close!(CloseReason::AgentClosed)
      when MessageType::START_PUBLICATION
        start_publication
      when MessageType::PAUSE_PUBLICATION
        pause_publication
      else
        # Unknown message types are ignored, matching OutputMessageHandler.
      end
    rescue ex : ProtocolError | JSON::ParseException
      @error = ex
      close!(CloseReason::ProtocolError)
    rescue ChannelClosed
      # The session closed while this frame was being processed.
    end

    private def handle_output_stream(message : Message) : Nil
      acceptance = @inbound.accept(message.sequence_number, message)
      case acceptance.disposition
      when InboundSequencer::Disposition::Delivered
        acceptance.items.each do |item|
          acknowledge(item) if handshake_payload?(item)
          deliver(item)
          acknowledge(item) unless handshake_payload?(item)
        end
      when InboundSequencer::Disposition::Buffered
        acknowledge(message)
      when InboundSequencer::Disposition::Duplicate, InboundSequencer::Disposition::Overflow
        # No ack: double-acking a duplicate confuses the agent's accounting.
      end
    end

    private def handshake_payload?(message : Message) : Bool
      type = message.payload_type
      type == PayloadType::HandshakeRequest.value ||
        type == PayloadType::HandshakeComplete.value ||
        type == PayloadType::EncChallengeRequest.value
    end

    private def deliver(message : Message) : Nil
      case message.payload_type
      when PayloadType::HandshakeRequest.value
        handle_handshake_request(message)
      when PayloadType::HandshakeComplete.value
        complete_handshake
      when PayloadType::Output.value
        complete_handshake if !@handshake_complete && @session_type.nil?
        emit(Stream::Stdout, message.payload)
      when PayloadType::StdErr.value
        emit(Stream::Stderr, message.payload)
      when PayloadType::ExitCode.value
        @exit_code = parse_exit_code(message.payload)
      when PayloadType::Error.value
        @channel_output = String.new(message.payload)
      when PayloadType::EncChallengeRequest.value
        @handshake_error = KmsUnsupported.new("the agent requested an encryption challenge")
        notify_handshake
        close!(CloseReason::ProtocolError)
      else
        # Size, Parameter and Flag are not exposed by this byte-stream API.
      end
    end

    private def emit(stream : Stream, bytes : Bytes) : Nil
      return if bytes.empty? || closed?
      @output.send(Output.new(stream, bytes.dup))
    rescue Channel::ClosedError
      # The session closed between the guard and the send.
    end

    private def parse_exit_code(payload : Bytes) : Int32?
      # The agent sends the ASCII text `EXIT_CODE: <n>`.
      text = String.new(payload)
      match = text.match(/\AEXIT_CODE:\s*(-?\d+)/)
      match.try(&.[1].to_i?)
    end

    private def handle_handshake_request(message : Message) : Nil
      request = Handshake::HandshakeRequestPayload.from_json(String.new(message.payload))
      processed = [] of Handshake::ProcessedClientAction
      errors = [] of String
      kms_requested = false

      request.requested_client_actions.each do |action|
        case action.action_type
        when ActionType::SESSION_TYPE
          if process_session_type(action.action_parameters)
            processed << Handshake::ProcessedClientAction.new(
              ActionType::SESSION_TYPE, ActionStatus::Success.value)
          else
            text = "Unknown session type"
            processed << Handshake::ProcessedClientAction.new(
              ActionType::SESSION_TYPE, ActionStatus::Failed.value, nil, text)
            errors << text
          end
        when ActionType::KMS_ENCRYPTION
          kms_requested = true
          text = "KMS session encryption is not supported by this client"
          processed << Handshake::ProcessedClientAction.new(
            ActionType::KMS_ENCRYPTION, ActionStatus::Failed.value, nil, text)
          errors << text
        else
          text = "Unsupported action #{action.action_type}"
          processed << Handshake::ProcessedClientAction.new(
            action.action_type, ActionStatus::Unsupported.value, nil, text)
          errors << text
        end
      end

      response = Handshake::HandshakeResponsePayload.new(
        @settings.client_version, processed, errors.empty? ? nil : errors)
      send_input(PayloadType::HandshakeResponse.value, response.to_json.to_slice)

      if kms_requested
        @handshake_error = KmsUnsupported.new
        notify_handshake
        close!(CloseReason::ProtocolError)
      end
    end

    private def process_session_type(parameters : JSON::Any?) : Bool
      return false unless parameters
      request = Handshake::SessionTypeRequest.from_json(parameters.to_json)
      case request.session_type
      when SessionType::STANDARD_STREAM, SessionType::INTERACTIVE_COMMANDS,
           SessionType::NON_INTERACTIVE_COMMANDS
        @session_type = SessionType::STANDARD_STREAM
        true
      when SessionType::PORT
        @session_type = request.session_type
        true
      else
        false
      end
    rescue JSON::ParseException
      false
    end

    private def complete_handshake : Nil
      return if @handshake_complete
      @handshake_complete = true
      notify_handshake
    end

    private def await_handshake : Nil
      select
      when @handshake_done.receive
        if error = @handshake_error
          raise error
        end
        unless @handshake_complete
          raise HandshakeFailed.new("session closed before the agent completed the handshake")
        end
      when timeout(@settings.connect_timeout)
        close!(CloseReason::ProtocolError)
        raise HandshakeFailed.new("timed out waiting for the agent handshake")
      end
    end

    private def notify_handshake : Nil
      notify = @state_mutex.synchronize do
        next false if @handshake_notified
        @handshake_notified = true
        true
      end
      @handshake_done.send(nil) if notify
    end

    # --- outbound ----------------------------------------------------------

    private def send_input(payload_type : UInt32, payload : Bytes) : Nil
      @write_mutex.synchronize do
        raise_closed if closed?
        sequence = @reliability.allocate
        frame = Message.new(
          message_type: MessageType::INPUT_STREAM_DATA,
          payload: payload,
          payload_type: payload_type,
          sequence_number: sequence,
        ).encode
        send_raw(frame)
        @reliability.track(sequence, frame)
      end
    end

    private def acknowledge(message : Message) : Nil
      content = AcknowledgeContent.new(
        message.message_type, message.message_id.to_s, message.sequence_number)
      frame = Message.new(
        message_type: MessageType::ACKNOWLEDGE,
        payload: content.to_json.to_slice,
        flags: Flags::ACK,
      ).encode
      send_raw(frame)
    end

    private def send_text(payload : String) : Nil
      ws = @ws
      raise ChannelClosed.new("session is closed") if ws.nil? || ws.closed?
      @send_mutex.synchronize { ws.send(payload) }
    rescue ex : IO::Error
      @error = ex
      close!(CloseReason::NetworkLost)
      raise ChannelClosed.new("session channel is closed", cause: ex)
    end

    private def send_raw(bytes : Bytes) : Nil
      ws = @ws
      raise ChannelClosed.new("session is closed") if ws.nil? || ws.closed?
      @send_mutex.synchronize { ws.send(bytes) }
    rescue ex : IO::Error
      @error = ex
      close!(CloseReason::NetworkLost)
      raise ChannelClosed.new("session channel is closed", cause: ex)
    end

    private def raise_closed : Nil
      raise ChannelClosed.new(
        "session #{@session_id} is closed (#{@close_reason || CloseReason::NetworkLost})")
    end

    # --- lifecycle ---------------------------------------------------------

    private def pause_publication : Nil
      @state_mutex.synchronize { @pause_channel ||= Channel(Nil).new }
    end

    private def start_publication : Nil
      channel = @state_mutex.synchronize do
        pending = @pause_channel
        @pause_channel = nil
        pending
      end
      channel.try(&.close)
    end

    private def wait_for_publication : Nil
      while channel = @state_mutex.synchronize { @pause_channel }
        channel.receive?
      end
    end

    private def close!(reason : CloseReason, error : Exception? = nil) : Nil
      first = @state_mutex.synchronize do
        next false if @closed
        @closed = true
        @close_reason = reason
        @error = error || @error
        true
      end
      return unless first

      @handshake_error ||= error
      notify_handshake
      start_publication
      quietly { @ws.try(&.close) }
      quietly { @io.try(&.close) }
      @output.close
    end

    private def quietly(&) : Nil
      yield
    rescue
    end
  end
end
