require "base64"
require "http/web_socket"
require "json"
require "openssl"
require "uri"
require "./chunker"
require "./client"
require "./credentials"
require "./encryption"
require "./errors"
require "./handshake"
require "./kms"
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
  # One reader fiber pumps frames, one writer path, and retransmit/ping/idle
  # fibers keep the channel alive. `read?` returns nil once the session is
  # closed and drained. Writes are serialized per message, so concurrent
  # callers are allowed but their chunks interleave; a `write` that fails
  # mid-stream may already have delivered a prefix.
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

    # Output is handed to `read?` through a growable queue, never a bounded
    # channel: the websocket reader must keep consuming frames (notably the
    # agent's acknowledgements) while a caller is not reading output. A bounded
    # queue that made the reader wait stalled every transfer that produced
    # output the caller had not drained yet, and an upload whose writer waits
    # for acknowledgements deadlocked outright. `Settings#output_buffer_limit`
    # caps the memory instead; exceeding it fails the session.
    @output = Deque(Output).new
    @output_bytes = 0_i64
    @output_mutex = Mutex.new
    @output_finished = false
    @output_signal = Channel(Nil).new(1)
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
    @last_inbound = Time.monotonic
    @generation = 0
    @ws : HTTP::WebSocket?
    @io : IO?
    @kms : Kms?
    @encrypter : Encrypter?
    @encryption_enabled = false

    def self.open(settings : Settings, chain : CredentialChain = CredentialChain.default,
                  client : Client? = nil, kms : Kms? = nil) : Session
      client ||= Client.new(settings, chain)
      info = client.start_session
      new(settings, client, info, kms).tap(&.connect)
    end

    def initialize(@settings : Settings, @client : Client, @info : SessionInfo,
                   @kms : Kms? = nil)
      @session_id = @info.session_id
      @client_id = UUID.random.to_s
    end

    # True once the KMS handshake action succeeded and payload encryption is on.
    def encryption_enabled? : Bool
      @encryption_enabled
    end

    # Dial the data channel, send the token in the open message and wait for
    # the agent handshake to complete.
    def connect : Nil
      open_channel(@info)
      send_open_message(@info)
      await_handshake
    end

    # Chunks the bytes into input_stream_data messages. A single writer is the
    # intended use; concurrent calls do not corrupt a message but interleave
    # chunks. Raises `ChannelClosed` if the session goes away mid-stream (some
    # chunks may already have been delivered).
    def write(bytes : Bytes) : Nil
      raise_closed if closed?
      return if bytes.empty?

      Chunker.chunks(bytes, @settings.chunk_size).each do |chunk|
        # The reference plugin rewrites a lone LF to CR for the pty.
        chunk = Bytes[13_u8] if chunk == Bytes[10_u8]
        await_send_room
        send_input(PayloadType::Output.value, chunk)
      end
    end

    def write(text : String) : Nil
      write(text.to_slice)
    end

    # Outbound messages still awaiting acknowledgement.
    def pending : Int32
      @reliability.pending
    end

    # Counters for the outbound channel: messages and bytes sent, acks,
    # round-trip samples, retransmissions and the send-window high-water mark.
    # Diagnostic only; the live throughput test prints it.
    def stats : Reliability::Stats
      @reliability.stats
    end

    # Ordered stdout/stderr bytes, or nil once closed and drained.
    def read? : Output?
      loop do
        output = @output_mutex.synchronize do
          item = @output.shift?
          @output_bytes -= item.bytes.size if item
          item
        end
        return output if output
        return if @output_mutex.synchronize { @output.empty? && @output_finished }
        @output_signal.receive?
      end
    end

    def closed? : Bool
      @state_mutex.synchronize { @closed }
    end

    # The data-channel transport (the TLS or plain TCP socket). Diagnostic,
    # and what the spec pins `TCP_NODELAY` on.
    def transport : IO?
      @io
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
        # Invalidate the fibers and callbacks of the connection being replaced
        # before anything can observe the session as open again. The old
        # generation must never match, or its loop would close this session.
        @generation += 1
        @closed = false
        @close_reason = nil
        @error = nil
        @output_mutex.synchronize do
          @output = Deque(Output).new
          @output_bytes = 0_i64
          @output_finished = false
        end
        @output_signal = Channel(Nil).new(1)
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
      generation = @state_mutex.synchronize { @generation }
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
      begin
        # A websocket frame is several small writes and the payload is usually
        # below one MSS. With Nagle on (Crystal's default, unlike Go's) every
        # message waits for the previous one's delayed acknowledgement, which
        # caps a sustained upload at about one MSS per RTT (~30 KiB/s on a
        # typical link). Go's net package, and therefore the reference plugin,
        # disables Nagle by default. See docs/protocol.md.
        tcp.tcp_nodelay = @settings.tcp_nodelay?
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
          quietly { tcp.close }
          raise HandshakeFailed.new(
            "data-channel upgrade to #{StreamUrl.redact(uri)} returned HTTP #{response.status_code}")
        end
        expected = HTTP::WebSocket::Protocol.key_challenge(key)
        unless response.headers["Sec-WebSocket-Accept"]? == expected
          quietly { tcp.close }
          raise HandshakeFailed.new("data-channel upgrade did not return a valid Sec-WebSocket-Accept")
        end
        io
      rescue ex : Socket::Error | OpenSSL::SSL::Error | IO::Error
        # Closing the TCP socket covers a failure before or during the TLS
        # handshake; the TLS socket wraps it with sync_close.
        quietly { tcp.close }
        raise HandshakeFailed.new(
          "failed to open data channel #{StreamUrl.redact(uri)}: #{ex.message}", cause: ex)
      end
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
      @state_mutex.synchronize { !@closed && @generation == generation }
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
        rescue ChannelClosed
          # The session went away between the loop guard and the send.
          break
        end
      end
    end

    private def ping_loop(generation : Int32) : Nil
      while current?(generation)
        sleep @settings.ping_interval
        next unless current?(generation)
        # A ping is a websocket frame like any other: serialize it with data
        # writes (the reference plugin takes its write lock here too), or two
        # fibers can interleave frame fragments on the wire.
        quietly { @send_mutex.synchronize { @ws.try(&.ping) } }
      end
    end

    private def liveness_loop(generation : Int32) : Nil
      while current?(generation)
        sleep 1.second
        next unless current?(generation)
        last_inbound = @state_mutex.synchronize { @last_inbound }
        if Time.monotonic - last_inbound > @settings.idle_timeout
          close!(CloseReason::SessionTimeout)
          break
        end
        # An ack-stalled stream is stuck even if the agent keeps sending
        # output: a writer out of window would otherwise sit in await_room
        # until every retransmission attempt is exhausted.
        if @reliability.pending > 0 && @reliability.ack_idle > @settings.idle_timeout
          stalled = @reliability.ack_idle.total_seconds.round
          close!(CloseReason::SessionTimeout,
            SessionTimeout.new("no acknowledgement for #{stalled}s"))
          break
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
      when MessageType::START_PUBLICATION, MessageType::PAUSE_PUBLICATION
        # Advisory only. The reference plugin's OutputMessageHandler ignores
        # both message types, and blocking writes on a real agent's pause
        # throttled input to about 30 KiB/s: see docs/protocol.md.
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
        emit(Stream::Stdout, payload_bytes(message))
      when PayloadType::StdErr.value
        emit(Stream::Stderr, payload_bytes(message))
      when PayloadType::ExitCode.value
        @exit_code = parse_exit_code(payload_bytes(message))
      when PayloadType::Error.value
        @channel_output = String.new(message.payload)
      when PayloadType::EncChallengeRequest.value
        handle_encryption_challenge(message)
      else
        # Size, Parameter and Flag are not exposed by this byte-stream API.
      end
    end

    # Payload types 1, 11 and 12 are AES-GCM encrypted when KMS is on; the
    # handshake and control payloads stay clear (plugin `streaming.go`).
    private def payload_bytes(message : Message) : Bytes
      encrypter = @encrypter
      return message.payload unless encrypter && @encryption_enabled && encrypted_payload?(message.payload_type)
      encrypter.decrypt(message.payload)
    end

    private def encrypted_payload?(payload_type : UInt32) : Bool
      payload_type == PayloadType::Output.value ||
        payload_type == PayloadType::StdErr.value ||
        payload_type == PayloadType::ExitCode.value
    end

    private def handle_encryption_challenge(message : Message) : Nil
      encrypter = @encrypter
      unless encrypter
        @handshake_error = HandshakeFailed.new(
          "the agent requested an encryption challenge before KMS was negotiated")
        notify_handshake
        close!(CloseReason::ProtocolError)
        return
      end
      challenge = JSON.parse(String.new(message.payload))["Challenge"]?.try(&.as_s?)
      raise ProtocolError.new("EncChallengeRequest is missing Challenge") unless challenge
      plaintext = encrypter.decrypt(Base64.decode(challenge))
      encrypted = encrypter.encrypt(plaintext)
      response = JSON.build do |json|
        json.object { json.field "Challenge", Base64.strict_encode(encrypted) }
      end
      send_input(PayloadType::EncChallengeResponse.value, response.to_slice)
    rescue ex : ProtocolError | Base64::Error | JSON::ParseException
      @error = ex
      @handshake_error = ex
      notify_handshake
      close!(CloseReason::ProtocolError)
    end

    # Never blocks: the websocket reader has to keep consuming frames even
    # when the caller is not draining output. Memory is capped by
    # `Settings#output_buffer_limit`.
    private def emit(stream : Stream, bytes : Bytes) : Nil
      return if bytes.empty? || closed?
      overflow = false
      added = @output_mutex.synchronize do
        if @output_finished
          false
        else
          @output << Output.new(stream, bytes.dup)
          @output_bytes += bytes.size
          overflow = @output_bytes > @settings.output_buffer_limit
          true
        end
      end
      return unless added
      if overflow
        @error = OutputBufferExceeded.new(
          "unread session output exceeded #{@settings.output_buffer_limit} bytes")
        close!(CloseReason::ProtocolError)
        return
      end
      # `close!` may close the signal between the guard above and this send.
      quietly do
        select
        when @output_signal.send(nil)
        else
        end
      end
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
      kms_error : HandshakeFailed? = nil

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
          begin
            result = enable_kms_encryption(action.action_parameters)
            processed << Handshake::ProcessedClientAction.new(
              ActionType::KMS_ENCRYPTION, ActionStatus::Success.value, result)
          rescue ex : Error | OpenSSL::Error | JSON::ParseException | IO::Error
            failure = HandshakeFailed.new(
              "Failed to process action KMSEncryption: #{ex.message}", cause: ex)
            kms_error = failure
            processed << Handshake::ProcessedClientAction.new(
              ActionType::KMS_ENCRYPTION, ActionStatus::Failed.value, nil, failure.message.to_s)
            errors << failure.message.to_s
          end
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

      if failed = kms_error
        @handshake_error = failed
        notify_handshake
        close!(CloseReason::ProtocolError)
      end
    end

    # Run the KMS handshake action: GenerateDataKey, split the key, and return
    # the exact plugin JSON (`KMSCipherTextHash` marshals as null).
    private def enable_kms_encryption(parameters : JSON::Any?) : JSON::Any
      raise HandshakeFailed.new("KMSEncryption action is missing its parameters") unless parameters
      request = Handshake::KMSEncryptionRequest.from_json(parameters.to_json)
      data_key = kms_client.generate_data_key(request.kms_key_id, @session_id, @settings.target)
      @encrypter = Encrypter.new(data_key.plaintext)
      @encryption_enabled = true
      JSON.parse(JSON.build do |json|
        json.object do
          json.field "KMSCipherTextKey", Base64.strict_encode(data_key.ciphertext_blob)
          json.field "KMSCipherTextHash", nil
        end
      end)
    end

    private def kms_client : Kms
      @kms ||= Kms.new(@client.credentials, @settings.region,
        endpoint_url: @settings.kms_endpoint_url,
        allow_insecure_endpoint: @settings.allow_insecure_endpoint?,
        retries: @settings.retries,
        connect_timeout: @settings.connect_timeout,
        read_timeout: @settings.read_timeout)
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
        if @encryption_enabled && payload_type == PayloadType::Output.value
          if encrypter = @encrypter
            payload = encrypter.encrypt(payload)
          end
        end
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

    # Wait for the send window: the reference plugin silently drops the oldest
    # unacknowledged message when its buffer fills, which abandons a sequence
    # the agent is still waiting for and stalls the stream. Waiting keeps the
    # in-order stream intact and, with a window sized to the agent's receive
    # path (Settings#send_window_bytes), stops a burst from overrunning the
    # service and being dropped. The liveness loop closes a session whose
    # acknowledgements stop, and `wake` releases this wait on close.
    private def await_send_room : Nil
      loop do
        raise_closed if closed?
        return if @reliability.pending_bytes < @settings.send_window_bytes
        @reliability.await_room
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

    private def close!(reason : CloseReason, error : Exception? = nil) : Nil
      # Snapshot the connection this close belongs to: `resume` may replace
      # @ws/@io/@output_signal while the teardown below is still running, and
      # the old close must never touch the resumed session.
      snapshot = @state_mutex.synchronize do
        next if @closed
        @closed = true
        @close_reason = reason
        @error = error || @error
        {ws: @ws, io: @io, signal: @output_signal, generation: @generation}
      end
      return unless snapshot

      @handshake_error ||= error
      notify_handshake
      @reliability.wake
      quietly { snapshot[:ws].try(&.close) }
      quietly { snapshot[:io].try(&.close) }
      same_generation = @state_mutex.synchronize { @generation == snapshot[:generation] }
      if same_generation
        @output_mutex.synchronize { @output_finished = true }
      end
      quietly { snapshot[:signal].close }
    end

    private def quietly(&) : Nil
      yield
    rescue
    end
  end
end
