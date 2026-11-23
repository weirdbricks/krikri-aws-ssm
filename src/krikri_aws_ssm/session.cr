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

    # The state below is written on one fiber and read on another (reader,
    # writer, liveness, resume), so both sides go through @state_mutex
    # instead of relying on the scheduler's memory ordering.
    def close_reason : CloseReason?
      @state_mutex.synchronize { @close_reason }
    end

    def exit_code : Int32?
      @state_mutex.synchronize { @exit_code }
    end

    # `channel_closed` Output text, verbatim from the agent.
    def channel_output : String?
      @state_mutex.synchronize { @channel_output }
    end

    # Last transport/protocol error, for callers that report unreachable text.
    def error : Exception?
      @state_mutex.synchronize { @error }
    end

    def session_type : String?
      @state_mutex.synchronize { @session_type }
    end

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
    # Fibers other than the reader observe these through the accessors above.
    @close_reason : CloseReason?
    @exit_code : Int32?
    @channel_output : String?
    @error : Exception?
    @session_type : String?
    # Last *progress* (a delivery or a client message actually acknowledged),
    # not the last inbound byte: a chatty peer can fill the reader forever
    # while the sequencer is wedged, and acking duplicates or unknown
    # sequences is not progress either.
    @last_progress = Time.instant
    # When the first out-of-order frame arrived; nil while the stream is
    # contiguous. A gap older than `idle_timeout` is a protocol wedge.
    @gap_since : Time::Instant?
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
      # Buffered-but-undelivered frames hold full payload copies and are acked
      # (so the agent gets no backpressure); meter them like unread output.
      @inbound = InboundSequencer(Message).new(
        max_bytes: @settings.output_buffer_limit)
    end

    # The session holds `@info` (stream URL and token) and settings holding
    # credentials; the default `inspect` prints both.
    def to_s(io : IO) : Nil
      io << "Session(" << @session_id << ')'
    end

    def inspect(io : IO) : Nil
      to_s(io)
    end

    # True once the KMS handshake action succeeded and payload encryption is on.
    def encryption_enabled? : Bool
      @state_mutex.synchronize { @encryption_enabled }
    end

    # Dial the data channel, send the token in the open message and wait for
    # the agent handshake to complete.
    def connect : Nil
      generation = open_channel(@info)
      send_open_message(@info, generation)
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

    # Chunks the bytes into input_stream_data messages without `write`'s
    # reference-plugin LF rewrite. A caller moving a binary stream through the
    # pty (`rsync`'s protocol, for instance) must not have a chunk that
    # happens to be the single byte LF turned into CR; whether LF is safe at
    # all is the caller's terminal-state decision, not this method's.
    # Interleaving and failure rules are the same as `write`.
    def write_raw(bytes : Bytes) : Nil
      raise_closed if closed?
      return if bytes.empty?

      Chunker.chunks(bytes, @settings.chunk_size).each do |chunk|
        await_send_room
        send_input(PayloadType::Output.value, chunk)
      end
    end

    def write_raw(text : String) : Nil
      write_raw(text.to_slice)
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

    private def terminated? : Bool
      @state_mutex.synchronize { @terminated }
    end

    private def record_error(error : Exception) : Nil
      @state_mutex.synchronize { @error = error }
    end

    # The data-channel transport (the TLS or plain TCP socket). Diagnostic,
    # and what the spec pins `TCP_NODELAY` on.
    def transport : IO?
      @state_mutex.synchronize { @io }
    end

    # Terminate the session on the control plane and close the channel.
    # Idempotent. The control-plane call is made even when the transport has
    # already died: a NetworkLost session is still live service-side until it
    # is reclaimed, and `resume` is then blocked by @terminated. A session
    # that already ended answers SessionNotFound, which is swallowed.
    def terminate : Nil
      first = @state_mutex.synchronize do
        next false if @terminated
        @terminated = true
        true
      end
      if first
        begin
          @client.terminate_session(@session_id)
        rescue ex : ApiError
          record_error(ex)
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
      raise ChannelClosed.new("session was terminated") if terminated?
      info = @client.resume_session(@session_id)
      @info = info
      reset_for_reconnect
      begin
        generation = open_channel(info)
        send_open_message(info, generation)
      rescue ex : Exception
        # reset_for_reconnect cleared @closed; a failed reopen would leave the
        # session reporting open with a dead transport, unreadable and
        # unresumable. Re-close with the failure as the reason.
        close!(CloseReason::NetworkLost, ex)
        raise ex
      end
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
        # Sticky via `||=` on close, so it must be cleared here or a resume
        # reports the previous connection's failure.
        @handshake_error = nil
        @output_mutex.synchronize do
          @output = Deque(Output).new
          @output_bytes = 0_i64
          @output_finished = false
        end
        @output_signal = Channel(Nil).new(1)
        @handshake_done = Channel(Nil).new(1)
        @handshake_notified = false
        @handshake_complete = true
        @gap_since = nil
      end
    end

    # --- transport ---------------------------------------------------------

    private def open_channel(info : SessionInfo) : Int32
      uri = StreamUrl.parse(info.stream_url)
      StreamUrl.validate!(uri, @settings.allow_insecure_endpoint?)
      io = dial(uri)
      ws = HTTP::WebSocket.new(HTTP::WebSocket::Protocol.new(io, masked: true, sync_close: true))
      generation = @state_mutex.synchronize do
        @io = io
        @ws = ws
        @last_progress = Time.instant
        @gap_since = nil
        @generation
      end
      ws.on_binary { |bytes| handle_frame(bytes, generation) }
      ws.on_close { |_code, _message| close!(CloseReason::NetworkLost) if current?(generation) }
      spawn { read_loop(ws, generation) }
      spawn { retransmit_loop(generation) }
      spawn { ping_loop(generation) }
      spawn { liveness_loop(generation) }
      generation
    end

    private def dial(uri : URI) : IO
      host = uri.host
      raise ProtocolError.new("StreamUrl has no host") unless host
      port = uri.port || (uri.scheme == "wss" ? 443 : 80)
      tcp : TCPSocket? = nil
      begin
        # A black-holed gateway must not park connect/resume forever: the
        # liveness fibers only start after the upgrade completes.
        socket = TCPSocket.new(host, port, connect_timeout: @settings.connect_timeout)
        tcp = socket
        # A websocket frame is several small writes and the payload is usually
        # below one MSS. With Nagle on (Crystal's default, unlike Go's) every
        # message waits for the previous one's delayed acknowledgement, which
        # caps a sustained upload at about one MSS per RTT (~30 KiB/s on a
        # typical link). Go's net package, and therefore the reference plugin,
        # disables Nagle by default. See docs/protocol.md.
        socket.tcp_nodelay = @settings.tcp_nodelay?
        # Bound the TLS/client handshake and the upgrade read; the established
        # channel is long-lived and frame pacing is handled by the ping/idle
        # loops, so the timeout is cleared before the socket is returned.
        # Set on the TCP socket: the TLS socket delegates its reads to it.
        socket.read_timeout = @settings.read_timeout
        io = if uri.scheme == "wss"
               context = OpenSSL::SSL::Context::Client.new
               OpenSSL::SSL::Socket::Client.new(socket, context: context, sync_close: true,
                 hostname: host)
             else
               socket
             end

        headers = HTTP::Headers{"Host" => StreamUrl.authority(uri)}
        request = HTTP::Request.new("GET", StreamUrl.request_target(uri), headers)
        unless StreamUrl.presigned?(uri)
          # One resolution: each call may refresh, and a refresh between two
          # calls would mix key material from two credential sets in one
          # signature.
          creds = @client.credentials
          signer = KrikriAwsSigner::Signer.new("ssmmessages", @settings.region,
            creds.access_key, creds.secret_key, creds.session_token)
          signer.sign(request, add_sha: false)
        end

        key = Base64.strict_encode(Random::Secure.random_bytes(16))
        request.headers["Connection"] = "Upgrade"
        request.headers["Upgrade"] = "websocket"
        request.headers["Sec-WebSocket-Version"] = "13"
        request.headers["Sec-WebSocket-Key"] = key

        # The established channel is long-lived and frame pacing comes from
        # the ping/idle loops, so the handshake timeout is cleared here.
        request.to_io(io)
        io.flush
        response = HTTP::Client::Response.from_io(io, ignore_body: true)
        socket.read_timeout = nil
        unless response.status.switching_protocols?
          quietly { socket.close }
          raise HandshakeFailed.new(
            "data-channel upgrade to #{StreamUrl.redact(uri)} returned HTTP #{response.status_code}")
        end
        expected = HTTP::WebSocket::Protocol.key_challenge(key)
        unless response.headers["Sec-WebSocket-Accept"]? == expected
          quietly { socket.close }
          raise HandshakeFailed.new("data-channel upgrade did not return a valid Sec-WebSocket-Accept")
        end
        io
      rescue ex : Socket::Error | OpenSSL::SSL::Error | IO::Error
        # Closing the TCP socket covers a failure before or during the TLS
        # handshake; the TLS socket wraps it with sync_close.
        quietly { tcp.try(&.close) }
        raise HandshakeFailed.new(
          "failed to open data channel #{StreamUrl.redact(uri)}: #{ex.message}", cause: ex)
      end
    end

    private def send_open_message(info : SessionInfo, generation : Int32) : Nil
      payload = JSON.build do |json|
        json.object do
          json.field "MessageSchemaVersion", "1.0"
          json.field "RequestId", UUID.random.to_s
          json.field "TokenValue", info.token_value
          json.field "ClientId", @client_id
          json.field "ClientVersion", @settings.client_version
        end
      end
      send_text(payload, generation)
    end

    private def read_loop(ws : HTTP::WebSocket, generation : Int32) : Nil
      ws.run
    rescue ex : IO::Error | Socket::Error | OpenSSL::SSL::Error
      record_error(ex) if current?(generation)
    ensure
      close!(CloseReason::NetworkLost, generation: generation) if current?(generation)
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
            send_raw(frame, generation)
          end
        rescue ex : Reliability::RetransmissionTimeout
          close!(CloseReason::ProtocolError, ex, generation)
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
        # fibers can interleave frame fragments on the wire. Re-check the
        # generation and take the socket under the state lock: `resume` may
        # have replaced it.
        quietly do
          @send_mutex.synchronize do
            ws, current = @state_mutex.synchronize do
              {@ws, !@closed && @generation == generation}
            end
            ws.ping if ws && current
          end
        end
      end
    end

    private def liveness_loop(generation : Int32) : Nil
      while current?(generation)
        sleep 1.second
        next unless current?(generation)
        # An inbound sequence gap that never heals is a protocol wedge, not
        # an idle session: report it as such instead of waiting for traffic
        # to stop completely. Checked before idle so a wedge is not mislabelled.
        gap_since = @state_mutex.synchronize { @gap_since }
        if gap_since && Time.instant - gap_since > @settings.idle_timeout
          close!(CloseReason::ProtocolError,
            ProtocolError.new("inbound sequence gap did not heal within #{@settings.idle_timeout}"),
            generation)
          break
        end
        # Progress, not traffic: a wedged sequencer whose peer keeps
        # retransmitting buffered or duplicate frames makes no progress.
        last_progress = @state_mutex.synchronize { @last_progress }
        if Time.instant - last_progress > @settings.idle_timeout
          close!(CloseReason::SessionTimeout, generation: generation)
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

    private def handle_frame(bytes : Bytes, generation : Int32) : Nil
      # A frame from the connection `resume` replaced must never touch the
      # resumed session (output, acks or a close).
      return unless current?(generation)
      message = Message.decode(bytes)
      case message.message_type
      when MessageType::OUTPUT_STREAM_DATA
        handle_output_stream(message, generation)
      when MessageType::ACKNOWLEDGE
        ack = AcknowledgeContent.from_json(String.new(message.payload))
        mark_progress if @reliability.acknowledge(ack.sequence_number)
      when MessageType::CHANNEL_CLOSED
        output = ChannelClosedContent.from_json(String.new(message.payload)).output
        @state_mutex.synchronize { @channel_output = output }
        close!(CloseReason::AgentClosed, generation: generation)
      when MessageType::START_PUBLICATION, MessageType::PAUSE_PUBLICATION
        # Advisory only. The reference plugin's OutputMessageHandler ignores
        # both message types, and blocking writes on a real agent's pause
        # throttled input to about 30 KiB/s: see docs/protocol.md.
      else
        # Unknown message types are ignored, matching OutputMessageHandler.
      end
    rescue ex : ProtocolError | JSON::ParseException
      close!(CloseReason::ProtocolError, ex, generation)
    rescue ChannelClosed
      # The session closed while this frame was being processed.
    end

    private def handle_output_stream(message : Message, generation : Int32) : Nil
      acceptance = @inbound.accept(message.sequence_number, message, message.payload.size.to_i64)
      case acceptance.disposition
      when InboundSequencer::Disposition::Delivered
        mark_progress
        @state_mutex.synchronize { @gap_since = nil } if @inbound.buffered.zero?
        acceptance.items.each do |item|
          # The reference processes a frame's handler before acknowledging it,
          # handshake payloads included.
          deliver(item, generation)
          acknowledge(item, generation)
        end
      when InboundSequencer::Disposition::Buffered
        # Buffered frames are acked (there is no other backpressure), so the
        # gap age is the only thing that can notice a stall.
        @state_mutex.synchronize { @gap_since ||= Time.instant }
        acknowledge(message, generation)
      when InboundSequencer::Disposition::Overflow
        # A held-out frame dropped unacked leaves the agent's head waiting;
        # the buffer itself is now meter-bound, so treat it as fatal rather
        # than silently losing data.
        close!(CloseReason::ProtocolError,
          OutputBufferExceeded.new("buffered session output exceeded #{@settings.output_buffer_limit} bytes"),
          generation)
      when InboundSequencer::Disposition::Duplicate
        # No ack: double-acking a duplicate confuses the agent's accounting.
      end
    end

    private def mark_progress : Nil
      @state_mutex.synchronize { @last_progress = Time.instant }
    end

    private def deliver(message : Message, generation : Int32) : Nil
      case message.payload_type
      when PayloadType::HandshakeRequest.value
        handle_handshake_request(message, generation)
      when PayloadType::HandshakeComplete.value
        complete_handshake
      when PayloadType::Output.value
        complete_handshake if !handshake_complete? && session_type.nil?
        emit(Stream::Stdout, payload_bytes(message))
      when PayloadType::StdErr.value
        emit(Stream::Stderr, payload_bytes(message))
      when PayloadType::ExitCode.value
        code = parse_exit_code(payload_bytes(message))
        @state_mutex.synchronize { @exit_code = code }
      when PayloadType::Error.value
        text = String.new(message.payload)
        @state_mutex.synchronize { @channel_output = text }
      when PayloadType::EncChallengeRequest.value
        handle_encryption_challenge(message, generation)
      else
        # Size, Parameter and Flag are not exposed by this byte-stream API.
      end
    end

    # Payload types 1, 11 and 12 are AES-GCM encrypted when KMS is on; the
    # handshake and control payloads stay clear (plugin `streaming.go`).
    private def payload_bytes(message : Message) : Bytes
      encrypter = active_encrypter
      return message.payload unless encrypter && encrypted_payload?(message.payload_type)
      encrypter.decrypt(message.payload)
    end

    # The reader writes @encrypter/@encryption_enabled during the handshake;
    # writer fibers read them. Nil means encryption is not active yet.
    private def active_encrypter : Encrypter?
      @state_mutex.synchronize { @encryption_enabled ? @encrypter : nil }
    end

    private def handshake_complete? : Bool
      @state_mutex.synchronize { @handshake_complete }
    end

    private def encrypted_payload?(payload_type : UInt32) : Bool
      payload_type == PayloadType::Output.value ||
        payload_type == PayloadType::StdErr.value ||
        payload_type == PayloadType::ExitCode.value
    end

    private def handle_encryption_challenge(message : Message, generation : Int32) : Nil
      encrypter = active_encrypter
      unless encrypter
        @state_mutex.synchronize do
          @handshake_error = HandshakeFailed.new(
            "the agent requested an encryption challenge before KMS was negotiated")
        end
        notify_handshake
        close!(CloseReason::ProtocolError, generation: generation)
        return
      end
      # `JSON::Any#[]?` raises a bare `Exception` on a non-object payload,
      # which none of this method's rescues catch; a ProtocolError keeps the
      # failure typed and the close reason accurate.
      object = JSON.parse(String.new(message.payload)).as_h?
      challenge = object.try(&.["Challenge"]?).try(&.as_s?)
      raise ProtocolError.new("EncChallengeRequest is missing Challenge") unless challenge
      plaintext = encrypter.decrypt(Base64.decode(challenge))
      encrypted = encrypter.encrypt(plaintext)
      response = JSON.build do |json|
        json.object { json.field "Challenge", Base64.strict_encode(encrypted) }
      end
      send_input(PayloadType::EncChallengeResponse.value, response.to_slice)
    rescue ex : ProtocolError | Base64::Error | JSON::ParseException
      @state_mutex.synchronize { @handshake_error = ex }
      record_error(ex)
      notify_handshake
      close!(CloseReason::ProtocolError, generation: generation)
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
        record_error(OutputBufferExceeded.new(
          "unread session output exceeded #{@settings.output_buffer_limit} bytes"))
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

    private def handle_handshake_request(message : Message, generation : Int32) : Nil
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
        @state_mutex.synchronize { @handshake_error = failed }
        notify_handshake
        close!(CloseReason::ProtocolError, generation: generation)
      end
    end

    # Run the KMS handshake action: GenerateDataKey, split the key, and return
    # the exact plugin JSON (`KMSCipherTextHash` marshals as null).
    private def enable_kms_encryption(parameters : JSON::Any?) : JSON::Any
      raise HandshakeFailed.new("KMSEncryption action is missing its parameters") unless parameters
      request = Handshake::KMSEncryptionRequest.from_json(parameters.to_json)
      data_key = kms_client.generate_data_key(request.kms_key_id, @session_id, @settings.target)
      @state_mutex.synchronize do
        @encrypter = Encrypter.new(data_key.plaintext)
        @encryption_enabled = true
      end
      JSON.parse(JSON.build do |json|
        json.object do
          json.field "KMSCipherTextKey", Base64.strict_encode(data_key.ciphertext_blob)
          json.field "KMSCipherTextHash", nil
        end
      end)
    end

    private def kms_client : Kms
      # The provider keeps KMS signing with refreshed credentials on a long
      # session instead of the snapshot taken at handshake time.
      @kms ||= Kms.new(-> { @client.credentials }, @settings.region,
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
        @state_mutex.synchronize { @session_type = SessionType::STANDARD_STREAM }
        true
      when SessionType::PORT
        @state_mutex.synchronize { @session_type = request.session_type }
        true
      else
        false
      end
    rescue JSON::ParseException
      false
    end

    private def complete_handshake : Nil
      notify = @state_mutex.synchronize do
        next false if @handshake_complete
        @handshake_complete = true
        true
      end
      notify_handshake if notify
    end

    private def await_handshake : Nil
      select
      when @handshake_done.receive
        error, complete = @state_mutex.synchronize { {@handshake_error, @handshake_complete} }
        raise error if error
        unless complete
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
        if payload_type == PayloadType::Output.value
          if encrypter = active_encrypter
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
        # Track before sending: an ACK can arrive before `send_raw` returns
        # (an in-process peer has ~0 RTT), and an ACK for an untracked
        # sequence is discarded, leaving the frame unacked forever. Roll the
        # entry back when the send fails.
        @reliability.track(sequence, frame)
        begin
          send_raw(frame)
        rescue ex
          @reliability.untrack(sequence)
          raise ex
        end
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

    private def acknowledge(message : Message, generation : Int32) : Nil
      content = AcknowledgeContent.new(
        message.message_type, message.message_id.to_s, message.sequence_number)
      frame = Message.new(
        message_type: MessageType::ACKNOWLEDGE,
        payload: content.to_json.to_slice,
        flags: Flags::ACK,
      ).encode
      send_raw(frame, generation)
    end

    private def send_text(payload : String, generation : Int32? = nil) : Nil
      send_frame_bytes(payload.to_slice, payload, generation)
    end

    private def send_raw(bytes : Bytes, generation : Int32? = nil) : Nil
      send_frame_bytes(bytes, nil, generation)
    end

    # Take the send lock before the state lock (the same order ping_loop
    # uses), then send on the socket that lock saw: `resume` may otherwise
    # swap @ws between the check and the write.
    private def send_frame_bytes(bytes : Bytes, text : String?, generation : Int32?) : Nil
      @send_mutex.synchronize do
        ws, current = @state_mutex.synchronize do
          {@ws, generation.nil? || (@generation == generation && !@closed)}
        end
        raise ChannelClosed.new("session generation is stale") if !current
        raise ChannelClosed.new("session is closed") if ws.nil? || ws.closed?
        text ? ws.send(text) : ws.send(bytes)
      end
    rescue ex : IO::Error
      close!(CloseReason::NetworkLost, ex, generation)
      raise ChannelClosed.new("session channel is closed", cause: ex)
    end

    private def raise_closed : Nil
      raise ChannelClosed.new(
        "session #{@session_id} is closed (#{close_reason || CloseReason::NetworkLost})")
    end

    # --- lifecycle ---------------------------------------------------------

    private def close!(reason : CloseReason, error : Exception? = nil,
                       generation : Int32? = nil) : Nil
      # Snapshot the connection this close belongs to: `resume` may replace
      # @ws/@io/@output_signal while the teardown below is still running, and
      # the old close must never touch the resumed session. A close naming a
      # generation is dropped once that generation has been replaced.
      snapshot = @state_mutex.synchronize do
        next if generation && generation != @generation
        next if @closed
        @closed = true
        @close_reason = reason
        @error = error || @error
        {ws: @ws, io: @io, signal: @output_signal, generation: @generation,
         encrypter: @encrypter}
      end
      return unless snapshot

      @state_mutex.synchronize { @handshake_error ||= error }
      notify_handshake
      @reliability.wake
      quietly { snapshot[:ws].try(&.close) }
      quietly { snapshot[:io].try(&.close) }
      # Key material out of memory as soon as the channel is gone.
      quietly { snapshot[:encrypter].try(&.wipe) }
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
