require "base64"
require "http/web_socket"
require "json"
require "../encryption"
require "../handshake"
require "../message"
require "../payload"
require "../reliability"
require "./pty"

module KrikriAwsSsm::Testing
  # An agent-side protocol peer. With `shell` set it drives a real pty; with
  # `shell` nil it stays silent so a spec can send hand-built output, exit
  # codes and channel_closed frames.
  class FakeAgent
    struct Options
      property shell : String? = "/bin/sh"
      property agent_version : String = "3.3.3572.0"
      property session_type : String = "Standard_Stream"
      property kms_key_id : String? = nil
      # The 64-byte data key the fake KMS returns. The agent uses the first
      # half to encrypt and the last half to decrypt (the client mirrors).
      property kms_plaintext_key : Bytes = Bytes.new(64) { |index| (index + 1).to_u8 }
      property? handshake : Bool = true
      # First delivery of these inbound sequences is dropped without an ack,
      # which exercises the client's retransmission queue.
      property drop_first_delivery : Set(Int64) = Set(Int64).new
      # Extra environment for the pty shell (merged over this process's
      # own), so a spec can put a stub `sudo` or a PATH on the "target"
      # without mutating the test process's ENV.
      property shell_env : Hash(String, String)? = nil
    end

    getter open_messages = Channel(JSON::Any).new(8)
    getter handshake_responses = Channel(Handshake::HandshakeResponsePayload).new(8)
    getter received_sequences = Channel(Int64).new(1024)
    getter acknowledged_sequences = Channel(Int64).new(1024)
    getter received_input = Channel(Bytes).new(1024)
    getter challenge_responses = Channel(Bytes).new(4)
    getter pings = Atomic(Int32).new(0)
    # Output frames handed to the socket. Specs use it as a barrier instead of
    # sleeping when they need the client to have buffered output.
    getter outputs_sent = Atomic(Int32).new(0)

    @options : Options
    @out_mutex = Mutex.new
    @send_mutex = Mutex.new
    @ack_mutex = Mutex.new
    @inbound = InboundSequencer(Message).new
    @out_sequence = 0_i64
    @dropped = Set(Int64).new
    @acks_held = false
    @held_acks = [] of AcknowledgeContent
    @stopped = false
    @channel_closed_sent = false
    @handshake_sent = false
    @shell_started = false
    @encrypter : Encrypter?
    @challenge_plaintext : Bytes?
    @pty : Pty?
    @process : Process?
    @pump_done : Channel(Nil)?

    def initialize(@ws : HTTP::WebSocket, @io : IO, @options : Options = Options.new)
    end

    def run : Nil
      @ws.on_ping { @pings.add(1) }
      @ws.on_message { |text| handle_text(text) }
      @ws.on_binary { |bytes| handle_binary(bytes) }
      @ws.run
    ensure
      stop
    end

    # --- frames the client should handle ----------------------------------

    def send_output(bytes : Bytes, payload_type : PayloadType = PayloadType::Output) : Nil
      @outputs_sent.add(1)
      if encrypter = @encrypter
        if [PayloadType::Output.value, PayloadType::StdErr.value, PayloadType::ExitCode.value].includes?(payload_type.value)
          bytes = encrypter.encrypt(bytes)
        end
      end
      send_stream_message(MessageType::OUTPUT_STREAM_DATA, payload_type.value, bytes)
    end

    def send_output(text : String, payload_type : PayloadType = PayloadType::Output) : Nil
      send_output(text.to_slice, payload_type)
    end

    def send_exit_code(code : Int32) : Nil
      send_output("EXIT_CODE: #{code}", PayloadType::ExitCode)
    end

    # Encrypt like the real agent, then corrupt the GCM tag, so the client
    # must reject the payload rather than deliver it.
    def send_corrupted_output(bytes : Bytes) : Nil
      encrypter = @encrypter
      return unless encrypter
      encrypted = encrypter.encrypt(bytes)
      encrypted[encrypted.size - 1] = (encrypted[encrypted.size - 1] ^ 0xff).to_u8
      send_stream_message(MessageType::OUTPUT_STREAM_DATA, PayloadType::Output.value, encrypted)
    end

    def send_channel_closed(output : String = "") : Nil
      payload = JSON.build do |json|
        json.object do
          json.field "MessageId", UUID.random.to_s
          json.field "CreatedDate", Time.utc.to_unix_ms.to_s
          json.field "DestinationId", "i-0123456789"
          json.field "SessionId", "s-1"
          json.field "MessageType", MessageType::CHANNEL_CLOSED
          json.field "SchemaVersion", 1
          json.field "Output", output
        end
      end
      send_stream_message(MessageType::CHANNEL_CLOSED, PayloadType::Undefined.value, payload.to_slice)
      @channel_closed_sent = true
    end

    def pause_publication : Nil
      send_control(MessageType::PAUSE_PUBLICATION)
    end

    def start_publication : Nil
      send_control(MessageType::START_PUBLICATION)
    end

    # Drop the socket without a close frame, for reconnect scenarios.
    def abrupt_close : Nil
      @io.close
    end

    def stop : Nil
      return if @stopped
      @stopped = true
      @pty.try(&.close)
      @process.try do |process|
        process.terminate unless process.terminated?
      end
      @ws.close unless @channel_closed_sent
    rescue
    end

    # Hold acknowledgements so a spec can watch the client's send window fill,
    # then release them in one batch. Messages are still processed; only the
    # acknowledgement frames are deferred.
    def hold_acks : Nil
      @ack_mutex.synchronize { @acks_held = true }
    end

    def release_acks : Nil
      held = @ack_mutex.synchronize do
        @acks_held = false
        contents = @held_acks
        @held_acks = [] of AcknowledgeContent
        contents
      end
      held.each { |content| send_ack(content) }
    end

    # --- inbound ----------------------------------------------------------

    private def handle_text(text : String) : Nil
      open_message = JSON.parse(text)
      observe(@open_messages, open_message)
      if @options.handshake? && !@handshake_sent
        @handshake_sent = true
        send_handshake_request
      end
    end

    private def handle_binary(bytes : Bytes) : Nil
      message = Message.decode(bytes)
      case message.message_type
      when MessageType::INPUT_STREAM_DATA
        handle_input_stream(message)
      when MessageType::ACKNOWLEDGE
        content = AcknowledgeContent.from_json(String.new(message.payload))
        observe(@acknowledged_sequences, content.sequence_number)
      else
        # channel_closed / publication messages from the client are ignored.
      end
    rescue ex : ProtocolError
      send_channel_closed(ex.message.to_s)
    end

    # The observation channels exist for specs, not for the protocol. A
    # transfer that nobody is watching must never stall the websocket
    # reader, so a full buffer drops the sample instead of blocking.
    private def observe(channel : Channel(T), value : T) : Nil forall T
      select
      when channel.send(value)
      else
      end
    end

    private def handle_input_stream(message : Message) : Nil
      sequence = message.sequence_number
      observe(@received_sequences, sequence)
      return unless first_delivery?(sequence)

      acceptance = @inbound.accept(sequence, message)
      case acceptance.disposition
      when InboundSequencer::Disposition::Delivered
        acceptance.items.each do |item|
          acknowledge(item)
          process(item)
        end
      when InboundSequencer::Disposition::Buffered
        acknowledge(message)
      else
        # Duplicate or overflow: do not ack.
      end
    end

    private def first_delivery?(sequence : Int64) : Bool
      @out_mutex.synchronize do
        if @options.drop_first_delivery.includes?(sequence) && !@dropped.includes?(sequence)
          @dropped << sequence
          return false
        end
        true
      end
    end

    private def process(message : Message) : Nil
      case message.payload_type
      when PayloadType::HandshakeResponse.value
        response = Handshake::HandshakeResponsePayload.from_json(String.new(message.payload))
        @handshake_responses.send(response)
        if kms_succeeded?(response)
          @encrypter = mirrored_encrypter
          send_challenge_request
        else
          send_handshake_complete
          start_shell
        end
      when PayloadType::Output.value
        plaintext = decrypted(message.payload)
        observe(@received_input, plaintext)
        @pty.try do |pty|
          pty.master.write(plaintext)
          pty.master.flush
        end
      when PayloadType::EncChallengeResponse.value
        challenge = JSON.parse(String.new(message.payload))["Challenge"]?.try(&.as_s?) || ""
        if encrypter = @encrypter
          plaintext = encrypter.decrypt(Base64.decode(challenge))
          @challenge_plaintext = plaintext
          @challenge_responses.send(plaintext)
        end
        send_handshake_complete
        start_shell
      when PayloadType::Flag.value
        flag = IO::ByteFormat::BigEndian.decode(UInt32, message.payload)
        if flag == 2 # TerminateSession
          send_channel_closed("")
          stop
        end
      when PayloadType::Size.value
        # Terminal size is accepted and ignored unless a spec inspects it.
      else
        # Unknown payloads are ignored.
      end
    end

    private def kms_succeeded?(response : Handshake::HandshakeResponsePayload) : Bool
      response.processed_client_actions.any? do |action|
        action.action_type == ActionType::KMS_ENCRYPTION &&
          action.action_status == ActionStatus::Success.value &&
          action.action_result.try(&.["KMSCipherTextKey"]?).try(&.as_s?)
      end
    end

    private def mirrored_encrypter : Encrypter
      key = @options.kms_plaintext_key
      Encrypter.new(key[32, 32] + key[0, 32])
    end

    private def decrypted(payload : Bytes) : Bytes
      if encrypter = @encrypter
        encrypter.decrypt(payload)
      else
        payload
      end
    end

    private def send_challenge_request : Nil
      encrypter = @encrypter
      return unless encrypter
      challenge = Bytes[99_u8, 104_u8, 97_u8, 108_u8, 108_u8, 101_u8, 110_u8, 103_u8, 101_u8]
      payload = JSON.build do |json|
        json.object { json.field "Challenge", Base64.strict_encode(encrypter.encrypt(challenge)) }
      end
      send_stream_message(MessageType::OUTPUT_STREAM_DATA,
        PayloadType::EncChallengeRequest.value, payload.to_slice)
    end

    # --- outbound ---------------------------------------------------------

    private def send_handshake_request : Nil
      actions = [
        Handshake::RequestedClientAction.new(ActionType::SESSION_TYPE,
          JSON.parse(%({"SessionType":#{@options.session_type.to_json},"Properties":{}}))),
      ]
      if key = @options.kms_key_id
        actions << Handshake::RequestedClientAction.new(ActionType::KMS_ENCRYPTION,
          JSON.parse(%({"KMSKeyId":#{key.to_json},"Challenge":"Y2hhbGxlbmdl"})))
      end
      request = Handshake::HandshakeRequestPayload.new(@options.agent_version, actions)
      send_stream_message(MessageType::OUTPUT_STREAM_DATA,
        PayloadType::HandshakeRequest.value, request.to_json.to_slice)
    end

    private def send_handshake_complete : Nil
      payload = Handshake::HandshakeCompletePayload.from_json(
        %({"HandshakeTimeToComplete":1000000,"CustomerMessage":""}))
      send_stream_message(MessageType::OUTPUT_STREAM_DATA,
        PayloadType::HandshakeComplete.value, payload.to_json.to_slice)
    end

    private def acknowledge(message : Message) : Nil
      content = AcknowledgeContent.new(
        message.message_type, message.message_id.to_s, message.sequence_number)
      held = @ack_mutex.synchronize do
        @held_acks << content if @acks_held
        @acks_held
      end
      send_ack(content) unless held
    end

    private def send_ack(content : AcknowledgeContent) : Nil
      frame = Message.new(
        message_type: MessageType::ACKNOWLEDGE,
        payload: content.to_json.to_slice,
        flags: Flags::ACK,
      ).encode
      send_frame(frame)
    end

    private def send_control(message_type : String) : Nil
      frame = Message.new(message_type: message_type).encode
      send_frame(frame)
    end

    private def send_stream_message(message_type : String, payload_type : UInt32,
                                    payload : Bytes) : Nil
      @send_mutex.synchronize do
        frame = @out_mutex.synchronize do
          sequence = @out_sequence
          @out_sequence += 1
          Message.new(
            message_type: message_type,
            payload: payload,
            payload_type: payload_type,
            sequence_number: sequence,
          ).encode
        end
        @ws.send(frame)
      end
    rescue ex : IO::Error
      @stopped = true
      raise ex
    end

    private def send_frame(bytes : Bytes) : Nil
      @send_mutex.synchronize { @ws.send(bytes) }
    rescue ex : IO::Error
      @stopped = true
      raise ex
    end

    # --- pty shell --------------------------------------------------------

    private def start_shell : Nil
      return if @shell_started
      shell = @options.shell
      return unless shell
      @shell_started = true
      pty = Pty.new
      @pty = pty
      shell_env = {"TERM" => "dumb"}
      @options.shell_env.try &.each { |name, value| shell_env[name] = value }
      @process = Process.new(shell, input: pty.slave, output: pty.slave, error: pty.slave,
        env: shell_env)
      pty.close_slave
      @pump_done = Channel(Nil).new(1)
      spawn { pump_shell_output(pty) }
      spawn { await_shell_exit }
    end

    private def pump_shell_output(pty : Pty) : Nil
      buffer = Bytes.new(4096)
      while (count = pty.master.read(buffer)) > 0
        send_output(buffer[0, count].dup)
      end
    rescue IO::Error
    ensure
      @pump_done.try(&.send(nil))
    end

    private def await_shell_exit : Nil
      process = @process
      return unless process
      status = process.wait
      @pump_done.try(&.receive)
      code = status.normal_exit? ? status.exit_code : 1
      send_exit_code(code)
      send_channel_closed("")
      # The channel_closed frame above hands the shutdown to the client (see
      # #stop): closing the socket here raced it and the client lost both the
      # exit status and the close reason.
      stop
    rescue
    end
  end
end
