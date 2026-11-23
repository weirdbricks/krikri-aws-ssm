require "./spec_helper"

module SessionSpecData
  CREDS = KrikriAwsSsm::Credentials.new("AKIDEXAMPLE", "secretEXAMPLEKEY", "session-token")

  def self.quiet_agent_options : KrikriAwsSsm::Testing::FakeAgent::Options
    options = KrikriAwsSsm::Testing::FakeAgent::Options.new
    options.shell = nil
    options
  end

  def self.settings(gateway : KrikriAwsSsm::Testing::FakeGateway,
                    connect_timeout : Time::Span = 5.seconds,
                    idle_timeout : Time::Span = 5.seconds,
                    ping_interval : Time::Span = 30.seconds,
                    kms_endpoint_url : String? = nil) : KrikriAwsSsm::Settings
    KrikriAwsSsm::Settings.new("i-0123456789",
      endpoint_url: gateway.url, kms_endpoint_url: kms_endpoint_url,
      allow_insecure_endpoint: true,
      credentials: CREDS, connect_timeout: connect_timeout,
      idle_timeout: idle_timeout, ping_interval: ping_interval)
  end

  # Settings without a gateway, for specs that never touch the network.
  def self.settings_without_gateway : KrikriAwsSsm::Settings
    KrikriAwsSsm::Settings.new("i-0123456789", credentials: CREDS)
  end
end

describe KrikriAwsSsm::Session do
  it "verifies the upgrade signature over the exact Host header" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        result = receive_with_timeout(gateway.upgrade_results)
        assert_equal ["host", "x-amz-date", "x-amz-security-token"], result.signed_headers
        request = receive_with_timeout(gateway.upgrade_requests)
        assert_equal "127.0.0.1:#{gateway.port}", request.headers["Host"]
        assert_equal "websocket", request.headers["Upgrade"]
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "redacts the stream URL and token from inspect" do
    settings = SessionSpecData.settings_without_gateway
    client = KrikriAwsSsm::Client.new(settings)
    info = KrikriAwsSsm::SessionInfo.new("s-1",
      "wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/s-1?X-Amz-Signature=deadbeef",
      "secret-token")
    text = KrikriAwsSsm::Session.new(settings, client, info).inspect
    refute_includes text, "secret-token"
    refute_includes text, "X-Amz-Signature"
    assert_includes text, "s-1"
  end

  it "bounds the data-channel upgrade read by the read timeout" do
    listener = TCPServer.new("127.0.0.1", 0)
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS,
      SessionSpecData.quiet_agent_options)
    gateway.stream_url_override =
      "ws://127.0.0.1:#{listener.local_address.port}/data-channel/s-fake-1"
    settings = KrikriAwsSsm::Settings.new("i-0123456789",
      endpoint_url: gateway.url, allow_insecure_endpoint: true,
      credentials: SessionSpecData::CREDS, connect_timeout: 2.seconds,
      read_timeout: 200.milliseconds)
    begin
      started = Time.instant
      error = assert_raises(KrikriAwsSsm::HandshakeFailed) do
        KrikriAwsSsm::Session.open(settings)
      end
      assert_includes error.message.to_s, "failed to open data channel"
      elapsed = Time.instant - started
      assert elapsed >= 200.milliseconds
      assert elapsed < 3.seconds
    ensure
      listener.close
      gateway.close
    end
  end

  it "waits for an upgrade result with a timeout" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        result = gateway.next_upgrade_result
        assert_equal ["host", "x-amz-date", "x-amz-security-token"], result.try(&.signed_headers)
        assert_nil gateway.next_upgrade_result(50.milliseconds)
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "disables Nagle on the data-channel socket" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        # A frame is several small writes below one MSS; with Nagle on, a
        # sustained upload runs at about one MSS per delayed-ACK round trip.
        assert session.transport.as(TCPSocket).tcp_nodelay?
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "leaves Nagle on when the setting disables it, so an A/B can measure it" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      settings = SessionSpecData.settings(gateway)
      settings.tcp_nodelay = false
      session = KrikriAwsSsm::Session.open(settings)
      begin
        refute session.transport.as(TCPSocket).tcp_nodelay?
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "completes the handshake and separates stdout, stderr, exit code and channel_closed" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        response = receive_with_timeout(agent.handshake_responses)
        assert_equal "1.0.0", response.client_version
        assert_equal 1, response.processed_client_actions.first.action_status
        assert_nil response.errors
        assert_equal "Standard_Stream", session.session_type

        open_message = receive_with_timeout(agent.open_messages)
        assert_equal "1.0", open_message["MessageSchemaVersion"].as_s
        assert_equal "fake-token-1", open_message["TokenValue"].as_s
        assert_equal session.client_id, open_message["ClientId"].as_s

        agent.send_output("hello\n")
        stdout = read_required(session)
        assert_equal KrikriAwsSsm::Stream::Stdout, stdout.stream
        assert_equal "hello\n", String.new(stdout.bytes)

        agent.send_output("oops\n", KrikriAwsSsm::PayloadType::StdErr)
        stderr = read_required(session)
        assert_equal KrikriAwsSsm::Stream::Stderr, stderr.stream
        assert_equal "oops\n", String.new(stderr.bytes)

        agent.send_exit_code(3)
        agent.send_channel_closed("bye")

        assert_nil read_with_timeout(session)
        assert_equal 3, session.exit_code
        assert_equal "bye", session.channel_output
        assert_equal KrikriAwsSsm::CloseReason::AgentClosed, session.close_reason
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "drains buffered output before reporting a closed session" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)

        agent.send_output("last")
        agent.send_channel_closed("")
        assert_equal "last", String.new(read_required(session).bytes)
        assert_nil read_with_timeout(session)
        assert_equal KrikriAwsSsm::CloseReason::AgentClosed, session.close_reason
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "chunks input into 1024-byte input_stream_data frames" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)
        # The handshake response is stream sequence 0.
        assert_equal 0_i64, receive_with_timeout(agent.received_sequences)

        payload = Bytes.new(2500) { |index| (index % 251).to_u8 }
        session.write(payload)

        chunks = Array(Bytes).new
        3.times { chunks << receive_with_timeout(agent.received_input) }
        assert_equal [1024, 1024, 452], chunks.map(&.size)
        assert_equal payload, chunks.reduce(Bytes.empty) { |acc, chunk| acc + chunk }
        assert_equal [1_i64, 2_i64, 3_i64], [
          receive_with_timeout(agent.received_sequences),
          receive_with_timeout(agent.received_sequences),
          receive_with_timeout(agent.received_sequences),
        ]
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "retransmits an unacknowledged message until the agent acks it" do
    options = SessionSpecData.quiet_agent_options
    options.drop_first_delivery = Set{1_i64}
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS, options)
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)
        assert_equal 0_i64, receive_with_timeout(agent.received_sequences)

        session.write("hi\n")

        assert_equal 1_i64, receive_with_timeout(agent.received_sequences)
        assert_equal 1_i64, receive_with_timeout(agent.received_sequences)
        assert_equal "hi\n", String.new(receive_with_timeout(agent.received_input))
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "rewrites a lone LF for write and leaves it alone for write_raw" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)

        # The reference plugin's pty workaround: a chunk that is exactly LF
        # becomes CR so the line discipline submits it as Enter.
        session.write(Bytes[10_u8])
        assert_equal Bytes[13_u8], receive_with_timeout(agent.received_input)

        # A binary stream (rsync's protocol) must reach the pty untouched.
        session.write_raw(Bytes[10_u8])
        assert_equal Bytes[10_u8], receive_with_timeout(agent.received_input)
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "passes a multi-chunk binary write_raw stream untouched" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    settings = KrikriAwsSsm::Settings.new("i-0123456789",
      endpoint_url: gateway.url, allow_insecure_endpoint: true,
      credentials: SessionSpecData::CREDS, connect_timeout: 5.seconds,
      idle_timeout: 5.seconds, chunk_size: 3)
    begin
      session = KrikriAwsSsm::Session.open(settings)
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)

        payload = Bytes[0_u8, 10_u8, 13_u8, 10_u8, 255_u8, 65_u8, 0_u8, 10_u8]
        session.write_raw(payload)

        received = Bytes.empty
        (payload.size // 3 + 1).times do
          received += receive_with_timeout(agent.received_input)
        end
        assert_equal payload, received
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "delivers the shell's exit code and AgentClosed when the shell exits" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)

        session.write("exit 3\n")
        while session.read?
        end

        assert_equal 3, session.exit_code
        assert_equal KrikriAwsSsm::CloseReason::AgentClosed, session.close_reason
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "moves a 1MiB payload in both directions" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)
        assert_equal 0_i64, receive_with_timeout(agent.received_sequences)

        payload = Bytes.new(1_048_576) { |index| (index % 253).to_u8 }
        writer = Channel(Exception?).new(1)
        spawn do
          session.write(payload)
          writer.send(nil)
        rescue ex
          writer.send(ex)
        end

        received = Bytes.new(payload.size)
        offset = 0
        while offset < payload.size
          chunk = receive_with_timeout(agent.received_input, 10.seconds)
          chunk.copy_to(received[offset, chunk.size])
          offset += chunk.size
        end
        assert_equal payload, received
        assert_nil receive_with_timeout(writer, 10.seconds)

        agent.send_output(payload)
        collected = IO::Memory.new(payload.size)
        while collected.pos < payload.size
          output = read_required(session, 10.seconds)
          collected.write(output.bytes)
        end
        assert_equal payload, collected.to_slice
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "keeps writing while publication is paused, matching the reference plugin" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)

        # streaming.go's OutputMessageHandler returns nil for both message
        # types; blocking here throttled a real agent to ~30 KiB/s.
        agent.pause_publication
        sleep 100.milliseconds
        session.write("hi")
        assert_equal "hi", String.new(receive_with_timeout(agent.received_input))

        agent.start_publication
        session.write("bye")
        assert_equal "bye", String.new(receive_with_timeout(agent.received_input))
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "sends websocket pings on the configured interval" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(
        SessionSpecData.settings(gateway, ping_interval: 50.milliseconds))
      begin
        agent = receive_with_timeout(gateway.agents)
        assert wait_until(2.seconds) { agent.pings.get > 0 }
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "closes with SessionTimeout when no inbound frame arrives before the idle deadline" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(
        SessionSpecData.settings(gateway, idle_timeout: 100.milliseconds))
      begin
        receive_with_timeout(gateway.agents)
        assert wait_until(3.seconds) { session.closed? }
        assert_equal KrikriAwsSsm::CloseReason::SessionTimeout, session.close_reason
        assert_nil read_with_timeout(session)
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "closes with ProtocolError when an inbound gap does not heal" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(
        SessionSpecData.settings(gateway, idle_timeout: 200.milliseconds))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)

        # Skip the next sequence: the frame after it is buffered, acked and
        # can never be delivered, so the session must not look alive.
        agent.send_output("ahead", sequence: agent.next_output_sequence + 1)

        assert wait_until(3.seconds) { session.closed? }
        assert_equal KrikriAwsSsm::CloseReason::ProtocolError, session.close_reason
        assert_includes session.error.to_s, "inbound sequence gap"
        assert_nil read_with_timeout(session)
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "terminates on the control plane and closes the channel idempotently" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      receive_with_timeout(gateway.agents)
      session.terminate

      assert_equal "s-fake-1", receive_with_timeout(gateway.terminated_sessions)
      assert session.closed?
      assert_equal KrikriAwsSsm::CloseReason::Terminated, session.close_reason
      assert_nil read_with_timeout(session)
      session.terminate
    ensure
      gateway.close
    end
  end

  it "answers SSM control-plane actions with the configured failure" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.control_failure = {400,
                               %({"__type":"TargetNotConnected","message":"i-0123456789 is not connected"})}
    begin
      error = assert_raises(KrikriAwsSsm::TargetNotConnected) do
        KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      end
      assert_includes error.message.to_s, "is not connected"
    ensure
      gateway.close
    end
  end

  it "runs a real pty shell" do
    options = SessionSpecData.quiet_agent_options
    options.shell = "/bin/sh"
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS, options)
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        receive_with_timeout(gateway.agents)
        session.write("echo krikri-ssm-pty\n")

        output = ""
        deadline = Time.instant + 5.seconds
        while Time.instant < deadline
          chunk = read_with_timeout(session, deadline - Time.instant).try(&.bytes)
          break unless chunk
          output += String.new(chunk)
          break if output.includes?("krikri-ssm-pty")
        end
        assert_includes output, "krikri-ssm-pty"
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "passes shell_env to the pty shell" do
    options = SessionSpecData.quiet_agent_options
    options.shell = "/bin/sh"
    options.shell_env = {"KRIKRI_SSM_TEST_ENV" => "from-harness"}
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS, options)
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        receive_with_timeout(gateway.agents)
        session.write("printf '%s\\n' \"$KRIKRI_SSM_TEST_ENV\"\n")

        output = ""
        deadline = Time.instant + 5.seconds
        while Time.instant < deadline
          chunk = read_with_timeout(session, deadline - Time.instant).try(&.bytes)
          break unless chunk
          output += String.new(chunk)
          break if output.includes?("from-harness")
        end
        assert_includes output, "from-harness"
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "streams input larger than the agent's observation buffers" do
    options = SessionSpecData.quiet_agent_options
    options.shell = "/bin/sh"
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS, options)
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        receive_with_timeout(gateway.agents)
        line = "a" * 3000
        lines = 512
        total = (line.bytesize + 1) * lines
        session.write("stty -echo 2>/dev/null; head -c #{total} > /dev/null; " \
                      "printf 'STREAM-%s\\n' DONE\n")
        spawn do
          lines.times { session.write(line + "\n") }
        rescue
        end

        output = ""
        deadline = Time.instant + 30.seconds
        while Time.instant < deadline
          chunk = read_with_timeout(session, deadline - Time.instant).try(&.bytes)
          break unless chunk
          output += String.new(chunk)
          break if output.includes?("STREAM-DONE")
        end
        assert_includes output, "STREAM-DONE"
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "keeps processing acknowledgements while output is unread" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        # Unread output must not wedge the websocket reader: during an
        # upload nothing calls Session#read?, and the reader still has to
        # consume the agent's acknowledgements.
        10.times { agent.send_output("unread") }
        sleep 100.milliseconds
        session.write("after-output")
        assert wait_until(3.seconds) { session.pending == 0 }
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "keeps processing client input after many agent outputs" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        outputs = 1_100
        outputs.times { agent.send_output("x") }
        outputs.times { read_required(session) }

        session.write("after-acks")
        assert_equal "after-acks",
          String.new(receive_with_timeout(agent.received_input))
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "keeps acknowledging input while far more output is unread than the old queue held" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)

        # A bounded output queue (1024 frames) blocked the websocket reader
        # here, so the agent's acknowledgements were never consumed and an
        # upload's send window could never drain. Wait until the agent has
        # handed every frame to the socket: more than the old queue held, so
        # the old code's reader is parked and fails the pending assertion
        # instead of hanging the test.
        spawn do
          1_500.times { agent.send_output("x" * 1024) }
        rescue
        end
        assert wait_until(5.seconds) { agent.outputs_sent.get >= 1_500 },
          "the agent could not hand its output to the socket"

        session.write("after-output")
        assert wait_until(10.seconds) { session.pending == 0 },
          "acknowledgements stopped while output was unread"
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "waits for acknowledgements instead of dropping the oldest unacked message" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      settings = SessionSpecData.settings(gateway)
      settings.send_window_bytes = 2048
      session = KrikriAwsSsm::Session.open(settings)
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)
        agent.hold_acks

        writer = Channel(Exception?).new(1)
        spawn do
          session.write(Bytes.new(4 * 1024))
          writer.send(nil)
        rescue ex
          writer.send(ex)
        end

        assert wait_until(2.seconds) { session.pending == 2 }
        select
        when _ = writer.receive
          flunk "write returned while the send window was full"
        when timeout(200.milliseconds)
        end

        agent.release_acks
        select
        when error = writer.receive
          assert_nil error
        when timeout(5.seconds)
          flunk "write did not resume after acknowledgements were released"
        end
        assert wait_until(3.seconds) { session.pending == 0 }
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "closes a session whose acknowledgements stall while output keeps flowing" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      settings = SessionSpecData.settings(gateway, idle_timeout: 300.milliseconds)
      settings.send_window_bytes = 1024
      session = KrikriAwsSsm::Session.open(settings)
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)
        agent.hold_acks

        # Keep inbound frames arriving so the idle deadline never fires; only
        # the missing acknowledgement can explain the close.
        spawn do
          loop do
            agent.send_output(".")
            sleep 20.milliseconds
          end
        rescue
        end

        writer = Channel(Exception?).new(1)
        spawn do
          session.write(Bytes.new(4 * 1024))
          writer.send(nil)
        rescue ex
          writer.send(ex)
        end
        assert wait_until(2.seconds) { session.pending == 1 }

        assert wait_until(5.seconds) { session.closed? }
        assert_equal KrikriAwsSsm::CloseReason::SessionTimeout, session.close_reason
        assert_match(/no acknowledgement/,
          session.error.try(&.message).to_s)
        select
        when error = writer.receive
          assert_instance_of KrikriAwsSsm::ChannelClosed, error
        when timeout(5.seconds)
          flunk "write stayed blocked after the session closed"
        end
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "fails the session when unread output exceeds its buffer limit" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      settings = SessionSpecData.settings(gateway)
      settings.output_buffer_limit = 16
      session = KrikriAwsSsm::Session.open(settings)
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)

        3.times do
          agent.send_output("0123456789")
        rescue
          break
        end
        assert wait_until(3.seconds) { session.closed? }
        assert_instance_of KrikriAwsSsm::OutputBufferExceeded, session.error
        assert_equal KrikriAwsSsm::CloseReason::ProtocolError, session.close_reason
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "verifies control-plane and upgrade signatures in the configured region" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS,
      region: "us-west-2")
    gateway.agent_options = SessionSpecData.quiet_agent_options
    settings = KrikriAwsSsm::Settings.new("i-0123456789", region: "us-west-2",
      endpoint_url: gateway.url, allow_insecure_endpoint: true,
      credentials: SessionSpecData::CREDS, connect_timeout: 5.seconds,
      idle_timeout: 5.seconds)
    begin
      session = KrikriAwsSsm::Session.open(settings)
      begin
        result = gateway.next_upgrade_result
        refute_nil result
        assert_equal "us-west-2", settings.region
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "keeps its state safe to read while another fiber closes it" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        receive_with_timeout(gateway.agents)
        done = Atomic(Int32).new(0)
        4.times do
          spawn do
            20.times do
              session.close_reason
              session.error
              session.exit_code
              session.channel_output
              session.session_type
              session.encryption_enabled?
              session.closed?
              sleep 1.millisecond
            end
            done.add(1)
          end
        end
        session.terminate
        assert wait_until(2.seconds) { done.get == 4 }
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "skips SigV4 signing for a presigned StreamUrl" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS,
      presigned: true)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        request = receive_with_timeout(gateway.upgrade_requests)
        assert_nil request.headers["Authorization"]?
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "resumes a dropped channel with a fresh token and re-sends the open message" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        first_agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(first_agent.handshake_responses)

        first_agent.abrupt_close
        assert wait_until(2.seconds) { session.closed? }
        assert_equal KrikriAwsSsm::CloseReason::NetworkLost, session.close_reason

        resumed_options = SessionSpecData.quiet_agent_options
        resumed_options.handshake = false
        gateway.agent_options = resumed_options

        session.resume
        assert_equal "s-fake-1", receive_with_timeout(gateway.resumed_sessions)
        second_agent = receive_with_timeout(gateway.agents)
        open_message = receive_with_timeout(second_agent.open_messages)
        assert_equal "fake-token-2", open_message["TokenValue"].as_s
        refute session.closed?
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end
  it "delivers output that arrives on the resumed channel" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        first_agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(first_agent.handshake_responses)
        # The sequence state survives a resume, so the new fake agent must
        # continue numbering where the old one stopped.
        next_sequence = first_agent.next_output_sequence
        first_agent.abrupt_close
        assert wait_until(2.seconds) { session.closed? }

        resumed_options = SessionSpecData.quiet_agent_options
        resumed_options.handshake = false
        gateway.agent_options = resumed_options
        session.resume
        second_agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(second_agent.open_messages)

        second_agent.send_output("after\n", sequence: next_sequence)
        assert_equal "after\n", String.new(read_required(session).bytes)
        refute session.closed?
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "re-closes the session when resume cannot reopen the channel" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        first_agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(first_agent.handshake_responses)
        first_agent.abrupt_close
        assert wait_until(2.seconds) { session.closed? }

        gateway.stream_url_override = "ws://127.0.0.1:1/data-channel/s-fake-1"
        error = assert_raises(KrikriAwsSsm::HandshakeFailed) { session.resume }
        assert_includes error.message.to_s, "failed to open data channel"
        assert session.closed?
        refute_nil session.error
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "terminates on the control plane after the channel was lost" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)
        agent.abrupt_close
        assert wait_until(2.seconds) { session.closed? }
        assert_equal KrikriAwsSsm::CloseReason::NetworkLost, session.close_reason

        session.terminate
        assert_equal "s-fake-1", receive_with_timeout(gateway.terminated_sessions)
        assert_equal KrikriAwsSsm::CloseReason::NetworkLost, session.close_reason
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end
end

describe "KrikriAwsSsm::Session KMS encryption" do
  it "negotiates KMS, mirrors the challenge and encrypts both directions" do
    options = SessionSpecData.quiet_agent_options
    options.kms_key_id = "key-1"
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS, options)
    begin
      session = KrikriAwsSsm::Session.open(
        SessionSpecData.settings(gateway, kms_endpoint_url: gateway.url))
      begin
        agent = receive_with_timeout(gateway.agents)
        response = receive_with_timeout(agent.handshake_responses)
        kms_action = response.processed_client_actions.find do |action|
          action.action_type == KrikriAwsSsm::ActionType::KMS_ENCRYPTION
        end
        refute_nil kms_action
        kms_action = kms_action.as(KrikriAwsSsm::Handshake::ProcessedClientAction)
        assert_equal KrikriAwsSsm::ActionStatus::Success.value, kms_action.action_status
        result = kms_action.action_result
        refute_nil result
        result = result.as(JSON::Any)
        assert_equal Base64.strict_encode(gateway.kms_ciphertext_blob),
          result["KMSCipherTextKey"].as_s
        assert result["KMSCipherTextHash"].raw.nil?
        assert_equal(
          %({"KMSCipherTextKey":"#{Base64.strict_encode(gateway.kms_ciphertext_blob)}",) +
          %("KMSCipherTextHash":null}),
          result.to_json)
        assert session.encryption_enabled?

        challenge = receive_with_timeout(agent.challenge_responses)
        assert_equal "challenge", String.new(challenge)

        session.write("hello\n")
        assert_equal "hello\n", String.new(receive_with_timeout(agent.received_input))

        agent.send_output("out\n")
        assert_equal "out\n", String.new(read_required(session).bytes)
        agent.send_output("err\n", KrikriAwsSsm::PayloadType::StdErr)
        stderr = read_required(session)
        assert_equal KrikriAwsSsm::Stream::Stderr, stderr.stream
        assert_equal "err\n", String.new(stderr.bytes)

        agent.send_exit_code(7)
        agent.send_channel_closed("bye")
        assert_nil read_with_timeout(session)
        assert_equal 7, session.exit_code

        kms_request = receive_with_timeout(gateway.kms_requests)
        body = JSON.parse(kms_request.body || "")
        assert_equal 64, body["NumberOfBytes"].as_i
        assert_equal "s-fake-1", body["EncryptionContext"]["aws:ssm:SessionId"].as_s
        assert_equal "i-0123456789", body["EncryptionContext"]["aws:ssm:TargetId"].as_s
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end

  it "fails the handshake on a non-object encryption challenge payload" do
    options = SessionSpecData.quiet_agent_options
    options.kms_key_id = "key-1"
    options.challenge_payload = %(["nope"])
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS, options)
    begin
      error = assert_raises(KrikriAwsSsm::ProtocolError) do
        KrikriAwsSsm::Session.open(
          SessionSpecData.settings(gateway, kms_endpoint_url: gateway.url))
      end
      assert_equal "EncChallengeRequest is missing Challenge", error.message
    ensure
      gateway.close
    end
  end

  it "fails the handshake when KMS denies GenerateDataKey instead of downgrading" do
    options = SessionSpecData.quiet_agent_options
    options.kms_key_id = "key-1"
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS, options)
    kms_server = TestHttpServer.new do |_request|
      TestHttpResponse.new(403,
        %({"__type":"AccessDeniedException","message":"no kms:GenerateDataKey"}))
    end
    begin
      error = assert_raises(KrikriAwsSsm::HandshakeFailed) do
        KrikriAwsSsm::Session.open(
          SessionSpecData.settings(gateway, kms_endpoint_url: kms_server.url))
      end
      assert_includes error.message.to_s, "Failed to process action KMSEncryption"
      assert_includes error.message.to_s, "no kms:GenerateDataKey"

      agent = receive_with_timeout(gateway.agents)
      response = receive_with_timeout(agent.handshake_responses)
      kms_action = response.processed_client_actions.find do |action|
        action.action_type == KrikriAwsSsm::ActionType::KMS_ENCRYPTION
      end
      refute_nil kms_action
      assert_equal KrikriAwsSsm::ActionStatus::Failed.value,
        kms_action.as(KrikriAwsSsm::Handshake::ProcessedClientAction).action_status
      refute_nil response.errors
    ensure
      kms_server.close
      gateway.close
    end
  end

  it "closes with ProtocolError when an encrypted payload fails authentication" do
    options = SessionSpecData.quiet_agent_options
    options.kms_key_id = "key-1"
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS, options)
    begin
      session = KrikriAwsSsm::Session.open(
        SessionSpecData.settings(gateway, kms_endpoint_url: gateway.url))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)
        receive_with_timeout(agent.challenge_responses)

        agent.send_corrupted_output("should not be delivered".to_slice)

        assert wait_until(3.seconds) { session.closed? }
        assert_equal KrikriAwsSsm::CloseReason::ProtocolError, session.close_reason
        assert session.error.is_a?(KrikriAwsSsm::ProtocolError)
      ensure
        session.terminate
      end
    ensure
      gateway.close
    end
  end
end
