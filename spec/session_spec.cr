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
                    ping_interval : Time::Span = 30.seconds) : KrikriAwsSsm::Settings
    KrikriAwsSsm::Settings.new("i-0123456789",
      endpoint_url: gateway.url, allow_insecure_endpoint: true,
      credentials: CREDS, connect_timeout: connect_timeout,
      idle_timeout: idle_timeout, ping_interval: ping_interval)
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

  it "blocks writes while publication is paused and resumes them on start_publication" do
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS)
    gateway.agent_options = SessionSpecData.quiet_agent_options
    begin
      session = KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      begin
        agent = receive_with_timeout(gateway.agents)
        receive_with_timeout(agent.handshake_responses)

        agent.pause_publication
        sleep 100.milliseconds

        written = Channel(Nil).new(1)
        spawn do
          session.write("hi")
          written.send(nil)
        end
        select
        when written.receive
          flunk("write returned while publication was paused")
        when timeout(200.milliseconds)
        end

        agent.start_publication
        select
        when written.receive
        when timeout(2.seconds)
          flunk("write stayed blocked after start_publication")
        end
        assert_equal "hi", String.new(receive_with_timeout(agent.received_input))
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

  it "refuses a KMS encryption request instead of downgrading to plaintext" do
    options = SessionSpecData.quiet_agent_options
    options.kms_key_id = "key-1"
    gateway = KrikriAwsSsm::Testing::FakeGateway.new(SessionSpecData::CREDS, options)
    begin
      error = assert_raises(KrikriAwsSsm::KmsUnsupported) do
        KrikriAwsSsm::Session.open(SessionSpecData.settings(gateway))
      end
      assert_match(/KMS session encryption is not supported/, error.message.to_s)

      agent = receive_with_timeout(gateway.agents)
      response = receive_with_timeout(agent.handshake_responses)
      assert_equal 2, response.processed_client_actions.last.action_status
      assert_equal true, response.errors.try(&.any?(&.includes?("not supported")))
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
        deadline = Time.monotonic + 5.seconds
        while Time.monotonic < deadline
          chunk = read_with_timeout(session, deadline - Time.monotonic).try(&.bytes)
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
end
