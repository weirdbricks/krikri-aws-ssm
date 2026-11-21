require "./spec_helper"

describe KrikriAwsSsm::MessageType do
  # Every string is pinned from src/message/clientmessage.go.
  it "matches the reference message type strings" do
    assert_equal "input_stream_data", KrikriAwsSsm::MessageType::INPUT_STREAM_DATA
    assert_equal "output_stream_data", KrikriAwsSsm::MessageType::OUTPUT_STREAM_DATA
    assert_equal "acknowledge", KrikriAwsSsm::MessageType::ACKNOWLEDGE
    assert_equal "channel_closed", KrikriAwsSsm::MessageType::CHANNEL_CLOSED
    assert_equal "start_publication", KrikriAwsSsm::MessageType::START_PUBLICATION
    assert_equal "pause_publication", KrikriAwsSsm::MessageType::PAUSE_PUBLICATION
  end

  it "exempts only start_publication and pause_publication from digest checks" do
    assert KrikriAwsSsm::MessageType.digest_exempt?("start_publication")
    assert KrikriAwsSsm::MessageType.digest_exempt?("pause_publication")
    refute KrikriAwsSsm::MessageType.digest_exempt?("output_stream_data")
    refute KrikriAwsSsm::MessageType.digest_exempt?("acknowledge")
  end
end

describe KrikriAwsSsm::PayloadType do
  it "matches the reference numbers" do
    assert_equal 0_u32, KrikriAwsSsm::PayloadType::Undefined.value
    assert_equal 1_u32, KrikriAwsSsm::PayloadType::Output.value
    assert_equal 2_u32, KrikriAwsSsm::PayloadType::Error.value
    assert_equal 3_u32, KrikriAwsSsm::PayloadType::Size.value
    assert_equal 4_u32, KrikriAwsSsm::PayloadType::Parameter.value
    assert_equal 5_u32, KrikriAwsSsm::PayloadType::HandshakeRequest.value
    assert_equal 6_u32, KrikriAwsSsm::PayloadType::HandshakeResponse.value
    assert_equal 7_u32, KrikriAwsSsm::PayloadType::HandshakeComplete.value
    assert_equal 8_u32, KrikriAwsSsm::PayloadType::EncChallengeRequest.value
    assert_equal 9_u32, KrikriAwsSsm::PayloadType::EncChallengeResponse.value
    assert_equal 10_u32, KrikriAwsSsm::PayloadType::Flag.value
    assert_equal 11_u32, KrikriAwsSsm::PayloadType::StdErr.value
    assert_equal 12_u32, KrikriAwsSsm::PayloadType::ExitCode.value
  end
end

describe KrikriAwsSsm::Flags do
  it "uses SYN=1, FIN=2 and sends both on acknowledgements" do
    assert_equal 1_u64, KrikriAwsSsm::Flags::SYN
    assert_equal 2_u64, KrikriAwsSsm::Flags::FIN
    assert_equal 3_u64, KrikriAwsSsm::Flags::ACK
  end
end

describe KrikriAwsSsm::ActionStatus do
  it "matches the reference numbers" do
    assert_equal 1, KrikriAwsSsm::ActionStatus::Success.value
    assert_equal 2, KrikriAwsSsm::ActionStatus::Failed.value
    assert_equal 3, KrikriAwsSsm::ActionStatus::Unsupported.value
  end
end

describe KrikriAwsSsm::AcknowledgeContent do
  it "serializes with the reference field names and order" do
    ack = KrikriAwsSsm::AcknowledgeContent.new(
      message_type: "output_stream_data",
      message_id: "00112233-4455-6677-8899-aabbccddeeff",
      sequence_number: 7_i64,
    )
    assert_equal(
      %({"AcknowledgedMessageType":"output_stream_data",) +
      %("AcknowledgedMessageId":"00112233-4455-6677-8899-aabbccddeeff",) +
      %("AcknowledgedMessageSequenceNumber":7,"IsSequentialMessage":true}),
      ack.to_json)
  end

  it "parses the acknowledge payload the agent sends" do
    ack = KrikriAwsSsm::AcknowledgeContent.from_json(
      %({"AcknowledgedMessageType":"input_stream_data","AcknowledgedMessageId":"x",) +
      %("AcknowledgedMessageSequenceNumber":42,"IsSequentialMessage":true}))
    assert_equal "input_stream_data", ack.message_type
    assert_equal 42_i64, ack.sequence_number
    assert ack.sequential?
  end
end

describe KrikriAwsSsm::ChannelClosedContent do
  it "parses the reference channel_closed body" do
    content = KrikriAwsSsm::ChannelClosedContent.from_json(
      %({"MessageId":"m","CreatedDate":"123","DestinationId":"i-1","SessionId":"s-1",) +
      %("MessageType":"channel_closed","SchemaVersion":1,"Output":"bye"}))
    assert_equal "s-1", content.session_id
    assert_equal "bye", content.output
  end

  it "tolerates a minimal body" do
    content = KrikriAwsSsm::ChannelClosedContent.from_json(%({"Output":"bye"}))
    assert_equal "bye", content.output
    assert_nil content.session_id
  end
end

describe KrikriAwsSsm::SizeContent do
  it "uses lowercase cols/rows like SizeData" do
    assert_equal %({"cols":80,"rows":24}), KrikriAwsSsm::SizeContent.new(80_u32, 24_u32).to_json
  end
end
