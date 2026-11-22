require "./spec_helper"

describe KrikriAwsSsm::Chunker do
  it "returns no chunks for empty input" do
    assert_empty KrikriAwsSsm::Chunker.chunks(Bytes.empty, 4)
  end

  it "returns the input unchanged when it fits" do
    assert_equal [Bytes[1, 2, 3]], KrikriAwsSsm::Chunker.chunks(Bytes[1, 2, 3], 4)
  end

  it "splits at the configured payload size" do
    bytes = Bytes.new(10, &.to_u8)
    chunks = KrikriAwsSsm::Chunker.chunks(bytes, 4)
    assert_equal [4, 4, 2], chunks.map(&.size)
    assert_equal bytes, chunks.reduce(Bytes.empty) { |acc, chunk| acc + chunk }
  end

  it "rejects a non-positive chunk size" do
    assert_raises(ArgumentError) { KrikriAwsSsm::Chunker.chunks(Bytes[1], 0) }
  end
end

describe KrikriAwsSsm::Reliability do
  it "retransmits only the head after the initial 200ms RTO" do
    clock = Time::Span.zero
    reliability = KrikriAwsSsm::Reliability.new(now: -> { clock })
    first = reliability.allocate
    second = reliability.allocate
    reliability.track(first, Bytes[1])
    reliability.track(second, Bytes[2])

    clock += 150.milliseconds
    assert_nil reliability.retransmission
    clock += 60.milliseconds
    assert_equal Bytes[1], reliability.retransmission
    assert_equal 1, reliability.attempts_for(first)
    assert_equal 0, reliability.attempts_for(second)
    assert_equal [first, second], reliability.pending_sequences
  end

  it "updates the RTO with the Jacobson/Karels formula" do
    clock = Time::Span.zero
    reliability = KrikriAwsSsm::Reliability.new(now: -> { clock })
    sequence = reliability.allocate
    reliability.track(sequence, Bytes[1])
    clock += 210.milliseconds

    assert reliability.acknowledge(sequence)
    # srtt = 113.75ms, rttvar = 27.5ms, rto = srtt + 4*rttvar = 223.75ms
    assert_equal 113.75.milliseconds, reliability.srtt
    assert_equal 27.5.milliseconds, reliability.rtt_variation
    assert_equal 223.75.milliseconds, reliability.retransmission_timeout
    assert_equal 0, reliability.pending
  end

  it "clamps the RTO to 50ms..1s, matching config.go's MaxTransmissionTimeout" do
    clock = Time::Span.zero
    reliability = KrikriAwsSsm::Reliability.new(now: -> { clock })
    50.times do
      fast = reliability.allocate
      reliability.track(fast, Bytes[1])
      clock += 1.millisecond
      reliability.acknowledge(fast)
    end
    assert_equal 50.milliseconds, reliability.retransmission_timeout

    slow = reliability.allocate
    reliability.track(slow, Bytes[2])
    clock += 2.minutes
    reliability.acknowledge(slow)
    assert_equal 1.second, reliability.retransmission_timeout
  end

  it "keeps every unacknowledged message instead of dropping the oldest" do
    reliability = KrikriAwsSsm::Reliability.new
    capacity = KrikriAwsSsm::Reliability::OUTGOING_BUFFER_CAPACITY
    (capacity + 5).times do
      reliability.track(reliability.allocate, Bytes[1])
    end

    # The reference plugin drops the head here, which abandons a message the
    # agent is still waiting for; the writer waits for room instead.
    assert_equal capacity + 5, reliability.pending
    assert_equal 0_i64, reliability.pending_sequences.first
  end

  it "reports transfer statistics and wakes a writer when an ack frees room" do
    clock = Time::Span.zero
    reliability = KrikriAwsSsm::Reliability.new(now: -> { clock })
    sequence = reliability.allocate
    reliability.track(sequence, Bytes.new(10))
    clock += 25.milliseconds

    assert_equal 1_i64, reliability.stats.messages_sent
    assert_equal 10_i64, reliability.stats.bytes_sent
    assert_equal 10_i64, reliability.stats.pending_bytes
    assert_equal 1, reliability.stats.peak_pending

    assert reliability.acknowledge(sequence)
    stats = reliability.stats
    assert_equal 1_i64, stats.acks
    assert_equal 10_i64, stats.bytes_acked
    assert_equal 0_i64, stats.pending_bytes
    assert_equal 1, stats.ack_samples
    assert_equal 25.milliseconds, stats.ack_min
    assert_equal 0, stats.pending
    assert stats.acks_per_second > 0.0
  end

  it "does not sample the round trip of a retransmitted message" do
    clock = Time::Span.zero
    reliability = KrikriAwsSsm::Reliability.new(now: -> { clock })
    sequence = reliability.allocate
    reliability.track(sequence, Bytes[1])
    clock += 300.milliseconds
    reliability.retransmission
    clock += 20.milliseconds
    reliability.acknowledge(sequence)

    assert_equal 0, reliability.stats.ack_samples
    assert_equal 1_i64, reliability.stats.retransmissions
  end

  it "returns false for an already acknowledged sequence" do
    clock = Time::Span.zero
    reliability = KrikriAwsSsm::Reliability.new(now: -> { clock })
    sequence = reliability.allocate
    reliability.track(sequence, Bytes[1])
    assert reliability.acknowledge(sequence)
    refute reliability.acknowledge(sequence)
  end

  it "gives up after the configured attempt count" do
    clock = Time::Span.zero
    reliability = KrikriAwsSsm::Reliability.new(1, -> { clock })
    sequence = reliability.allocate
    reliability.track(sequence, Bytes[1])
    clock += 1.second
    assert_equal Bytes[1], reliability.retransmission
    clock += 1.second
    error = assert_raises(KrikriAwsSsm::Reliability::RetransmissionTimeout) do
      reliability.retransmission
    end
    assert_match(/message 0 was resent 1 times/, error.message.to_s)
  end

  it "issues every sequence exactly once under concurrent allocation" do
    reliability = KrikriAwsSsm::Reliability.new
    results = Channel(Array(Int64)).new(4)
    4.times do
      spawn do
        values = Array(Int64).new(500)
        500.times { values << reliability.allocate }
        results.send(values)
      end
    end
    all = Array(Int64).new(2000)
    4.times { all.concat(results.receive) }
    assert_equal 2000, all.size
    assert_equal 2000, all.uniq.size
    assert_equal (0_i64...2000_i64).to_a, all.sort
  end
end

describe KrikriAwsSsm::InboundSequencer do
  it "delivers in order and drains buffered messages" do
    sequencer = KrikriAwsSsm::InboundSequencer(String).new
    assert_equal KrikriAwsSsm::InboundSequencer::Disposition::Buffered,
      sequencer.accept(1_i64, "b").disposition
    acceptance = sequencer.accept(0_i64, "a")
    assert_equal KrikriAwsSsm::InboundSequencer::Disposition::Delivered, acceptance.disposition
    assert_equal ["a", "b"], acceptance.items
    assert_equal 2_i64, sequencer.expected
    assert_equal 0, sequencer.buffered
  end

  it "drops duplicates without delivering them" do
    sequencer = KrikriAwsSsm::InboundSequencer(String).new
    sequencer.accept(0_i64, "a")
    acceptance = sequencer.accept(0_i64, "a")
    assert_equal KrikriAwsSsm::InboundSequencer::Disposition::Duplicate, acceptance.disposition
    assert_empty acceptance.items
  end

  it "does not buffer past capacity" do
    sequencer = KrikriAwsSsm::InboundSequencer(String).new(1)
    sequencer.accept(1_i64, "b")
    acceptance = sequencer.accept(2_i64, "c")
    assert_equal KrikriAwsSsm::InboundSequencer::Disposition::Overflow, acceptance.disposition
    assert_equal 1, sequencer.buffered
  end
end

describe KrikriAwsSsm::StreamUrl do
  it "detects every presigned query parameter the reference checks" do
    KrikriAwsSsm::StreamUrl::PRESIGNED_PARAMS.each do |param|
      assert KrikriAwsSsm::StreamUrl.presigned?("wss://host/x?#{param}=value"), param
    end
    refute KrikriAwsSsm::StreamUrl.presigned?("wss://host/x")
  end

  it "accepts a wss URL on an AWS host" do
    uri = KrikriAwsSsm::StreamUrl.parse("wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/s")
    KrikriAwsSsm::StreamUrl.validate!(uri, false)
  end

  it "refuses a plain ws URL unless an insecure test endpoint is configured" do
    uri = KrikriAwsSsm::StreamUrl.parse("ws://127.0.0.1:1234/data")
    assert_raises(KrikriAwsSsm::ProtocolError) { KrikriAwsSsm::StreamUrl.validate!(uri, false) }
    KrikriAwsSsm::StreamUrl.validate!(uri, true)
  end

  it "refuses a non-AWS host in production" do
    uri = KrikriAwsSsm::StreamUrl.parse("wss://evil.example.com/data")
    error = assert_raises(KrikriAwsSsm::ProtocolError) do
      KrikriAwsSsm::StreamUrl.validate!(uri, false)
    end
    assert_match(/not an AWS Session Manager endpoint/, error.message.to_s)
  end

  it "builds the exact Host value, adding a non-default port only" do
    aws = KrikriAwsSsm::StreamUrl.parse("wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/s")
    assert_equal "ssmmessages.us-east-1.amazonaws.com", KrikriAwsSsm::StreamUrl.authority(aws)
    local = KrikriAwsSsm::StreamUrl.parse("ws://127.0.0.1:9/data")
    assert_equal "127.0.0.1:9", KrikriAwsSsm::StreamUrl.authority(local)
  end

  it "redacts the query string" do
    uri = KrikriAwsSsm::StreamUrl.parse("wss://host/path?X-Amz-Signature=secret")
    assert_equal "wss://host/path", KrikriAwsSsm::StreamUrl.redact(uri)
  end
end
