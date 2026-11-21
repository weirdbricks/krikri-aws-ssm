require "./spec_helper"

describe KrikriAwsSsm::UUIDCodec do
  # From `putUuid` in src/message/messageparser.go: the least-significant
  # 64-bit half is written first, then the most-significant half.
  it "encodes the least-significant half first (Java UUID order)" do
    uuid = UUID.new("00112233-4455-6677-8899-aabbccddeeff")
    expected = Bytes[
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    ]
    assert_equal expected, KrikriAwsSsm::UUIDCodec.encode(uuid)
  end

  it "decodes the least-significant half first" do
    wire = Bytes[
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    ]
    assert_equal "00112233-4455-6677-8899-aabbccddeeff", KrikriAwsSsm::UUIDCodec.decode(wire).to_s
  end

  it "round-trips every random UUID" do
    16.times do
      uuid = UUID.random
      assert_equal uuid, KrikriAwsSsm::UUIDCodec.decode(KrikriAwsSsm::UUIDCodec.encode(uuid))
    end
  end

  it "rejects a short buffer" do
    error = assert_raises(KrikriAwsSsm::ProtocolError) do
      KrikriAwsSsm::UUIDCodec.decode(Bytes[1, 2, 3])
    end
    assert_equal "UUID needs 16 bytes, got 3", error.message
  end
end
