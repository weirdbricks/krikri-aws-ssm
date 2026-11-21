require "uuid"

module KrikriAwsSsm
  # Session Manager writes UUIDs in Java `UUID` order: the least-significant
  # 64-bit half first, then the most-significant half. The reference plugin
  # does this in `putUuid`/`getUuid` (`message/messageparser.go`); getting it
  # wrong makes every acknowledgement unmatchable and the session hang.
  module UUIDCodec
    extend self

    # RFC 4122 bytes (MSB first) to the 16 wire bytes (LSB half first).
    def encode(uuid : UUID) : Bytes
      rfc = uuid.bytes.to_slice
      wire = Bytes.new(16)
      wire[0, 8].copy_from(rfc[8, 8])
      wire[8, 8].copy_from(rfc[0, 8])
      wire
    end

    # 16 wire bytes back to a UUID.
    def decode(bytes : Bytes) : UUID
      raise ProtocolError.new("UUID needs 16 bytes, got #{bytes.size}") unless bytes.size == 16
      rfc = Bytes.new(16)
      rfc[0, 8].copy_from(bytes[8, 8])
      rfc[8, 8].copy_from(bytes[0, 8])
      UUID.new(rfc)
    end
  end
end
