require "digest/sha256"
require "uuid"
require "./errors"
require "./payload"
require "./uuid"

module KrikriAwsSsm
  # A Session Manager data-channel frame: a 120-byte header followed by the
  # payload. Field layout and offsets are pinned from
  # `aws/session-manager-plugin` `src/message/clientmessage.go` and
  # `src/message/messageparser.go`.
  #
  # All integers are big-endian. `MessageType` is ASCII, padded with spaces to
  # 32 bytes. `MessageId` uses Java `UUID` byte order (see `UUIDCodec`). The
  # payload digest is SHA-256 of the payload exactly as sent.
  class Message
    # Header length stored in the first field: everything after that field.
    HEADER_LENGTH = 116
    # Bytes before the payload.
    TOTAL_HEADER_LENGTH = 120
    MESSAGE_TYPE_LENGTH =  32

    getter header_length : UInt32
    getter message_type : String
    getter schema_version : UInt32
    getter created_date : UInt64
    getter sequence_number : Int64
    getter flags : UInt64
    getter message_id : UUID
    getter payload_digest : Bytes
    getter payload_type : UInt32
    getter payload : Bytes

    def initialize(@message_type : String, @payload : Bytes = Bytes.empty,
                   @payload_type : UInt32 = PayloadType::Undefined.value,
                   @sequence_number : Int64 = 0_i64,
                   @flags : UInt64 = Flags::NONE,
                   @message_id : UUID = UUID.random,
                   @created_date : UInt64 = Time.utc.to_unix_ms.to_u64,
                   @schema_version : UInt32 = 1_u32)
      @header_length = HEADER_LENGTH.to_u32
      @payload_digest = Digest::SHA256.digest(@payload)
    end

    private def initialize(@header_length : UInt32, @message_type : String,
                           @schema_version : UInt32, @created_date : UInt64,
                           @sequence_number : Int64, @flags : UInt64,
                           @message_id : UUID, @payload_digest : Bytes,
                           @payload_type : UInt32, @payload : Bytes)
    end

    def syn? : Bool
      @flags & Flags::SYN != 0
    end

    def fin? : Bool
      @flags & Flags::FIN != 0
    end

    def acknowledge? : Bool
      @message_type == MessageType::ACKNOWLEDGE
    end

    def payload_length : UInt32
      @payload.size.to_u32
    end

    # Encode this message. The digest is always computed over the payload,
    # matching `ClientMessage.SerializeClientMessage`.
    def encode : Bytes
      bytes = Bytes.new(TOTAL_HEADER_LENGTH + @payload.size)
      write_u32(bytes, 0, @header_length)
      write_message_type(bytes)
      write_u32(bytes, 36, @schema_version)
      write_u64(bytes, 40, @created_date)
      write_u64(bytes, 48, @sequence_number.to_u64!)
      write_u64(bytes, 56, @flags)
      UUIDCodec.encode(@message_id).copy_to(bytes[64, 16])
      Digest::SHA256.digest(@payload).copy_to(bytes[80, 32])
      write_u32(bytes, 112, @payload_type)
      write_u32(bytes, 116, @payload.size.to_u32)
      @payload.copy_to(bytes[TOTAL_HEADER_LENGTH, @payload.size]) unless @payload.empty?
      bytes
    end

    # Decode one frame and verify its payload digest. Raises `ProtocolError`
    # for malformed input and `DigestMismatch` when the digest does not match.
    def self.decode(bytes : Bytes) : Message
      raise ProtocolError.new("message shorter than its #{TOTAL_HEADER_LENGTH}-byte header") if bytes.size < TOTAL_HEADER_LENGTH

      header_length = read_u32(bytes, 0)
      raise ProtocolError.new("unexpected header length #{header_length}, expected #{HEADER_LENGTH}") unless header_length == HEADER_LENGTH

      message_type = String.new(bytes[4, MESSAGE_TYPE_LENGTH]).tr("\0", " ").strip
      raise ProtocolError.new("message type is empty") if message_type.empty?

      schema_version = read_u32(bytes, 36)
      created_date = read_u64(bytes, 40)
      sequence_number = read_u64(bytes, 48).to_i64!
      flags = read_u64(bytes, 56)
      message_id = UUIDCodec.decode(bytes[64, 16])
      payload_digest = Bytes.new(32)
      bytes[80, 32].copy_to(payload_digest)
      payload_type = read_u32(bytes, 112)
      payload_length = read_u32(bytes, 116)

      # Widen before adding: `Int32 + UInt32` promotes to `Int32`, so a
      # hostile `PayloadLength` above 2^31 raises `OverflowError` here instead
      # of the typed `ProtocolError` this method promises.
      unless bytes.size.to_i64 == TOTAL_HEADER_LENGTH.to_i64 + payload_length.to_i64
        raise ProtocolError.new(
          "payload length #{payload_length} does not match frame size #{bytes.size - TOTAL_HEADER_LENGTH}")
      end

      payload = Bytes.new(payload_length)
      bytes[TOTAL_HEADER_LENGTH, payload_length].copy_to(payload) unless payload.empty?

      verify_digest!(message_type, payload, payload_digest)
      new(header_length, message_type, schema_version, created_date, sequence_number,
        flags, message_id, payload_digest, payload_type, payload)
    end

    # Matches `ClientMessage.Validate`: zero-length payloads and
    # start/pause_publication are not digest-checked.
    private def self.verify_digest!(message_type : String, payload : Bytes, digest : Bytes) : Nil
      return if payload.empty?
      return if MessageType.digest_exempt?(message_type)
      return if Digest::SHA256.digest(payload) == digest
      raise DigestMismatch.new(message_type, digest, Digest::SHA256.digest(payload))
    end

    private def write_message_type(bytes : Bytes) : Nil
      if @message_type.bytesize > MESSAGE_TYPE_LENGTH
        raise ProtocolError.new("message type #{@message_type.inspect} exceeds #{MESSAGE_TYPE_LENGTH} bytes")
      end
      bytes[4, MESSAGE_TYPE_LENGTH].fill(' '.ord.to_u8)
      @message_type.to_slice.copy_to(bytes[4, @message_type.bytesize])
    end

    private def write_u32(bytes : Bytes, offset : Int32, value : UInt32) : Nil
      IO::ByteFormat::BigEndian.encode(value, bytes[offset, 4])
    end

    private def write_u64(bytes : Bytes, offset : Int32, value : UInt64) : Nil
      IO::ByteFormat::BigEndian.encode(value, bytes[offset, 8])
    end

    private def self.read_u32(bytes : Bytes, offset : Int32) : UInt32
      IO::ByteFormat::BigEndian.decode(UInt32, bytes[offset, 4])
    end

    private def self.read_u64(bytes : Bytes, offset : Int32) : UInt64
      IO::ByteFormat::BigEndian.decode(UInt64, bytes[offset, 8])
    end
  end
end
