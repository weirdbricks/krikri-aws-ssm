module KrikriAwsSsm
  # Splits client input into `input_stream_data` payloads. The default matches
  # `config.StreamDataPayloadSize` in the reference plugin and the agent's
  # `StdinBufferLimit`.
  module Chunker
    extend self

    def chunks(bytes : Bytes, size : Int32) : Array(Bytes)
      raise ArgumentError.new("chunk size must be positive") unless size > 0
      return [] of Bytes if bytes.empty?
      return [bytes] if bytes.size <= size

      result = [] of Bytes
      offset = 0
      while offset < bytes.size
        count = Math.min(size, bytes.size - offset)
        result << bytes[offset, count]
        offset += count
      end
      result
    end
  end
end
