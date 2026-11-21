require "./errors"

module KrikriAwsSsm
  # Outbound sequencing, acknowledgements, retransmission and RTO, pinned from
  # `src/datachannel/streaming.go` and `src/config/config.go`.
  #
  # One sequence counter is shared by every client stream message (input data,
  # terminal size, handshake response, encryption challenge response); the
  # caller allocates and tracks under its own write lock so a sequence is
  # issued exactly once. Only the queue head is retransmitted.
  class Reliability
    INITIAL_SRTT         = 100.milliseconds
    INITIAL_RTO          = 200.milliseconds
    MIN_RTO              = 50.milliseconds
    MAX_RTO              = 30.seconds
    CLOCK_GRANULARITY    = 10.milliseconds
    RTT_ALPHA            = 0.125
    RTT_BETA             =  0.25
    DEFAULT_MAX_ATTEMPTS = 3_000

    record Pending, bytes : Bytes, sequence : Int64, sent_at : Time::Span, attempts : Int32

    class RetransmissionTimeout < Error
    end

    getter next_sequence : Int64 = 0
    getter retransmission_timeout : Time::Span
    getter srtt : Time::Span
    getter rtt_variation : Time::Span

    def initialize(@max_attempts : Int32 = DEFAULT_MAX_ATTEMPTS,
                   @now : Proc(Time::Span) = -> { Time.monotonic })
      @queue = Deque(Pending).new
      @mutex = Mutex.new
      @srtt = INITIAL_SRTT
      @rtt_variation = Time::Span.zero
      @retransmission_timeout = INITIAL_RTO
    end

    # Allocate the next outbound sequence number.
    def allocate : Int64
      @mutex.synchronize do
        sequence = @next_sequence
        @next_sequence += 1
        sequence
      end
    end

    def track(sequence : Int64, bytes : Bytes) : Nil
      @mutex.synchronize do
        @queue << Pending.new(bytes, sequence, @now.call, 0)
      end
    end

    # Remove the acknowledged message and refresh the RTO from its round trip.
    # Returns false for an unknown (already acknowledged) sequence.
    def acknowledge(sequence : Int64) : Bool
      @mutex.synchronize do
        index = @queue.index { |pending| pending.sequence == sequence }
        return false unless index
        pending = @queue[index]
        update_rto(@now.call - pending.sent_at)
        @queue.delete_at(index)
        true
      end
    end

    # Returns the head's bytes when its RTO has elapsed, refreshing its send
    # time and attempt count. Raises `RetransmissionTimeout` after
    # `max_attempts` gives up.
    def retransmission : Bytes?
      @mutex.synchronize do
        return if @queue.empty?
        head = @queue[0]
        return if @now.call - head.sent_at < @retransmission_timeout

        attempts = head.attempts + 1
        if attempts > @max_attempts
          raise RetransmissionTimeout.new(
            "message #{head.sequence} was resent #{@max_attempts} times without acknowledgement")
        end
        @queue[0] = Pending.new(head.bytes, head.sequence, @now.call, attempts)
        head.bytes
      end
    end

    def pending : Int32
      @mutex.synchronize { @queue.size }
    end

    def pending_sequences : Array(Int64)
      @mutex.synchronize { @queue.map(&.sequence) }
    end

    def attempts_for(sequence : Int64) : Int32?
      @mutex.synchronize do
        @queue.find { |pending| pending.sequence == sequence }.try(&.attempts)
      end
    end

    # Jacobson/Karels with the bridge's 50ms..30s clamp.
    private def update_rto(rtt : Time::Span) : Nil
      difference = (rtt - @srtt).abs
      @rtt_variation = @rtt_variation * (1 - RTT_BETA) + difference * RTT_BETA
      @srtt = @srtt * (1 - RTT_ALPHA) + rtt * RTT_ALPHA
      rto = @srtt + Math.max(CLOCK_GRANULARITY, @rtt_variation * 4)
      @retransmission_timeout = rto.clamp(MIN_RTO, MAX_RTO)
    end
  end

  # In-order delivery with gap buffering, matching `HandleOutputMessage`:
  # `seq == expected` delivers and advances; `seq > expected` buffers;
  # `seq < expected` is a duplicate. Buffer overflow drops the message.
  class InboundSequencer(T)
    enum Disposition
      Delivered
      Buffered
      Duplicate
      Overflow
    end

    record Acceptance(T), disposition : Disposition, items : Array(T)

    getter expected : Int64 = 0

    def initialize(@capacity : Int32 = 10_000)
      @buffer = {} of Int64 => T
    end

    def accept(sequence : Int64, item : T) : Acceptance(T)
      if sequence < @expected
        Acceptance(T).new(Disposition::Duplicate, [] of T)
      elsif sequence == @expected
        Acceptance(T).new(Disposition::Delivered, deliver(sequence, item))
      elsif @buffer.size >= @capacity
        Acceptance(T).new(Disposition::Overflow, [] of T)
      else
        @buffer[sequence] = item
        Acceptance(T).new(Disposition::Buffered, [] of T)
      end
    end

    def buffered : Int32
      @buffer.size
    end

    private def deliver(sequence : Int64, item : T) : Array(T)
      items = [item]
      @expected = sequence + 1
      while buffered = @buffer.delete(@expected)
        items << buffered
        @expected += 1
      end
      items
    end
  end
end
