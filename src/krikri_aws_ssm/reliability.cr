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
    MAX_RTO              = 1.second
    CLOCK_GRANULARITY    = 10.milliseconds
    RTT_ALPHA            = 0.125
    RTT_BETA             =  0.25
    DEFAULT_MAX_ATTEMPTS = 3_000
    # Reference plugin: config.go's OutgoingMessageBufferCapacity. This is the
    # send window: a writer waits for an acknowledgement when this many
    # messages are unacknowledged instead of abandoning the oldest one (see
    # docs/protocol.md).
    OUTGOING_BUFFER_CAPACITY = 10_000
    # Round-trip samples kept for the transfer statistics. Older samples are
    # overwritten; percentiles describe the most recent window, not the whole
    # session.
    RTT_SAMPLE_CAPACITY = 4_096

    record Pending, bytes : Bytes, sequence : Int64, sent_at : Time::Span, attempts : Int32

    # Diagnostic view of the outbound channel, updated by `Session#stats`.
    # `bytes_sent`/`bytes_acked` count encoded frames (header plus payload)
    # once: a retransmission is not counted again, so a stalling stream shows
    # fewer wire bytes than actually left the socket.
    # `ack_*` spans are round-trip samples for messages acknowledged without a
    # retransmission (Karn's algorithm), so a retransmission storm shows up as
    # extra `retransmissions` rather than a bogus RTT.
    struct Stats
      getter elapsed : Time::Span
      getter messages_sent : Int64
      getter bytes_sent : Int64
      getter acks : Int64
      getter bytes_acked : Int64
      getter retransmissions : Int64
      getter pending : Int32
      getter peak_pending : Int32
      getter ack_samples : Int32
      getter ack_min : Time::Span?
      getter ack_median : Time::Span?
      getter ack_p95 : Time::Span?
      getter ack_max : Time::Span?

      def initialize(@elapsed, @messages_sent, @bytes_sent, @acks, @bytes_acked,
                     @retransmissions, @pending, @peak_pending, @ack_samples,
                     @ack_min, @ack_median, @ack_p95, @ack_max)
      end

      # Acknowledgements per second since the channel was created.
      def acks_per_second : Float64
        seconds = @elapsed.total_seconds
        seconds > 0 ? @acks / seconds : 0.0
      end
    end

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
      @started_at = @now.call
      @messages_sent = 0_i64
      @bytes_sent = 0_i64
      @acks = 0_i64
      @bytes_acked = 0_i64
      @retransmissions = 0_i64
      @peak_pending = 0
      @last_ack_at = @started_at
      @samples = Array(Time::Span).new(RTT_SAMPLE_CAPACITY)
      @sample_cursor = 0
      @room = Channel(Nil).new(1)
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
        # A new stream starts the ack-stall clock even if the channel sat
        # idle for longer than the deadline beforehand.
        @last_ack_at = @now.call if @queue.empty?
        @queue << Pending.new(bytes, sequence, @now.call, 0)
        @messages_sent += 1
        @bytes_sent += bytes.size
        @peak_pending = @queue.size if @queue.size > @peak_pending
      end
    end

    # Remove the acknowledged message and refresh the RTO from its round trip.
    # Returns false for an unknown (already acknowledged) sequence.
    def acknowledge(sequence : Int64) : Bool
      acked = @mutex.synchronize do
        # The agent acknowledges in order, so the common case is the head.
        # Falling back to a scan keeps a late ack for an earlier message
        # working without a lookup table.
        index = if !@queue.empty? && @queue[0].sequence == sequence
                  0
                else
                  @queue.index { |pending| pending.sequence == sequence }
                end
        if index
          pending = @queue[index]
          if index == 0
            @queue.shift
          else
            @queue.delete_at(index)
          end
          # Karn's algorithm: a retransmitted message's sample belongs to
          # neither send, so it would skew the RTO.
          record_rtt(@now.call - pending.sent_at) if pending.attempts.zero?
          @last_ack_at = @now.call
          @acks += 1
          @bytes_acked += pending.bytes.size
          true
        else
          false
        end
      end
      notify_room if acked
      acked
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
        @retransmissions += 1
        head.bytes
      end
    end

    def pending : Int32
      @mutex.synchronize { @queue.size }
    end

    # Time since the last acknowledgement. With `pending > 0` this detects an
    # ack-stalled stream; `Session` closes one after `idle_timeout`.
    def ack_idle : Time::Span
      @mutex.synchronize { @now.call - @last_ack_at }
    end

    # Block until `acknowledge` frees a slot (or `wake` is called because the
    # session closed). The caller re-checks its pending count and
    # `Session#closed?`. Only one waiter token is buffered, so with several
    # waiters the rest wake on the timeout and re-check.
    def await_room : Nil
      select
      when @room.receive?
      when timeout(100.milliseconds)
      end
    end

    # Wake an `await_room` waiter (one buffered token). Called on close so a
    # blocked writer observes the closed session instead of hanging on
    # acknowledgements that will never arrive.
    def wake : Nil
      notify_room
    end

    def pending_sequences : Array(Int64)
      @mutex.synchronize { @queue.map(&.sequence) }
    end

    def attempts_for(sequence : Int64) : Int32?
      @mutex.synchronize do
        @queue.find { |pending| pending.sequence == sequence }.try(&.attempts)
      end
    end

    def stats : Stats
      @mutex.synchronize do
        sorted = @samples.sort
        Stats.new(
          elapsed: @now.call - @started_at,
          messages_sent: @messages_sent,
          bytes_sent: @bytes_sent,
          acks: @acks,
          bytes_acked: @bytes_acked,
          retransmissions: @retransmissions,
          pending: @queue.size,
          peak_pending: @peak_pending,
          ack_samples: sorted.size,
          ack_min: sorted.first?,
          ack_median: percentile(sorted, 0.50),
          ack_p95: percentile(sorted, 0.95),
          ack_max: sorted.last?,
        )
      end
    end

    private def percentile(sorted : Array(Time::Span), fraction : Float64) : Time::Span?
      return if sorted.empty?
      index = ((sorted.size - 1) * fraction).round.to_i
      sorted[index]
    end

    private def record_rtt(rtt : Time::Span) : Nil
      if @samples.size < RTT_SAMPLE_CAPACITY
        @samples << rtt
      else
        @samples[@sample_cursor] = rtt
        @sample_cursor = (@sample_cursor + 1) % RTT_SAMPLE_CAPACITY
      end
      update_rto(rtt)
    end

    private def notify_room : Nil
      select
      when @room.send(nil)
      else
      end
    end

    # Jacobson/Karels with the bridge's 50ms..1s clamp.
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
