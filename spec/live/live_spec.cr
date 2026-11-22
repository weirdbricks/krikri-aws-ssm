require "file_utils"
require "base64"
require "digest/md5"
require "../spec_helper"

# Live tests need a real SSM-managed target, real credentials in the standard
# chain and (for the encryption test) Session Manager preferences that require
# a KMS key. They are opt-in and never run in CI:
#
#   KRIKRI_SSM_LIVE=1 SSM_TARGET=i-... SSM_REGION=us-east-2 just live
module LiveSpecData
  def self.enabled? : Bool
    ENV["KRIKRI_SSM_LIVE"]? == "1" && !ENV["SSM_TARGET"]?.to_s.empty?
  end

  def self.target : String
    ENV["SSM_TARGET"]
  end

  def self.region : String
    ENV["SSM_REGION"]? || ENV["AWS_REGION"]? || ENV["AWS_DEFAULT_REGION"]? || "us-east-2"
  end

  def self.settings : KrikriAwsSsm::Settings
    settings = KrikriAwsSsm::Settings.new(target,
      region: region, connect_timeout: 30.seconds, idle_timeout: 120.seconds,
      retries: 2)
    # A/B knobs for the throughput test: the pre-0.2.2 transport and send
    # window, so the regression can be reproduced on demand.
    settings.tcp_nodelay = false if ENV["SSM_LIVE_NO_NAGLE"]? == "1"
    if bytes = ENV["SSM_LIVE_SEND_WINDOW_BYTES"]?.try(&.to_i64?)
      settings.send_window_bytes = bytes
    end
    settings
  end

  SETUP = "stty -echo -onlcr 2>/dev/null; PS1=''; export TERM=dumb; unset PROMPT_COMMAND\r"

  def self.run(session : KrikriAwsSsm::Session, command : String,
               timeout : Time::Span = 60.seconds) : String
    begin_marker = "__KRIKRI_BEGIN_#{Random.rand(1_000_000)}__"
    end_marker = "__KRIKRI_END_#{Random.rand(1_000_000)}__"
    session.write("printf '%s\\n' #{begin_marker}; ( #{command} ); printf '\\n%s:%s\\n' #{end_marker} \"$?\"\r")
    read_until(session, /#{end_marker}:(-?\d+)/, timeout, begin_marker)
  end

  def self.read_until(session : KrikriAwsSsm::Session, pattern : Regex,
                      timeout : Time::Span = 60.seconds, begin_marker : String? = nil) : String
    buffer = IO::Memory.new
    deadline = Time.monotonic + timeout
    loop do
      text = buffer.to_s
      break if text =~ pattern
      remaining = deadline - Time.monotonic
      raise "timed out waiting for #{pattern} in #{text.inspect}" if remaining <= Time::Span.zero
      output = read_with_timeout(session, remaining)
      if output.nil?
        raise "session closed before #{pattern} (#{session.close_reason}, #{session.error}): #{text.inspect}"
      end
      buffer << String.new(output.bytes).gsub('\r', "")
    end
    text = buffer.to_s
    if begin_marker
      if index = text.index(begin_marker)
        text = text[index, text.size - index]
      end
    end
    text
  end

  # Newline-wrap base64 the way krikri streams it: 3000 bytes per line, under
  # the pty's 4096-byte canonical input limit.
  def self.wrap(encoded : String) : Array(String)
    lines = Array(String).new(encoded.bytesize // 3000 + 1)
    offset = 0
    while offset < encoded.bytesize
      count = Math.min(3000, encoded.bytesize - offset)
      lines << encoded[offset, count]
      offset += count
    end
    lines
  end

  # Bytes written by wrapping *encoded* into 3000-byte lines.
  def self.wrapped_size(encoded : String) : Int64
    return 0_i64 if encoded.empty?
    encoded.bytesize.to_i64 + (encoded.bytesize + 2999_i64) // 3000_i64
  end

  # Print the shard's own counters for a transfer so a slow live run can be
  # diagnosed without guessing: message rate, ack rate, send-window high-water
  # mark, retransmissions and the round-trip distribution.
  def self.report(label : String, before : KrikriAwsSsm::Reliability::Stats,
                  after : KrikriAwsSsm::Reliability::Stats,
                  bytes : Int64, elapsed : Time::Span) : Nil
    seconds = elapsed.total_seconds
    kib = seconds > 0 ? bytes / seconds / 1024 : 0.0
    messages = after.messages_sent - before.messages_sent
    acks = after.acks - before.acks
    retransmissions = after.retransmissions - before.retransmissions
    puts "#{label}: #{bytes} bytes in #{seconds.round(2)}s (#{kib.round(1)} KiB/s), " \
         "#{messages} messages (#{(seconds > 0 ? messages / seconds : 0.0).round(1)}/s), " \
         "acks=#{acks} (#{(seconds > 0 ? acks / seconds : 0.0).round(1)}/s), " \
         "retransmissions=#{retransmissions}, session_peak_pending=#{after.peak_pending}, " \
         "rtt median=#{format_span(after.ack_median)} p95=#{format_span(after.ack_p95)}"
  end

  def self.format_span(span : Time::Span?) : String
    span ? "#{span.total_milliseconds.round(1)}ms" : "n/a"
  end
end

describe "live SSM" do
  it "runs a command and reports stdout, stderr and the exit code" do
    skip "set KRIKRI_SSM_LIVE=1 and SSM_TARGET" unless LiveSpecData.enabled?
    session = KrikriAwsSsm::Session.open(LiveSpecData.settings)
    begin
      session.write(LiveSpecData::SETUP)
      output = LiveSpecData.run(session,
        "echo LIVE_OK; echo LIVE_ERR >&2; exit 3")
      assert_includes output, "LIVE_OK"
      assert_includes output, "LIVE_ERR"
      assert_match(/__KRIKRI_END_\d+__:3/, output)
      assert session.encryption_enabled?, "Session Manager preferences should require KMS"
    ensure
      session.terminate
    end
  end

  it "moves a 1MiB payload up and back with matching checksums" do
    skip "set KRIKRI_SSM_LIVE=1 and SSM_TARGET" unless LiveSpecData.enabled?
    session = KrikriAwsSsm::Session.open(LiveSpecData.settings)
    begin
      session.write(LiveSpecData::SETUP)
      payload = Bytes.new((ENV["SSM_LIVE_BYTES"]? || "1048576").to_i) { |index| (index % 251).to_u8 }
      encoded = Base64.strict_encode(payload)
      # Pty canonical input is capped at 4096 bytes per line, so stream base64
      # in 3000-byte lines; `head -c` gives a deterministic EOF.
      lines = LiveSpecData.wrap(encoded)
      data = lines.join("\n") + "\n"
      wrapped = LiveSpecData.wrapped_size(encoded)
      begin_marker = "__KRIKRI_UP_#{Random.rand(1_000_000)}__"
      ready_marker = "__KRIKRI_READY_#{Random.rand(1_000_000)}__"
      end_marker = "__KRIKRI_UP_END_#{Random.rand(1_000_000)}__"
      # READY comes from inside the pipeline: a live agent drops bytes written
      # before `head` is reading (see krikri's exec_script_locked).
      session.write("printf '%s\\n' #{begin_marker}; " \
                    "( printf '%s\\n' #{ready_marker} >&2; exec head -c #{wrapped} ) | base64 -d > /tmp/krikri-live.bin; " \
                    "md5sum /tmp/krikri-live.bin; " \
                    "printf '\\n%s:%s\\n' #{end_marker} \"$?\"\r")
      LiveSpecData.read_until(session, /#{ready_marker}/, 30.seconds)
      before = session.stats
      started = Time.monotonic
      session.write(data)
      upload = LiveSpecData.read_until(session, /#{end_marker}:/, 180.seconds, begin_marker)
      elapsed = Time.monotonic - started
      expected = Digest::MD5.hexdigest(payload)
      assert_includes upload, expected
      LiveSpecData.report("live 1MiB upload", before, session.stats, wrapped, elapsed)

      download_marker = "__KRIKRI_DOWN_#{Random.rand(1_000_000)}__"
      session.write("base64 /tmp/krikri-live.bin; printf '\\n%s\\n' #{download_marker}\r")
      download = LiveSpecData.read_until(session, /#{download_marker}/, 180.seconds)
      assert_includes download.delete(" \t\r\n"), encoded
      puts "live throughput: #{(payload.size * 2 / elapsed.total_seconds / 1024 / 1024).round(2)} MiB/s"
    ensure
      session.terminate
    end
  end

  # Issue #1692: a cold krikri/SSM run was dominated by one ~13MB upload that
  # crossed the channel at ~50 KiB/s. A 1MiB burst was fast and a 4MiB stream
  # collapsed, which fits Nagle plus delayed ACK on the data-channel socket
  # (one MSS per round trip). The shard now sets TCP_NODELAY and waits for
  # acknowledgements instead of dropping the oldest unacked message. This test
  # pins the sustained rate and prints the counters a diagnosis needs.
  # SSM_LIVE_NO_NAGLE=1 runs the same test without the fix for an A/B.
  it "sustains a multi-megabyte upload after the first megabyte" do
    skip "set KRIKRI_SSM_LIVE=1 and SSM_TARGET" unless LiveSpecData.enabled?
    session = KrikriAwsSsm::Session.open(LiveSpecData.settings)
    begin
      session.write(LiveSpecData::SETUP)
      LiveSpecData.run(session, "true")

      total = (ENV["SSM_LIVE_SUSTAINED_BYTES"]? || "4194304").to_i
      floor_kib = (ENV["SSM_LIVE_MIN_KIBPS"]? || "64").to_f
      payload = Bytes.new(total) { |index| (index % 251).to_u8 }
      encoded = Base64.strict_encode(payload)
      lines = LiveSpecData.wrap(encoded)
      wrapped = LiveSpecData.wrapped_size(encoded)

      begin_marker = "__KRIKRI_SUSTAIN_#{Random.rand(1_000_000)}__"
      ready_marker = "__KRIKRI_SUSTAIN_READY_#{Random.rand(1_000_000)}__"
      end_marker = "__KRIKRI_SUSTAIN_END_#{Random.rand(1_000_000)}__"
      session.write("printf '%s\\n' #{begin_marker}; " \
                    "( printf '%s\\n' #{ready_marker} >&2; exec head -c #{wrapped} ) | base64 -d > /tmp/krikri-live-sustained.bin; " \
                    "md5sum /tmp/krikri-live-sustained.bin; " \
                    "printf '\\n%s:%s\\n' #{end_marker} \"$?\"\r")
      LiveSpecData.read_until(session, /#{ready_marker}/, 30.seconds)

      before = session.stats
      started = Time.monotonic
      first_mib_at = nil
      written = 0_i64
      lines.each do |line|
        session.write(line + "\n")
        written += line.bytesize + 1
        if first_mib_at.nil? && written >= 1_048_576
          first_mib_at = Time.monotonic
        end
      end
      handed_off = Time.monotonic
      upload = LiveSpecData.read_until(session, /#{end_marker}:/, 240.seconds, begin_marker)
      finished = Time.monotonic

      assert_includes upload, Digest::MD5.hexdigest(payload)
      if burst = first_mib_at
        burst_elapsed = burst - started
        burst_kib = 1_048_576 / burst_elapsed.total_seconds / 1024
        puts "live burst: first 1 MiB handed to the socket in " \
             "#{burst_elapsed.total_seconds.round(2)}s (#{burst_kib.round(1)} KiB/s)"
      end
      puts "live sustained: all #{written} bytes handed to the socket in " \
           "#{(handed_off - started).total_seconds.round(2)}s"

      LiveSpecData.report("live sustained upload", before, session.stats, written, finished - started)
      sustained_kib = written / (finished - started).total_seconds / 1024
      assert sustained_kib >= floor_kib,
        "sustained upload was #{sustained_kib.round(1)} KiB/s, below the #{floor_kib} KiB/s floor"
    ensure
      session.terminate
    end
  end

  it "terminates the session and leaves nothing Active" do
    skip "set KRIKRI_SSM_LIVE=1 and SSM_TARGET" unless LiveSpecData.enabled?
    client = KrikriAwsSsm::Client.new(LiveSpecData.settings)
    session = KrikriAwsSsm::Session.open(LiveSpecData.settings, client: client)
    session_id = session.session_id
    session.terminate
    deadline = Time.monotonic + 60.seconds
    active = true
    while active && Time.monotonic < deadline
      active = client.describe_sessions.any? do |entry|
        entry["SessionId"]?.try(&.as_s?) == session_id &&
          entry["Status"]?.try(&.as_s?) == "Connected"
      end
      sleep 2.seconds if active
    end
    refute active, "session #{session_id} is still Connected after TerminateSession"
  end
end

describe "live SSM credentials" do
  it "assumes a role from a source profile and opens a session with it" do
    role_arn = ENV["SSM_ASSUME_ROLE_ARN"]?
    skip "set SSM_ASSUME_ROLE_ARN to a role trusting the live user" unless LiveSpecData.enabled? && role_arn
    access_key = ENV["AWS_ACCESS_KEY_ID"]? || raise "AWS_ACCESS_KEY_ID is required"
    secret_key = ENV["AWS_SECRET_ACCESS_KEY"]? || raise "AWS_SECRET_ACCESS_KEY is required"

    dir = File.join(Dir.tempdir, "krikri-ssm-live-#{Random.rand(1_000_000)}")
    Dir.mkdir(dir, 0o700)
    begin
      credentials_file = File.join(dir, "credentials")
      File.write(credentials_file, <<-INI)
        [live-source]
        aws_access_key_id = #{access_key}
        aws_secret_access_key = #{secret_key}
        INI
      config_file = File.join(dir, "config")
      File.write(config_file, <<-INI)
        [profile live-assumed]
        role_arn = #{role_arn}
        source_profile = live-source
        region = #{LiveSpecData.region}
        INI
      chain = KrikriAwsSsm::CredentialChain.default(
        KrikriAwsSsm::CredentialChain::Config.new(
          # No AWS_* entries: the source profile must supply the credentials,
          # otherwise the environment provider (correctly) wins the chain.
          env: {"HOME" => ENV["HOME"]? || "."}, profile: "live-assumed",
          shared_credentials_file: credentials_file,
          shared_config_file: config_file,
          region: LiveSpecData.region))
      credentials = chain.resolve("live-assumed")
      refute_equal access_key, credentials.access_key
      refute_nil credentials.session_token
      session = KrikriAwsSsm::Session.open(
        KrikriAwsSsm::Settings.new(LiveSpecData.target, region: LiveSpecData.region,
          profile: "live-assumed", credentials: credentials))
      begin
        assert session.encryption_enabled?
      ensure
        session.terminate
      end
    ensure
      FileUtils.rm_rf(dir)
    end
  end
end
