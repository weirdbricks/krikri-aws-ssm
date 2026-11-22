require "../spec_helper"

# Session-lifetime semantics a detached job relies on (krikri's async: over
# aws_ssm, issue #1693). These are opt-in live tests:
#
#   KRIKRI_SSM_LIVE=1 SSM_TARGET=i-... SSM_REGION=us-east-2 \
#     crystal spec spec/live/detached_job_spec.cr
#
# The second test additionally needs Session Manager preferences whose
# idleSessionTimeout is 1 minute (the live harness's document does not set it
# by default) and SSM_LIVE_IDLE_SPIKE=1; it takes ~3 minutes.
private module DetachedJobData
  DIR = "/tmp/krikri-detached-job"

  SETUP = "stty -echo -onlcr 2>/dev/null; PS1=''; export TERM=dumb; unset PROMPT_COMMAND\r"

  def self.enabled? : Bool
    ENV["KRIKRI_SSM_LIVE"]? == "1" && !ENV["SSM_TARGET"]?.to_s.empty?
  end

  def self.settings(ping_interval : Time::Span = 30.seconds,
                    idle_timeout : Time::Span = 120.seconds) : KrikriAwsSsm::Settings
    KrikriAwsSsm::Settings.new(ENV["SSM_TARGET"],
      region: ENV["SSM_REGION"]? || "us-east-2",
      connect_timeout: 30.seconds, idle_timeout: idle_timeout,
      ping_interval: ping_interval, retries: 2)
  end

  def self.run(session : KrikriAwsSsm::Session, command : String,
               timeout : Time::Span = 60.seconds) : String
    begin_marker = "__DETACHED_BEGIN_#{Random.rand(1_000_000)}__"
    end_marker = "__DETACHED_END_#{Random.rand(1_000_000)}__"
    session.write("printf '%s\\n' #{begin_marker}; ( #{command} ); " \
                  "printf '\\n%s:%s\\n' #{end_marker} \"$?\"\r")
    read_until(session, /#{end_marker}:-?\d+/, timeout, begin_marker)
  end

  def self.read_until(session : KrikriAwsSsm::Session, pattern : Regex,
                      timeout : Time::Span = 60.seconds,
                      begin_marker : String? = nil) : String
    buffer = IO::Memory.new
    deadline = Time.instant + timeout
    loop do
      text = buffer.to_s
      break if text =~ pattern
      remaining = deadline - Time.instant
      raise "timed out waiting for #{pattern} in #{text.inspect}" if remaining <= Time::Span.zero
      output = read_with_timeout(session, remaining)
      raise "session closed before #{pattern} (#{session.close_reason})" if output.nil?
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

  def self.cleanup(session : KrikriAwsSsm::Session) : Nil
    run(session, "rm -rf #{DIR}")
  rescue
  end
end

describe "SSM detached jobs" do
  # The property krikri's async: launch depends on: a job started in the
  # session's shell keeps running after that session is terminated, so a
  # polled task or a later async_status: can still find its result. Both
  # launch forms are pinned - nohup alone (the fallback when the target has
  # no setsid, e.g. macOS) and nohup + setsid (what the launch emits
  # elsewhere). A bare `&` child also survived in the original spike, but
  # that is incidental and deliberately not pinned here.
  it "a detached job outlives TerminateSession" do
    skip "set KRIKRI_SSM_LIVE=1 and SSM_TARGET" unless DetachedJobData.enabled?

    first = KrikriAwsSsm::Session.open(DetachedJobData.settings)
    begin
      first.write(DetachedJobData::SETUP)
      DetachedJobData.run(first, "rm -rf #{DetachedJobData::DIR}; mkdir -p #{DetachedJobData::DIR}")
      DetachedJobData.run(first,
        "nohup sh -c 'sleep 30; printf plain > #{DetachedJobData::DIR}/plain' " \
        "</dev/null >/dev/null 2>&1 &")
      DetachedJobData.run(first,
        "nohup setsid sh -c 'sleep 30; printf setsid > #{DetachedJobData::DIR}/setsid' " \
        "</dev/null >/dev/null 2>&1 &")
      # The shell is usable straight after backgrounding, i.e. the jobs do
      # not hold the pty (the stdin redirect is what makes this true).
      output = DetachedJobData.run(first, "echo DETACHED_SHELL_USABLE")
      assert_includes output, "DETACHED_SHELL_USABLE"
    ensure
      first.terminate
    end

    # Each job writes 30s after launch; the session is long gone by then.
    sleep 40.seconds

    second = KrikriAwsSsm::Session.open(DetachedJobData.settings)
    begin
      second.write(DetachedJobData::SETUP)
      leftover = DetachedJobData.run(second, "ls -1 #{DetachedJobData::DIR} 2>&1")
      %w[plain setsid].each do |marker|
        assert leftover.lines.map(&.strip).includes?(marker),
          "the nohup job #{marker} did not survive TerminateSession: #{leftover}"
      end
      DetachedJobData.cleanup(second)
    ensure
      second.terminate
    end
  end

  # The other way a session ends: the agent's own idleSessionTimeout, with no
  # client pings to keep it alive. A detached job must survive that too, or
  # async would break whenever a play sits idle longer than the account's
  # idle timeout.
  it "a detached job outlives an agent-closed idle session" do
    skip "set KRIKRI_SSM_LIVE=1, SSM_TARGET and SSM_LIVE_IDLE_SPIKE=1" unless DetachedJobData.enabled? && ENV["SSM_LIVE_IDLE_SPIKE"]? == "1"

    marker = "#{DetachedJobData::DIR}/idle"
    # No pings: the agent's idleSessionTimeout (1 minute in the preferences
    # this test expects) is what closes the session. The client's read
    # timeout is raised so it does not give up first.
    started = Time.instant
    session = KrikriAwsSsm::Session.open(
      DetachedJobData.settings(ping_interval: 10.minutes, idle_timeout: 5.minutes))
    begin
      session.write(DetachedJobData::SETUP)
      DetachedJobData.run(session, "rm -rf #{DetachedJobData::DIR}; mkdir -p #{DetachedJobData::DIR}")
      DetachedJobData.run(session,
        "nohup setsid sh -c 'sleep 150; printf idle > #{marker}' " \
        "</dev/null >/dev/null 2>&1 &")
      # closed? is non-blocking, so this deadline is real. Polling it
      # rather than blocking in read? also proves the *agent* closed the
      # session: SessionTimeout would mean the client gave up first.
      while Time.instant - started < 170.seconds && !session.closed?
        sleep 1.second
      end
      assert_equal KrikriAwsSsm::CloseReason::AgentClosed, session.close_reason,
        "expected the agent to close the idle session, got #{session.close_reason}"
    ensure
      session.terminate
    end

    # The job writes 150s after launch.
    sleep_for = started + 165.seconds - Time.instant
    sleep(sleep_for) if sleep_for > Time::Span.zero

    second = KrikriAwsSsm::Session.open(DetachedJobData.settings)
    begin
      second.write(DetachedJobData::SETUP)
      listing = DetachedJobData.run(second, "ls -1 #{marker} 2>&1")
      assert listing.includes?(marker),
        "the detached job did not outlive the agent-closed idle session: #{listing}"
      DetachedJobData.cleanup(second)
    ensure
      second.terminate
    end
  end
end
