require "json"
require "../errors"
require "./config"
require "./ecs"
require "./imds"
require "./profile"
require "./sso"
require "./sts"
require "./types"

module KrikriAwsSsm
  # Resolves credentials provider-by-provider in AWS SDK precedence order:
  # environment statics, environment web identity, shared profile/config,
  # ECS container metadata, then IMDSv2.
  #
  # The chain caches the last credentials per profile and re-resolves them
  # once they enter their refresh window. All outside inputs come from
  # `Config`, so specs can run the whole chain without touching the real
  # environment or network.
  class CredentialChain
    alias Provider = Proc(String?, Credentials?)

    # One MFA prompt at a time, even when several sessions resolve
    # concurrently: concurrent reads on one terminal would steal each other's
    # codes.
    @@mfa_prompt_mutex = Mutex.new

    getter config : Config
    getter providers : Array(Provider)

    @cache : Hash(String, Credentials)
    # The credential value each profile's cache entry replaced, so a caller
    # still holding it can be mapped back to its profile. Bounded to one
    # superseded value per profile: keying a map by the value itself leaked a
    # secret-bearing key on every refresh of an expiring profile.
    @previous : Hash(String, Credentials)
    @last_profile : String?
    @mutex : Mutex

    # A caller-injected provider list, kept for the phase-1 public surface.
    def initialize(providers : Array(Provider))
      @config = Config.new
      @providers = providers
      @cache = {} of String => Credentials
      @previous = {} of String => Credentials
      @last_profile = nil
      @mutex = Mutex.new
    end

    def initialize(@config : Config = Config.new)
      @cache = {} of String => Credentials
      @previous = {} of String => Credentials
      @last_profile = nil
      @mutex = Mutex.new
      @providers = [] of Provider
      @providers << ->(_profile : String?) { from_environment }
      @providers << ->(_profile : String?) { from_environment_web_identity }
      @providers << ->(profile : String?) { from_profile(profile) }
      @providers << ->(_profile : String?) { from_ecs }
      @providers << ->(_profile : String?) { from_imds }
    end

    def self.default(config : Config = Config.new) : CredentialChain
      new(config)
    end

    def add(&provider : String? -> Credentials?) : self
      @providers << provider
      self
    end

    def resolve(profile : String? = nil) : Credentials
      name = effective_profile(profile)
      @mutex.synchronize do
        if cached = @cache[name]?
          @previous.delete(name)
          return cached unless cached.refresh_needed?
        end
        credentials = resolve_uncached(name)
        @last_profile = name
        @cache[name] = credentials
        credentials
      end
    end

    # Re-resolve the profile that produced *credentials* when they are inside
    # their refresh window; otherwise return them unchanged. Credentials the
    # chain never issued are returned unchanged: re-resolving some other
    # profile would hand the caller another profile's keys.
    def refresh(credentials : Credentials) : Credentials
      return credentials unless credentials.refresh_needed?
      @mutex.synchronize do
        return credentials unless name = profile_for(credentials)
        # Another fiber may have refreshed this profile while this caller
        # waited for the mutex; reuse that result instead of a second
        # AssumeRole round-trip (and a second MFA prompt).
        if cached = @cache[name]?
          return cached unless cached.refresh_needed?
        end
        fresh = resolve_uncached(name)
        @last_profile = name
        @cache[name] = fresh
        @previous[name] = credentials unless credentials == fresh
        fresh
      end
    end

    # A credentials value is all the public API gives us, so an identical
    # value from two profiles is ambiguous; prefer the last resolved profile.
    private def profile_for(credentials : Credentials) : String?
      if name = @last_profile
        return name if @cache[name]? == credentials || @previous[name]? == credentials
      end
      @cache.each do |cached_name, cached|
        return cached_name if cached == credentials
      end
      @previous.each do |previous_name, previous|
        return previous_name if previous == credentials
      end
      nil
    end

    # `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`),
    # with the legacy `AWS_ACCESS_KEY`/`AWS_SECRET_KEY` spellings.
    def self.from_environment : Credentials?
      static_credentials(ENV.to_h)
    end

    def self.static_credentials(env : Hash(String, String)) : Credentials?
      # Botocore treats an empty env value as unset; without `presence` a
      # blank AWS_ACCESS_KEY_ID also shadowed the legacy spellings.
      access_key = env["AWS_ACCESS_KEY_ID"]?.presence || env["AWS_ACCESS_KEY"]?.presence
      secret_key = env["AWS_SECRET_ACCESS_KEY"]?.presence || env["AWS_SECRET_KEY"]?.presence
      return unless access_key && secret_key
      Credentials.new(access_key, secret_key, env["AWS_SESSION_TOKEN"]?.presence)
    end

    private def resolve_uncached(name : String) : Credentials
      @providers.each do |provider|
        credentials = provider.call(name)
        return credentials if credentials
      end
      raise CredentialsError.new
    end

    private def effective_profile(explicit : String?) : String
      explicit || @config.profile ||
        @config.env["AWS_PROFILE"]? ||
        @config.env["AWS_DEFAULT_PROFILE"]? ||
        "default"
    end

    private def from_environment : Credentials?
      CredentialChain.static_credentials(@config.env)
    end

    private def from_environment_web_identity : Credentials?
      env = @config.env
      role_arn = env["AWS_ROLE_ARN"]?
      token_file = env["AWS_WEB_IDENTITY_TOKEN_FILE"]?
      return unless role_arn && token_file
      session_name = env["AWS_ROLE_SESSION_NAME"]? || Config::DEFAULT_ROLE_SESSION_NAME
      token = read_token_file(token_file)
      Sts.new(@config, sts_region).assume_role_with_web_identity(role_arn, session_name, token)
    end

    private def from_profile(name : String?) : Credentials?
      name ||= effective_profile(nil)
      shared = shared_config
      profile = shared.profile?(name)
      return unless profile

      if profile.empty?
        return
      end
      resolve_profile(name, profile, shared, [] of String)
    end

    # Provider order inside a profile, matching botocore's resolver.
    #
    # Top level: the assume-role provider runs before the profile
    # providers, so a profile with both static keys and role_arn assumes
    # the role (the static keys may be its source). The profile providers
    # order web identity, SSO, shared static keys, then credential_process.
    #
    # Source profile (top_level false): static keys win over that
    # profile's own role_arn (botocore's `_resolve_credentials_from_profile`
    # short-circuits when the source profile has static credentials);
    # without static keys a source profile with role_arn is a chained
    # assume-role, which botocore does support.
    private def resolve_profile(name : String, profile : Hash(String, String),
                                shared : SharedConfig, visited : Array(String),
                                top_level : Bool = true) : Credentials?
      if visited.includes?(name)
        raise cycle_error(name, visited)
      end
      visited = visited + [name]

      static = static_profile_credentials?(name, profile)
      role_arn = profile["role_arn"]?
      if top_level || (!static && role_arn)
        if role_arn
          if token_file = profile["web_identity_token_file"]?
            return web_identity_credentials(name, profile, role_arn, token_file)
          end
          return resolve_assume_role(name, profile, role_arn, shared, visited)
        end
      end

      if sso = sso_config(name, profile, shared)
        return sso_credentials(name, sso)
      end

      return static_profile_credentials(profile) if static

      if process = profile["credential_process"]?
        return process_credentials(name, process)
      end

      nil
    end

    private def resolve_assume_role(name : String, profile : Hash(String, String),
                                    role_arn : String, shared : SharedConfig,
                                    visited : Array(String)) : Credentials
      source = if source_profile = profile["source_profile"]?
                 resolve_source_profile(source_profile, name, shared, visited)
               elsif credential_source = profile["credential_source"]?
                 resolve_credential_source(credential_source, name)
               else
                 raise CredentialsError.new(
                   "The profile \"#{name}\" has role_arn but neither source_profile nor credential_source")
               end

      # Each assume-role step carries its own `mfa_serial` (a source profile
      # may have one too), so the prompt happens after the source resolves and
      # once per STS call. Re-prompting on credential refresh is a deliberate
      # divergence from botocore, which raises RefreshWithMFAUnsupportedError
      # instead; the caller's provider can supply the fresh single-use code.
      mfa = profile["mfa_serial"]?.try do |serial|
        {serial: serial, code: mfa_token_code(serial, name)}
      end
      assume_role(name, profile, role_arn, source, mfa)
    end

    private def resolve_source_profile(source_name : String, parent_name : String,
                                       shared : SharedConfig, visited : Array(String)) : Credentials
      profile = shared.profile?(source_name)
      unless profile
        raise CredentialsError.new(
          "The source_profile \"#{source_name}\" referenced in the profile " \
          "\"#{parent_name}\" does not exist.")
      end

      if visited.includes?(source_name)
        # A profile may reference itself only to combine static credentials.
        if source_name == parent_name && static_profile_credentials?(source_name, profile)
          return static_profile_credentials(profile)
        end
        raise cycle_error(source_name, visited)
      end

      resolve_profile(source_name, profile, shared, visited, top_level: false) ||
        raise CredentialsError.new(
          "The source profile \"#{source_name}\" must have credentials.")
    end

    private def resolve_credential_source(source : String, profile_name : String) : Credentials
      credentials = case source
                    when "Environment"
                      from_environment
                    when "Ec2InstanceMetadata"
                      from_imds
                    when "EcsContainer"
                      from_ecs
                    else
                      raise CredentialsError.new(
                        "Unsupported credential_source \"#{source}\" in profile \"#{profile_name}\"")
                    end
      credentials || raise CredentialsError.new(
        "credential_source #{source} has no credentials for profile \"#{profile_name}\"")
    end

    private def assume_role(name : String, profile : Hash(String, String), role_arn : String,
                            source : Credentials,
                            mfa : NamedTuple(serial: String, code: String)? = nil) : Credentials
      session_name = profile["role_session_name"]? || Config::DEFAULT_ROLE_SESSION_NAME
      external_id = profile["external_id"]?
      duration = profile["duration_seconds"]?.try(&.to_i?)
      source_identity = profile["source_identity"]?
      Sts.new(@config, sts_region(profile)).assume_role(
        role_arn, session_name, source, external_id, duration, source_identity, mfa)
    end

    # One-time code for *serial*: an injected provider wins, otherwise the
    # terminal prompt. A non-interactive stdin without a provider is an error
    # (never an empty or guessed code), because a controller such as krikri
    # may be running unattended.
    private def mfa_token_code(serial : String, profile : String) : String
      if provider = @config.mfa_token_provider
        code = provider.call(serial).strip
        if code.empty?
          raise CredentialsError.new(
            "The MFA token provider returned no code for #{serial} (profile \"#{profile}\")")
        end
        return code
      end

      unless @config.mfa_input.tty?
        raise CredentialsError.new(
          "MFA is required for profile \"#{profile}\" (#{serial}) but no terminal is " \
          "available to prompt for the code; run this interactively or supply an MFA token provider")
      end

      prompt_mfa_code(serial)
    end

    # Prompts on the configured streams. Echo is suppressed on the real
    # terminal, or through an injected `mfa_echo_control`; any other injected
    # IO is warned about so a caller knows the code may be visible. A process
    # killed by a signal while the prompt is open leaves echo off: Crystal's
    # default signal handling does not unwind the ensure.
    private def prompt_mfa_code(serial : String) : String
      input = @config.mfa_input
      output = @config.mfa_output
      @@mfa_prompt_mutex.synchronize do
        hidden = terminal_echo(enabled: false)
        begin
          output.puts "Warning: MFA code input may be echoed." unless hidden
          output.print "Enter MFA code for #{serial}: "
          output.flush
          code = read_mfa_code(input, serial)
        ensure
          terminal_echo(enabled: true) if hidden
        end
        output.puts
        code = code.try(&.strip)
        if code.nil? || code.empty?
          raise CredentialsError.new("No MFA code was entered for #{serial}")
        end
        code
      end
    end

    # A prompt that never returns holds the chain mutex and the class-wide
    # prompt mutex, wedging every credential resolution in the process, so
    # the read is bounded. A real terminal gets a read timeout; any other
    # injected IO is raced against the deadline.
    private def read_mfa_code(input : IO, serial : String) : String?
      if input.responds_to?(:read_timeout=) && input.responds_to?(:read_timeout)
        previous = input.read_timeout
        input.read_timeout = @config.mfa_timeout
        begin
          input.gets
        rescue IO::TimeoutError
          raise CredentialsError.new("Timed out waiting for the MFA code for #{serial}")
        ensure
          input.read_timeout = previous
        end
      else
        channel = Channel(String?).new(1)
        spawn { channel.send(input.gets) }
        select
        when code = channel.receive
          code
        when timeout(@config.mfa_timeout)
          raise CredentialsError.new("Timed out waiting for the MFA code for #{serial}")
        end
      end
    end

    # Disables or restores terminal echo, returning true when it took effect.
    # The default only touches the real terminal; an injected IO cannot have
    # its echo changed, and specs inject `mfa_echo_control` instead of stty.
    private def terminal_echo(enabled : Bool) : Bool
      if control = @config.mfa_echo_control
        return control.call(enabled)
      end
      return false unless @config.mfa_input.same?(STDIN)
      Process.run("stty", [enabled ? "echo" : "-echo"], input: Process::Redirect::Inherit,
        output: Process::Redirect::Inherit,
        error: Process::Redirect::Inherit).success?
    rescue
      false
    end

    private def web_identity_credentials(name : String, profile : Hash(String, String),
                                         role_arn : String, token_file : String) : Credentials
      token = read_token_file(token_file)
      session_name = profile["role_session_name"]? || Config::DEFAULT_ROLE_SESSION_NAME
      duration = profile["duration_seconds"]?.try(&.to_i?)
      Sts.new(@config, sts_region(profile)).assume_role_with_web_identity(
        role_arn, session_name, token, duration)
    end

    private def process_credentials(name : String, command : String) : Credentials
      stdout = IO::Memory.new
      stderr = IO::Memory.new
      process = Process.new(command, shell: true, output: stdout, error: stderr)
      outcome = Channel(Process::Status | Exception).new(1)
      spawn do
        outcome.send(process.wait)
      rescue ex
        outcome.send(ex)
      end
      status = select
      when value = outcome.receive
        value
      when timeout(@config.process_timeout)
        # The spawned fiber owns process.wait; calling wait again here
        # double-waits the same status channel and deadlocks.
        process.terminate(graceful: false) rescue nil
        raise CredentialsError.new(
          "credential_process for profile \"#{name}\" timed out after " \
          "#{@config.process_timeout.total_seconds.to_i} second(s)")
      end
      raise status if status.is_a?(Exception)
      unless status.success?
        detail = stderr.to_s.strip
        detail = "no stderr output" if detail.empty?
        raise CredentialsError.new(
          "credential_process for profile \"#{name}\" exited with status " \
          "#{status.exit_code}: #{detail}")
      end
      parse_process_output(name, stdout.to_s)
    rescue ex : IO::Error
      raise CredentialsError.new(
        "credential_process for profile \"#{name}\" could not be executed: #{ex.message}")
    end

    private def parse_process_output(name : String, output : String) : Credentials
      json = JSON.parse(output).as_h? ||
             raise CredentialsError.new(
               "credential_process for profile \"#{name}\" returned a non-object JSON document")
      version = json["Version"]?.try(&.as_i?)
      unless version == 1
        raise CredentialsError.new(
          "Unsupported credential_process version #{version.inspect} for profile \"#{name}\" " \
          "(supported versions: 1)")
      end
      access_key = json["AccessKeyId"]?.try(&.as_s?)
      secret_key = json["SecretAccessKey"]?.try(&.as_s?)
      unless access_key && secret_key
        raise CredentialsError.new(
          "credential_process for profile \"#{name}\" did not return AccessKeyId and SecretAccessKey")
      end
      session_token = json["SessionToken"]?.try(&.as_s?)
      expiration = json["Expiration"]?.try(&.as_s?)
      expires_at = expiration ? Time.parse_rfc3339(expiration) : nil
      Credentials.new(access_key, secret_key, session_token, expires_at)
    rescue JSON::ParseException
      raise CredentialsError.new(
        "credential_process for profile \"#{name}\" returned invalid JSON")
    rescue ex : Time::Format::Error
      raise CredentialsError.new(
        "credential_process for profile \"#{name}\" returned an invalid Expiration: #{ex.message}")
    end

    # A profile with only one of the two static keys is a configuration
    # error botocore names (`PartialCredentialsError`); falling through made
    # it look like "Unable to locate credentials".
    private def static_profile_credentials?(name : String,
                                            profile : Hash(String, String)) : Bool
      access_key = profile["aws_access_key_id"]?
      secret_key = profile["aws_secret_access_key"]?
      if access_key.nil? != secret_key.nil?
        missing = access_key ? "aws_secret_access_key" : "aws_access_key_id"
        raise CredentialsError.new(
          "Partial credentials found in profile \"#{name}\", missing: #{missing}")
      end
      !access_key.nil?
    end

    private def static_profile_credentials(profile : Hash(String, String)) : Credentials
      access_key = profile["aws_access_key_id"]
      secret_key = profile["aws_secret_access_key"]
      Credentials.new(access_key, secret_key, profile["aws_session_token"]?)
    end

    private def sso_config(name : String, profile : Hash(String, String),
                           shared : SharedConfig) : {String, String, String, String, String?}?
      account_id = profile["sso_account_id"]?
      role_name = profile["sso_role_name"]?
      return unless account_id && role_name

      session_name = profile["sso_session"]?
      session = session_name ? shared.sso_session(session_name) : nil
      if session_name && session.nil?
        raise CredentialsError.new(
          "The sso-session \"#{session_name}\" referenced by profile \"#{name}\" does not exist")
      end

      start_url = session.try { |value| value["sso_start_url"]? } || profile["sso_start_url"]?
      region = sso_region(session, profile)
      unless start_url
        raise CredentialsError.new(
          "The profile \"#{name}\" is configured to use SSO but is missing sso_start_url")
      end
      {start_url, region, account_id, role_name, session_name}
    end

    private def sso_region(session : Hash(String, String)?,
                           profile : Hash(String, String)) : String
      session.try { |value| value["sso_region"]? } ||
        profile["sso_region"]? ||
        @config.region ||
        @config.env["AWS_REGION"]? ||
        @config.env["AWS_DEFAULT_REGION"]? ||
        "us-east-1"
    end

    private def sso_credentials(name : String,
                                config : {String, String, String, String, String?}) : Credentials
      start_url, region, account_id, role_name, session_name = config
      Sso.new(@config).get_role_credentials(
        name, start_url, region, account_id, role_name, session_name)
    end

    # AWS_EC2_METADATA_DISABLED only disables IMDS; container credentials
    # are an explicit opt-in via AWS_CONTAINER_CREDENTIALS_*.
    private def from_ecs : Credentials?
      ecs = Ecs.new(@config)
      credentials = ecs.credentials
      return credentials if credentials
      if ecs.configured?
        raise CredentialsError.new(
          "ECS container credentials are configured but could not be retrieved")
      end
      nil
    end

    private def from_imds : Credentials?
      return if @config.disabled_metadata?
      Imds.new(@config).credentials
    end

    private def sts_region(profile : Hash(String, String)? = nil) : String
      profile_region = profile.try { |value| value["region"]? }
      profile_region ||
        @config.region ||
        @config.env["AWS_REGION"]? ||
        @config.env["AWS_DEFAULT_REGION"]? ||
        "us-east-1"
    end

    private def read_token_file(path : String) : String
      File.read(path).strip
    rescue ex : IO::Error
      raise CredentialsError.new("Unable to read web identity token file #{path}: #{ex.message}")
    end

    private def shared_config : SharedConfig
      SharedConfig.load(@config.shared_config_file, @config.shared_credentials_file)
    end

    private def cycle_error(profile : String, visited : Array(String)) : CredentialsError
      CredentialsError.new(
        "Infinite loop in credential configuration detected. Attempting to load from " \
        "profile \"#{profile}\" which has already been visited. " \
        "Visited profiles: #{visited.join(", ")}")
    end
  end
end
