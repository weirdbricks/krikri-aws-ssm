module KrikriAwsSsm
  # Static AWS credentials. `expires_at` stays nil for long-lived keys.
  struct Credentials
    getter access_key : String
    getter secret_key : String
    getter session_token : String?
    getter expires_at : Time?

    def initialize(@access_key : String, @secret_key : String,
                   @session_token : String? = nil, @expires_at : Time? = nil)
    end

    def expired?(now : Time = Time.utc) : Bool
      if expiry = @expires_at
        now >= expiry
      else
        false
      end
    end

    # True when the credentials expire within *window* (default 5 minutes).
    def refresh_needed?(now : Time = Time.utc, window : Time::Span = 5.minutes) : Bool
      if expiry = @expires_at
        now >= expiry - window
      else
        false
      end
    end

    def to_s(io : IO) : Nil
      io << "Credentials(#{@access_key[0, 4]}..., token=#{@session_token ? "yes" : "no"})"
    end
  end

  # Resolves credentials provider-by-provider in AWS SDK precedence order.
  # Phase 3 only needs environment credentials; the profile, SSO, IMDS, ECS,
  # web-identity and `credential_process` providers land in phase 6.
  class CredentialChain
    alias Provider = Proc(String?, Credentials?)

    getter providers : Array(Provider)

    def initialize(@providers = [] of Provider)
    end

    def add(&provider : String? -> Credentials?) : self
      @providers << provider
      self
    end

    def self.default : CredentialChain
      new.add { |_profile| from_environment }
    end

    def resolve(profile : String? = nil) : Credentials
      @providers.each do |provider|
        credentials = provider.call(profile)
        return credentials if credentials
      end
      raise CredentialsError.new
    end

    # Re-resolve when the cached credentials are near expiry.
    def refresh(credentials : Credentials) : Credentials
      return credentials unless credentials.refresh_needed?
      resolve
    end

    # `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`),
    # with the legacy `AWS_ACCESS_KEY`/`AWS_SECRET_KEY` spellings.
    def self.from_environment : Credentials?
      access_key = ENV["AWS_ACCESS_KEY_ID"]? || ENV["AWS_ACCESS_KEY"]?
      secret_key = ENV["AWS_SECRET_ACCESS_KEY"]? || ENV["AWS_SECRET_KEY"]?
      return unless access_key && secret_key
      Credentials.new(access_key, secret_key, ENV["AWS_SESSION_TOKEN"]?)
    end
  end
end
