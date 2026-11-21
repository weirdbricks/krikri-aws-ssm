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

    # Never reveal the secret key or the full session token in logs.
    def to_s(io : IO) : Nil
      io << "Credentials(" << access_key_prefix << "..., token=" << (@session_token ? "yes" : "no") << ')'
    end

    private def access_key_prefix : String
      @access_key[0, Math.min(4, @access_key.size)]
    end
  end
end
