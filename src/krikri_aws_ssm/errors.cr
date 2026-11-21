module KrikriAwsSsm
  # Base class for every error this shard raises.
  class Error < Exception
  end

  # Invalid configuration (missing target, bad endpoint scheme, ...).
  class ConfigurationError < Error
  end

  # The peer sent bytes that do not match the Session Manager wire protocol.
  class ProtocolError < Error
  end

  # A received message's payload did not hash to the digest in its header.
  class DigestMismatch < ProtocolError
    getter message_type : String

    def initialize(@message_type : String, expected : Bytes, actual : Bytes)
      super("payload digest mismatch for #{@message_type}: " \
            "header #{expected.hexstring}, payload #{actual.hexstring}")
    end
  end

  # The websocket upgrade failed or the agent refused the handshake.
  class HandshakeFailed < Error
  end

  # The session is gone: closed by the agent, the network, or the user.
  class ChannelClosed < Error
  end

  # The session was reclaimed by the service (idle timeout or lifetime cap).
  class SessionTimeout < Error
  end

  # No usable credentials were found in the credential chain.
  class CredentialsError < Error
    def initialize(message = "Unable to locate credentials")
      super(message)
    end
  end

  # An SSM (or other AWS JSON 1.1) API call returned an error response.
  class ApiError < Error
    getter code : String
    getter status : Int32?
    getter request_id : String?

    def initialize(@code : String, message : String, @status : Int32? = nil, @request_id : String? = nil)
      super(message.empty? ? @code : "#{@code}: #{message}")
    end

    # Map an AWS error code (with or without the `com.amazonaws.ssm#` prefix)
    # to a typed error. Unknown codes stay an `ApiError` so the caller still
    # sees the service's own message text.
    def self.from_code(code : String, message : String, status : Int32? = nil,
                       request_id : String? = nil) : ApiError
      short = code.includes?('#') ? code.split('#').last : code
      case short
      when "AccessDeniedException", "AccessDenied"
        AccessDenied.new(short, message, status, request_id)
      when "TargetNotConnected"
        TargetNotConnected.new(short, message, status, request_id)
      when "InvalidDocument", "InvalidDocumentContent"
        InvalidDocument.new(short, message, status, request_id)
      when "SessionNotFound", "InvalidSessionId"
        SessionNotFound.new(short, message, status, request_id)
      when "ThrottlingException", "TooManyUpdates", "RequestLimitExceeded"
        Throttling.new(short, message, status, request_id)
      else
        new(short, message, status, request_id)
      end
    end
  end

  class AccessDenied < ApiError
  end

  class TargetNotConnected < ApiError
  end

  class InvalidDocument < ApiError
  end

  class SessionNotFound < ApiError
  end

  class Throttling < ApiError
  end
end
