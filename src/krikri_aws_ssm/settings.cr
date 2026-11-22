require "./credentials"

module KrikriAwsSsm
  # Everything `Client` and `Session` need to talk to SSM.
  class Settings
    DEFAULT_REGION  = "us-east-1"
    DEFAULT_TIMEOUT = 60.seconds
    DEFAULT_RETRIES = 3
    # `config.StreamDataPayloadSize` in the reference plugin.
    DEFAULT_CHUNK_SIZE = 1024
    # Bridge's liveness improvement over the plugin's 5-minute blind ping.
    DEFAULT_PING_INTERVAL = 30.seconds
    DEFAULT_IDLE_TIMEOUT  = 120.seconds
    # Unacknowledged payload bytes a writer may have in flight. Measured on a
    # live agent (3.3.5828.0): keeping the window at 64 KiB sustains ~1 MiB/s,
    # while a 10,000-message burst overruns the agent's receive path, the
    # service drops messages, and recovery collapses to ~25 KiB/s.
    DEFAULT_SEND_WINDOW_BYTES = 64_i64 * 1024
    # Output kept for a caller that is not reading. The websocket reader never
    # blocks on it (that would stop acknowledgement processing and deadlock an
    # upload), so an unread stream is capped and closes the session with
    # OutputBufferExceeded instead of growing without bound.
    DEFAULT_OUTPUT_BUFFER_LIMIT = 64_i64 * 1024 * 1024

    property target : String
    property region : String
    property profile : String?
    # Overrides the SSM control-plane endpoint (tests, VPC endpoints).
    property endpoint_url : String?
    # Overrides the KMS endpoint (tests, VPC endpoints). nil follows the region.
    property kms_endpoint_url : String?
    # Allow `ws://`/`http://` endpoints. Only for an explicit test endpoint;
    # production endpoints must be TLS.
    property? allow_insecure_endpoint : Bool
    # nil means the account's default shell document.
    property document : String?
    property parameters : Hash(String, Array(String))
    property connect_timeout : Time::Span
    property read_timeout : Time::Span
    property retries : Int32
    property credentials : Credentials?
    property client_version : String
    property chunk_size : Int32
    property ping_interval : Time::Span
    property idle_timeout : Time::Span
    # Unacknowledged encoded bytes a writer may have in flight before it
    # waits for acknowledgements.
    property send_window_bytes : Int64
    # Bytes of unread output buffered before the session is closed.
    property output_buffer_limit : Int64
    # Disable Nagle on the data-channel socket. Only turn this off to measure
    # the difference; a sustained upload collapses without it.
    property? tcp_nodelay : Bool

    def initialize(@target : String, @region : String = DEFAULT_REGION,
                   @profile : String? = nil, @endpoint_url : String? = nil,
                   @kms_endpoint_url : String? = nil,
                   @allow_insecure_endpoint : Bool = false, @document : String? = nil,
                   @parameters : Hash(String, Array(String)) = {} of String => Array(String),
                   @connect_timeout : Time::Span = DEFAULT_TIMEOUT,
                   @read_timeout : Time::Span = DEFAULT_TIMEOUT,
                   @retries : Int32 = DEFAULT_RETRIES,
                   @credentials : Credentials? = nil,
                   @client_version : String = "1.0.0",
                   @chunk_size : Int32 = DEFAULT_CHUNK_SIZE,
                   @ping_interval : Time::Span = DEFAULT_PING_INTERVAL,
                   @idle_timeout : Time::Span = DEFAULT_IDLE_TIMEOUT,
                   @send_window_bytes : Int64 = DEFAULT_SEND_WINDOW_BYTES,
                   @output_buffer_limit : Int64 = DEFAULT_OUTPUT_BUFFER_LIMIT,
                   @tcp_nodelay : Bool = true)
      raise ConfigurationError.new("target must not be empty") if @target.empty?
      raise ConfigurationError.new("region must not be empty") if @region.empty?
      raise ConfigurationError.new("chunk_size must be positive") unless @chunk_size > 0
      unless @send_window_bytes > 0
        raise ConfigurationError.new("send_window_bytes must be positive")
      end
      unless @output_buffer_limit > 0
        raise ConfigurationError.new("output_buffer_limit must be positive")
      end
    end
  end
end
