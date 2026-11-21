require "http/client"
require "uri"
require "./transport"

module KrikriAwsSsm
  class CredentialChain
    # Every input the credential chain reads from the outside world, so tests
    # can supply a fake environment, temp config files, local endpoints and a
    # transport without touching the real environment or network.
    class Config
      DEFAULT_IMDS_ENDPOINT           = "http://169.254.169.254"
      DEFAULT_CONTAINER_ENDPOINT      = "http://169.254.170.2"
      DEFAULT_METADATA_TIMEOUT        = 250.milliseconds
      DEFAULT_SERVICE_CONNECT_TIMEOUT = 10.seconds
      DEFAULT_SERVICE_READ_TIMEOUT    = 60.seconds
      DEFAULT_PROCESS_TIMEOUT         = 60.seconds
      DEFAULT_ROLE_SESSION_NAME       = "krikri-aws-ssm-session"

      property env : Hash(String, String)
      property profile : String?
      property region : String?
      property home_dir : String
      property shared_credentials_file : String
      property shared_config_file : String
      property sso_cache_dir : String
      property sts_endpoint_url : String?
      property sso_endpoint_url : String?
      property imds_endpoint : String
      property container_metadata_endpoint : String?
      # Kept in the AWS option spelling rather than Crystal's `?` form.
      getter allow_insecure_endpoint : Bool # ameba:disable Naming/QueryBoolMethods

      def allow_insecure_endpoint=(value : Bool) : Bool
        @allow_insecure_endpoint = value
      end

      # Metadata endpoints (IMDS/ECS) use short timeouts; STS/SSO are
      # internet calls and must not inherit the 250 ms metadata budget.
      property connect_timeout : Time::Span
      property read_timeout : Time::Span
      property service_connect_timeout : Time::Span
      property service_read_timeout : Time::Span
      # A hung credential_process must not wedge resolve under the chain mutex.
      property process_timeout : Time::Span

      # One shared transport seam, plus per-service overrides. Any nil override
      # falls back to `transport`, then to a real HTTP client.
      property transport : Transport?
      property sts_transport : Transport?
      property sso_transport : Transport?
      property imds_transport : Transport?
      property ecs_transport : Transport?

      def initialize(env : Hash(String, String)? = nil, profile : String? = nil,
                     region : String? = nil, home_dir : String? = nil,
                     shared_credentials_file : String? = nil,
                     shared_config_file : String? = nil,
                     sso_cache_dir : String? = nil,
                     sts_endpoint_url : String? = nil,
                     sso_endpoint_url : String? = nil,
                     imds_endpoint : String? = nil,
                     container_metadata_endpoint : String? = nil,
                     allow_insecure_endpoint : Bool = false,
                     connect_timeout : Time::Span = DEFAULT_METADATA_TIMEOUT,
                     read_timeout : Time::Span = DEFAULT_METADATA_TIMEOUT,
                     service_connect_timeout : Time::Span = DEFAULT_SERVICE_CONNECT_TIMEOUT,
                     service_read_timeout : Time::Span = DEFAULT_SERVICE_READ_TIMEOUT,
                     process_timeout : Time::Span = DEFAULT_PROCESS_TIMEOUT,
                     transport : Transport? = nil,
                     sts_transport : Transport? = nil,
                     sso_transport : Transport? = nil,
                     imds_transport : Transport? = nil,
                     ecs_transport : Transport? = nil)
        @env = env || ENV.to_h
        @profile = profile
        @region = region
        @home_dir = home_dir || @env["HOME"]? || "."
        @shared_credentials_file = shared_credentials_file ||
                                   @env["AWS_SHARED_CREDENTIALS_FILE"]? ||
                                   File.join(@home_dir, ".aws", "credentials")
        @shared_config_file = shared_config_file ||
                              @env["AWS_CONFIG_FILE"]? ||
                              File.join(@home_dir, ".aws", "config")
        @sso_cache_dir = sso_cache_dir || File.join(@home_dir, ".aws", "sso", "cache")
        @sts_endpoint_url = sts_endpoint_url
        @sso_endpoint_url = sso_endpoint_url
        @imds_endpoint = imds_endpoint || DEFAULT_IMDS_ENDPOINT
        @container_metadata_endpoint = container_metadata_endpoint
        @allow_insecure_endpoint = allow_insecure_endpoint
        @connect_timeout = connect_timeout
        @read_timeout = read_timeout
        @service_connect_timeout = service_connect_timeout
        @service_read_timeout = service_read_timeout
        @process_timeout = process_timeout
        @transport = transport
        @sts_transport = sts_transport
        @sso_transport = sso_transport
        @imds_transport = imds_transport
        @ecs_transport = ecs_transport
      end

      def disabled_metadata? : Bool
        env["AWS_EC2_METADATA_DISABLED"]?.try(&.downcase) == "true"
      end

      def sts_transport_or_default : Transport?
        sts_transport || transport
      end

      def sso_transport_or_default : Transport?
        sso_transport || transport
      end

      def imds_transport_or_default : Transport?
        imds_transport || transport
      end

      def ecs_transport_or_default : Transport?
        ecs_transport || transport
      end
    end
  end
end
