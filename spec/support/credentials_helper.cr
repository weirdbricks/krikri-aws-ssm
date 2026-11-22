require "digest/sha1"
require "file_utils"
require "json"
require "random"

# Shared fixtures for the credential-chain specs. Everything runs against temp
# directories and loopback HTTP servers; no real AWS endpoint or environment.
module CredentialSpecHelper
  extend self

  def temp_dir : String
    path = File.join(Dir.tempdir, "krikri-aws-ssm-cred-#{Random.rand(1_000_000_000)}-#{Time.utc.nanosecond}")
    Dir.mkdir_p(path)
    path
  end

  def with_temp_dir(&)
    dir = temp_dir
    begin
      yield dir
    ensure
      FileUtils.rm_rf(dir)
    end
  end

  def write(path : String, contents : String) : String
    Dir.mkdir_p(File.dirname(path))
    File.write(path, contents)
    path
  end

  def sts_response(action : String, access_key = "ASSUMEDKEY",
                   secret_key = "ASSUMEDSECRET", token = "ASSUMEDTOKEN",
                   expires_at : Time = Time.utc + 1.hour) : String
    expiration = expires_at.to_s("%Y-%m-%dT%H:%M:%SZ")
    <<-XML
      <#{action}Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
        <#{action}Result>
          <Credentials>
            <AccessKeyId>#{access_key}</AccessKeyId>
            <SecretAccessKey>#{secret_key}</SecretAccessKey>
            <SessionToken>#{token}</SessionToken>
            <Expiration>#{expiration}</Expiration>
          </Credentials>
        </#{action}Result>
      </#{action}Response>
      XML
  end

  def sso_response(access_key = "SSOKEY", secret_key = "SSOSECRET",
                   token = "SSOTOKEN", expires_at : Time = Time.utc + 1.hour) : String
    JSON.build do |json|
      json.object do
        json.field "roleCredentials" do
          json.object do
            json.field "accessKeyId", access_key
            json.field "secretAccessKey", secret_key
            json.field "sessionToken", token
            json.field "expiration", expires_at.to_unix_ms
          end
        end
      end
    end
  end

  def metadata_response(access_key = "METAKEY", secret_key = "METASECRET",
                        token = "METATOKEN", expires_at : Time = Time.utc + 1.hour) : String
    JSON.build do |json|
      json.object do
        json.field "Code", "Success"
        json.field "AccessKeyId", access_key
        json.field "SecretAccessKey", secret_key
        json.field "Token", token
        json.field "Expiration", expires_at.to_s("%Y-%m-%dT%H:%M:%SZ")
      end
    end
  end

  def form_params(body : String) : URI::Params
    URI::Params.parse(body)
  end

  # `mfa_input` defaults to an empty memory IO (not a terminal), so an MFA
  # profile in any spec fails instead of blocking the suite on a prompt.
  def config(env : Hash(String, String), dir : String,
             sts_endpoint : String? = nil, sso_endpoint : String? = nil,
             imds_endpoint : String? = nil, container_endpoint : String? = nil,
             region : String? = nil, allow_insecure : Bool = true,
             mfa_token_provider : Proc(String, String)? = nil,
             mfa_input : IO? = IO::Memory.new,
             mfa_output : IO? = nil,
             mfa_echo_control : Proc(Bool, Bool)? = nil) : KrikriAwsSsm::CredentialChain::Config
    KrikriAwsSsm::CredentialChain::Config.new(
      env: env,
      region: region,
      shared_credentials_file: File.join(dir, "credentials"),
      shared_config_file: File.join(dir, "config"),
      sso_cache_dir: File.join(dir, "sso-cache"),
      sts_endpoint_url: sts_endpoint,
      sso_endpoint_url: sso_endpoint,
      imds_endpoint: imds_endpoint,
      container_metadata_endpoint: container_endpoint,
      allow_insecure_endpoint: allow_insecure,
      mfa_token_provider: mfa_token_provider,
      mfa_input: mfa_input,
      mfa_output: mfa_output,
      mfa_echo_control: mfa_echo_control)
  end

  def chain(env : Hash(String, String), dir : String,
            sts_endpoint : String? = nil, sso_endpoint : String? = nil,
            imds_endpoint : String? = nil, container_endpoint : String? = nil,
            region : String? = nil, allow_insecure : Bool = true,
            mfa_token_provider : Proc(String, String)? = nil,
            mfa_input : IO? = IO::Memory.new,
            mfa_output : IO? = nil,
            mfa_echo_control : Proc(Bool, Bool)? = nil) : KrikriAwsSsm::CredentialChain
    KrikriAwsSsm::CredentialChain.new(
      config(env, dir, sts_endpoint, sso_endpoint, imds_endpoint, container_endpoint,
        region, allow_insecure, mfa_token_provider, mfa_input, mfa_output, mfa_echo_control))
  end
end
