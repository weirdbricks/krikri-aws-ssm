require "digest/sha1"
require "json"
require "uri"
require "../errors"
require "./config"
require "./types"

module KrikriAwsSsm
  class CredentialChain
    # Native AWS IAM Identity Center (SSO) credentials: read the CLI's token
    # cache, then call the unsigned REST-JSON `GetRoleCredentials` endpoint.
    #
    # Provenance: cache-file naming and token fields pinned from
    # `botocore.utils.SSOTokenLoader` and
    # `botocore.credentials.SSOCredentialFetcher` (Apache-2.0); the
    # REST-JSON endpoint and `x-amz-sso_bearer_token` auth follow the SSO
    # portal API.
    class Sso
      TOKEN_ERROR = "The SSO session associated with this profile has expired or is invalid. " \
                    "Please run aws sso login"
      CREDENTIALS_PATH = "/federation/credentials"

      def initialize(@config : Config)
      end

      def get_role_credentials(profile_name : String, start_url : String, sso_region : String,
                               account_id : String, role_name : String,
                               session_name : String? = nil) : Credentials
        token = cached_access_token(profile_name, start_url, session_name, sso_region)
        endpoint = endpoint_url(sso_region)
        query = URI::Params.encode({"role_name" => role_name, "account_id" => account_id})
        path = HTTPTransport.join_path(endpoint, CREDENTIALS_PATH)
        headers = HTTP::Headers{
          "Host"                   => HTTPTransport.authority(endpoint),
          "x-amz-sso_bearer_token" => token,
        }
        request = HTTP::Request.new("GET", "#{path}?#{query}", headers)
        response = HTTPTransport.perform(request, endpoint,
          @config.sso_transport_or_default,
          @config.service_connect_timeout, @config.service_read_timeout)
        unless response.success?
          raise CredentialsError.new(TOKEN_ERROR) if response.status_code == 401 || response.status_code == 403
          raise CredentialsError.new("SSO GetRoleCredentials failed with HTTP #{response.status_code}")
        end
        parse_credentials(response.body)
      rescue ex : IO::Error
        raise CredentialsError.new("SSO GetRoleCredentials request failed: #{ex.message}")
      end

      # Path of the cached-token file for a profile, exposed so callers and
      # tests can pin the botocore-compatible sha1 naming.
      def self.cache_key(start_url : String, session_name : String? = nil) : String
        Digest::SHA1.hexdigest(session_name || start_url)
      end

      def token_path(start_url : String, session_name : String? = nil) : String
        File.join(@config.sso_cache_dir, "#{Sso.cache_key(start_url, session_name)}.json")
      end

      private def cached_access_token(profile_name : String, start_url : String,
                                      session_name : String?, sso_region : String) : String
        path = token_path(start_url, session_name)
        unless File.file?(path)
          raise CredentialsError.new(
            "No SSO token cache entry for profile #{profile_name} (expected #{path}). #{TOKEN_ERROR}")
        end

        json = JSON.parse(File.read(path)).as_h? ||
               raise CredentialsError.new(
                 "SSO token cache entry for profile #{profile_name} is not a JSON object. #{TOKEN_ERROR}")
        access_token = json["accessToken"]?.try(&.as_s?)
        expires_at = json["expiresAt"]?.try(&.as_s?)
        unless access_token && expires_at
          raise CredentialsError.new(
            "SSO token cache entry for profile #{profile_name} is invalid. #{TOKEN_ERROR}")
        end

        expiry = parse_expiry(expires_at)
        return access_token if expiry && Time.utc < expiry

        # A modern CLI v2 cache also carries a refresh token; botocore asks
        # sso-oidc CreateToken for a new access token before failing.
        if refreshed = refresh_access_token(json, sso_region)
          return refreshed
        end
        raise CredentialsError.new(TOKEN_ERROR)
      rescue JSON::ParseException
        raise CredentialsError.new(
          "SSO token cache entry for profile #{profile_name} is invalid JSON. #{TOKEN_ERROR}")
      rescue IO::Error
        raise CredentialsError.new(
          "Unable to read the SSO token cache for profile #{profile_name}. #{TOKEN_ERROR}")
      end

      # `grantType: refresh_token` against the SSO OIDC endpoint, pinned from
      # `botocore.utils.SSOTokenFetcher._refresh_access_token` (Apache-2.0).
      # Returns nil when the cache has no refresh material or the call fails;
      # the caller then reports the login error.
      private def refresh_access_token(cache : Hash(String, JSON::Any),
                                       sso_region : String) : String?
        refresh_token = cache["refreshToken"]?.try(&.as_s?)
        client_id = cache["clientId"]?.try(&.as_s?)
        client_secret = cache["clientSecret"]?.try(&.as_s?)
        return unless refresh_token && client_id && client_secret

        region = cache["region"]?.try(&.as_s?) || sso_region
        endpoint = URI.parse("https://oidc.#{region}.amazonaws.com")
        body = JSON.build do |json|
          json.object do
            json.field "clientId", client_id
            json.field "clientSecret", client_secret
            json.field "grantType", "refresh_token"
            json.field "refreshToken", refresh_token
          end
        end
        headers = HTTP::Headers{
          "Host"         => HTTPTransport.authority(endpoint),
          "Content-Type" => "application/json",
        }
        request = HTTP::Request.new("POST", "/token", headers, body)
        response = HTTPTransport.perform(request, endpoint,
          @config.sso_transport_or_default,
          @config.service_connect_timeout, @config.service_read_timeout)
        return unless response.success?

        response.body.presence.try do |text|
          JSON.parse(text).as_h?.try(&.["accessToken"]?).try(&.as_s?)
        end
      rescue IO::Error | JSON::ParseException
        nil
      end

      private def parse_expiry(value : String) : Time?
        Time.parse_rfc3339(value)
      rescue Time::Format::Error
        nil
      end

      private def endpoint_url(sso_region : String) : URI
        if url = @config.sso_endpoint_url
          HTTPTransport.parse_endpoint(url, @config.allow_insecure_endpoint, "SSO")
        else
          URI.parse("https://portal.sso.#{sso_region}.amazonaws.com")
        end
      end

      private def parse_credentials(body : String) : Credentials
        json = JSON.parse(body).as_h? ||
               raise CredentialsError.new("SSO GetRoleCredentials response was not a JSON object")
        role = json["roleCredentials"]?.try(&.as_h?)
        unless role
          raise CredentialsError.new("SSO GetRoleCredentials response did not contain roleCredentials")
        end

        access_key = role["accessKeyId"]?.try(&.as_s?)
        secret_key = role["secretAccessKey"]?.try(&.as_s?)
        session_token = role["sessionToken"]?.try(&.as_s?)
        expiration = role["expiration"]?.try(&.as_i64?)
        unless access_key && secret_key && session_token && expiration
          raise CredentialsError.new("SSO GetRoleCredentials response was missing credential fields")
        end
        Credentials.new(access_key, secret_key, session_token, Time.unix_ms(expiration))
      rescue ex : JSON::ParseException
        raise CredentialsError.new("SSO GetRoleCredentials response was not valid JSON: #{ex.message}")
      end
    end
  end
end
