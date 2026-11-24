require "krikri-aws-signer"
require "krikri-xml"
require "uri"
require "../errors"
require "./config"
require "./types"

module KrikriAwsSsm
  class CredentialChain
    # STS Query-protocol client (AssumeRole and AssumeRoleWithWebIdentity).
    #
    # STS speaks the AWS Query protocol, not JSON: a form-encoded POST with
    # `Action` + `Version=2011-06-15`, answered with XML. AssumeRole is signed
    # with the source credentials; AssumeRoleWithWebIdentity is unsigned (the
    # bearer token in the body is the authentication).
    #
    # Provenance: request parameters and XML field names pinned from the STS
    # API and botocore's `AssumeRoleCredentialFetcher` /
    # `AssumeRoleWithWebIdentityCredentialFetcher` (Apache-2.0).
    class Sts
      API_VERSION  = "2011-06-15"
      CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8"

      def initialize(@config : Config, @region : String)
      end

      def assume_role(role_arn : String, session_name : String, source : Credentials,
                      external_id : String? = nil, duration_seconds : Int32? = nil,
                      source_identity : String? = nil,
                      mfa : NamedTuple(serial: String, code: String)? = nil) : Credentials
        params = [
          {"Action", "AssumeRole"},
          {"Version", API_VERSION},
          {"RoleArn", role_arn},
          {"RoleSessionName", session_name},
        ] of Tuple(String, String)
        params << {"ExternalId", external_id} if external_id
        params << {"DurationSeconds", duration_seconds.to_s} if duration_seconds
        params << {"SourceIdentity", source_identity} if source_identity
        # A role protected by MFA needs both the virtual-device serial and the
        # current one-time code; STS rejects either one alone.
        if mfa
          params << {"SerialNumber", mfa[:serial]}
          params << {"TokenCode", mfa[:code]}
        end
        response = perform("AssumeRole", encode_form(params), source)
        parse_credentials(response.body, "AssumeRole")
      end

      def assume_role_with_web_identity(role_arn : String, session_name : String,
                                        web_identity_token : String,
                                        duration_seconds : Int32? = nil) : Credentials
        params = [
          {"Action", "AssumeRoleWithWebIdentity"},
          {"Version", API_VERSION},
          {"RoleArn", role_arn},
          {"RoleSessionName", session_name},
          {"WebIdentityToken", web_identity_token},
        ] of Tuple(String, String)
        params << {"DurationSeconds", duration_seconds.to_s} if duration_seconds
        response = perform("AssumeRoleWithWebIdentity", encode_form(params), nil)
        parse_credentials(response.body, "AssumeRoleWithWebIdentity")
      end

      private def perform(action : String, body : String,
                          source : Credentials?) : HTTP::Client::Response
        endpoint = endpoint_url
        headers = HTTP::Headers{
          "Host"         => HTTPTransport.authority(endpoint),
          "Content-Type" => CONTENT_TYPE,
        }
        path = endpoint.path.empty? ? "/" : endpoint.path
        request = HTTP::Request.new("POST", path, headers, body)

        if source
          signer = KrikriAwsSigner::Signer.new("sts", signing_region(endpoint),
            source.access_key, source.secret_key, source.session_token)
          signer.sign(request)
        end

        response = HTTPTransport.perform(request, endpoint,
          @config.sts_transport_or_default,
          @config.service_connect_timeout, @config.service_read_timeout)
        return response if response.success?
        raise CredentialsError.new(sts_error(action, response))
      rescue ex : IO::Error
        raise CredentialsError.new("STS #{action} request failed: #{ex.message}")
      end

      private def endpoint_url : URI
        if url = @config.sts_endpoint_url
          HTTPTransport.parse_endpoint(url, @config.allow_insecure_endpoint, "STS")
        elsif legacy_endpoint?
          URI.parse("https://sts.amazonaws.com")
        else
          URI.parse("https://sts.#{@region}.amazonaws.com")
        end
      end

      # The global STS endpoint signs with us-east-1 even when the caller's
      # region is elsewhere (botocore's endpoint credentialScope).
      private def signing_region(endpoint : URI) : String
        endpoint.host == "sts.amazonaws.com" ? "us-east-1" : @region
      end

      private def legacy_endpoint? : Bool
        @config.env["AWS_STS_REGIONAL_ENDPOINTS"]?.try(&.downcase) == "legacy"
      end

      private def encode_form(params : Array(Tuple(String, String))) : String
        String.build do |io|
          params.each_with_index do |(key, value), index|
            io << '&' if index > 0
            io << URI.encode_www_form(key) << '=' << URI.encode_www_form(value)
          end
        end
      end

      private def sts_error(action : String, response : HTTP::Client::Response) : String
        document = KXML.parse(response.body) rescue nil
        code = document.try { |doc| find_text(doc, "Code") } || "HTTP #{response.status_code}"
        message = document.try { |doc| find_text(doc, "Message") }
        return "STS #{action} failed: #{code}" unless message
        "STS #{action} failed: #{code}: #{message}"
      end

      private def parse_credentials(xml : String, action : String) : Credentials
        document = KXML.parse(xml)
        root = document.root
        raise CredentialsError.new("STS #{action} response was empty") unless root
        result = find_node(root, "#{action}Result") || root
        credentials_node = find_node(result, "Credentials")
        unless credentials_node
          raise CredentialsError.new("STS #{action} response did not contain Credentials")
        end

        access_key = find_text(credentials_node, "AccessKeyId")
        secret_key = find_text(credentials_node, "SecretAccessKey")
        session_token = find_text(credentials_node, "SessionToken")
        expiration = find_text(credentials_node, "Expiration")
        unless access_key && secret_key && session_token && expiration
          raise CredentialsError.new("STS #{action} response was missing credential fields")
        end

        Credentials.new(access_key, secret_key, session_token, parse_time(expiration))
      rescue ex : KXML::Error
        raise CredentialsError.new("STS #{action} response was not valid XML: #{ex.message}")
      end

      private def parse_time(value : String) : Time
        Time.parse_rfc3339(value)
      rescue ex : Time::Format::Error
        raise CredentialsError.new("STS response had an invalid expiration: #{ex.message}")
      end

      private def find_node(node : KXML::Element, name : String) : KXML::Element?
        return node if node.name == name
        node.elements.each do |child|
          found = find_node(child, name)
          return found if found
        end
        nil
      end

      private def find_text(node : KXML::Element, name : String) : String?
        find_node(node, name).try(&.text_content.strip)
      end

      private def find_text(document : KXML::Document, name : String) : String?
        document.root.try { |root| find_text(root, name) }
      end
    end
  end
end
