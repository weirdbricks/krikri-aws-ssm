require "./transport"

module KrikriAwsSsm
  class CredentialChain
    # The shared credentials file (`~/.aws/credentials`) and config file
    # (`~/.aws/config`), parsed and merged the way botocore does it:
    # `[NAME]` in credentials, `[profile NAME]`/`[default]` in config, the
    # credentials file overrides the config file on shared keys, and
    # `[sso-session NAME]` blocks stay separate.
    #
    # Provenance: layout and merge order pinned from
    # `botocore.session.Session.full_config` and
    # `botocore.configloader.raw_config_parse` (Apache-2.0).
    class SharedConfig
      getter profiles : Hash(String, Hash(String, String))
      getter sso_sessions : Hash(String, Hash(String, String))

      def self.load(config_file : String, credentials_file : String) : SharedConfig
        new(read_file(config_file), read_file(credentials_file))
      end

      def self.read_file(path : String) : String
        File.file?(path) ? File.read(path) : ""
      rescue ex : IO::Error
        raise ConfigurationError.new("Unable to read AWS config file #{path}: #{ex.message}")
      end

      def initialize(config_text : String = "", credentials_text : String = "")
        @profiles = {} of String => Hash(String, String)
        @sso_sessions = {} of String => Hash(String, String)

        SharedConfig.parse_ini(config_text).each do |section, values|
          if session_name = section.lchop?("sso-session ")
            @sso_sessions[session_name] = values
          elsif section == "default"
            @profiles["default"] = values
          elsif profile_name = section.lchop?("profile ")
            @profiles[profile_name] = values
          end
        end

        # The credentials file wins over overlapping config-file values.
        SharedConfig.parse_ini(credentials_text).each do |name, values|
          if existing = @profiles[name]?
            existing.merge!(values)
          else
            @profiles[name] = values
          end
        end
      end

      # Empty hash when the profile does not exist, matching botocore's
      # "default is optional" behavior; explicit-profile validation lives in
      # the chain.
      def profile(name : String) : Hash(String, String)
        @profiles[name]? || {} of String => String
      end

      def profile?(name : String) : Hash(String, String)?
        @profiles[name]?
      end

      def sso_session(name : String) : Hash(String, String)?
        @sso_sessions[name]?
      end

      # Parse the simple INI subset AWS uses: `[section]`, `key = value`,
      # full-line `#`/`;` comments, and no nested sections.
      def self.parse_ini(text : String) : Hash(String, Hash(String, String))
        sections = {} of String => Hash(String, String)
        current : Hash(String, String)? = nil
        text.each_line do |line|
          stripped = line.strip
          next if stripped.empty?
          next if stripped.starts_with?('#') || stripped.starts_with?(';')
          if stripped.starts_with?('[') && stripped.ends_with?(']')
            current = sections[stripped[1..-2].strip] ||= {} of String => String
          elsif section = current
            key, separator, value = stripped.partition('=')
            next if separator.empty?
            section[key.strip] = value.strip
          end
        end
        sections
      end
    end
  end
end
