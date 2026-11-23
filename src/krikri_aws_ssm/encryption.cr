require "openssl"
require "./errors"

# AES-256-GCM payload encryption for KMS-enabled sessions.
#
# Transliterated from `aws/session-manager-plugin` `src/encryption/encrypter.go`
# (Apache-2.0; see NOTICE): the 64-byte KMS data key is split in half, the first
# half decrypts inbound payloads and the last half encrypts outbound payloads,
# and every message carries a fresh 12-byte nonce in front of the ciphertext.
# Go's `Seal` appends the 16-byte GCM tag to the ciphertext, which is the same
# layout `OpenSSL::Cipher#gcm_tag` produces here.
module KrikriAwsSsm
  class Encrypter
    KEY_SIZE      = 64
    HALF_KEY_SIZE = 32
    NONCE_SIZE    = 12
    TAG_SIZE      = 16

    @decryption_key : Bytes
    @encryption_key : Bytes

    def initialize(plaintext_key : Bytes)
      unless plaintext_key.size == KEY_SIZE
        raise ProtocolError.new("KMS data key must be #{KEY_SIZE} bytes, got #{plaintext_key.size}")
      end
      @decryption_key = plaintext_key[0, HALF_KEY_SIZE]
      @encryption_key = plaintext_key[HALF_KEY_SIZE, HALF_KEY_SIZE]
    end

    # 12-byte nonce, then ciphertext, then the 16-byte GCM tag.
    def encrypt(plaintext : Bytes) : Bytes
      nonce = Random::Secure.random_bytes(NONCE_SIZE)
      cipher = cipher(:encrypt, @encryption_key, nonce)
      ciphertext = update_and_final(cipher, plaintext)
      tag = cipher.gcm_tag
      Bytes.new(nonce.size + ciphertext.size + tag.size).tap do |output|
        nonce.copy_to(output[0, nonce.size])
        ciphertext.copy_to(output[nonce.size, ciphertext.size])
        tag.copy_to(output[nonce.size + ciphertext.size, tag.size])
      end
    rescue ex : OpenSSL::Cipher::Error
      raise ProtocolError.new("failed to encrypt payload: #{ex.message}")
    end

    def decrypt(ciphertext : Bytes) : Bytes
      if ciphertext.size < NONCE_SIZE + TAG_SIZE
        raise ProtocolError.new("encrypted payload is shorter than its nonce and tag")
      end
      nonce = ciphertext[0, NONCE_SIZE]
      tag = ciphertext[ciphertext.size - TAG_SIZE, TAG_SIZE]
      body = ciphertext[NONCE_SIZE, ciphertext.size - NONCE_SIZE - TAG_SIZE]
      cipher = cipher(:decrypt, @decryption_key, nonce)
      cipher.gcm_tag = tag
      update_and_final(cipher, body)
    rescue ex : OpenSSL::Cipher::Error
      raise ProtocolError.new("encrypted payload failed authentication: #{ex.message}")
    end

    # Zero the two key halves at session close. They are views of the 64-byte
    # KMS plaintext buffer, so this clears the whole data key in place; the
    # session keeps no other copy.
    def wipe : Nil
      @decryption_key.fill(0_u8)
      @encryption_key.fill(0_u8)
    end

    private def cipher(mode : Symbol, key : Bytes, nonce : Bytes) : OpenSSL::Cipher
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      mode == :encrypt ? cipher.encrypt : cipher.decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher
    end

    private def update_and_final(cipher : OpenSSL::Cipher, body : Bytes) : Bytes
      head = body.empty? ? Bytes.empty : cipher.update(body)
      head + cipher.final
    end
  end
end
