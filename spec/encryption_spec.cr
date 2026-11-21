require "./spec_helper"

describe KrikriAwsSsm::Encrypter do
  # Generated independently with Python's cryptography AESGCM (not Crystal's
  # OpenSSL binding): key = 00..1f, nonce = 000102..0b, plaintext below.
  VECTOR_PLAINTEXT  = "krikri ssm kms vector"
  VECTOR_KEY        = Bytes.new(32, &.to_u8)
  VECTOR_CIPHERTEXT = "000102030405060708090a0b2c70bf70b78ce268fe2cb7e0dc9a581be6b5f35b8240c2ce02f28e056bdf12a9cacc6f5934".hexbytes

  def self.sixty_four_byte_key(first_half : Bytes) : Bytes
    first_half + Bytes.new(32) { |index| (index + 128).to_u8 }
  end

  it "decrypts a vector produced by an independent AES-GCM implementation" do
    encrypter = KrikriAwsSsm::Encrypter.new(self.class.sixty_four_byte_key(VECTOR_KEY))
    assert_equal VECTOR_PLAINTEXT, String.new(encrypter.decrypt(VECTOR_CIPHERTEXT))
  end

  it "round-trips payloads with a fresh nonce per message" do
    key = Bytes.new(64) { |index| ((index * 3) & 0xff).to_u8 }
    encrypter = KrikriAwsSsm::Encrypter.new(key)
    peer = KrikriAwsSsm::Encrypter.new(key[32, 32] + key[0, 32])
    first = encrypter.encrypt("hello".to_slice)
    second = encrypter.encrypt("hello".to_slice)
    refute_equal first, second
    assert_equal KrikriAwsSsm::Encrypter::NONCE_SIZE + 5 + KrikriAwsSsm::Encrypter::TAG_SIZE, first.size
    assert_equal "hello", String.new(peer.decrypt(first))
    assert_equal "hello", String.new(peer.decrypt(second))
  end

  it "uses the first half for inbound and the last half for outbound" do
    key = Bytes.new(64) { |index| ((index * 7) & 0xff).to_u8 }
    encrypter = KrikriAwsSsm::Encrypter.new(key)
    # The peer mirrors the split: it decrypts with the last half and encrypts
    # with the first half.
    peer = KrikriAwsSsm::Encrypter.new(key[32, 32] + key[0, 32])
    assert_equal "out", String.new(peer.decrypt(encrypter.encrypt("out".to_slice)))
    assert_equal "in", String.new(encrypter.decrypt(peer.encrypt("in".to_slice)))
  end

  it "rejects a tampered tag" do
    key = Bytes.new(64) { |index| (index + 1).to_u8 }
    encrypter = KrikriAwsSsm::Encrypter.new(key)
    ciphertext = encrypter.encrypt("secret".to_slice)
    ciphertext[ciphertext.size - 1] = (ciphertext[ciphertext.size - 1] ^ 0xff).to_u8
    assert_raises(KrikriAwsSsm::ProtocolError) { encrypter.decrypt(ciphertext) }
  end

  it "rejects short ciphertexts and bad key sizes" do
    encrypter = KrikriAwsSsm::Encrypter.new(Bytes.new(64))
    assert_raises(KrikriAwsSsm::ProtocolError) { encrypter.decrypt(Bytes.new(27)) }
    assert_raises(KrikriAwsSsm::ProtocolError) { KrikriAwsSsm::Encrypter.new(Bytes.new(32)) }
  end
end
