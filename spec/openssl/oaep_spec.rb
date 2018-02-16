require 'spec_helper'

RSpec.describe Openssl::Oaep do
  it 'has a version number' do
    expect(Openssl::Oaep::VERSION).not_to be nil
  end

  describe 'RSA' do
    let(:key) { OpenSSL::PKey::RSA.generate(1024) }
    let(:plan_text) { 'abcdefghij' }
    let(:label) { '' }
    let(:md) { nil }
    let(:mgf1md) { nil }
    let(:label_d) { label }
    let(:md_d) { md }
    let(:mgf1md_d) { mgf1md }

    shared_examples 'success' do
      it 'results in the same text' do
        encrypted = key.public_encrypt_oaep(plan_text, label, md, mgf1md)
        decrypted = key.private_decrypt_oaep(encrypted, label, md, mgf1md)
        expect(decrypted).to eq(plan_text)
      end
    end

    shared_examples 'fail on encryption' do
      it 'raises error on encrypt' do
        expect { key.public_encrypt_oaep(plan_text, label, md, mgf1md) }.to raise_error(OpenSSL::PKey::RSAError)
      end
    end

    shared_examples 'fail on decryption' do
      it 'raises error on decrypt' do
        encrypted = key.public_encrypt_oaep(plan_text, label, md, mgf1md)
        expect { key.private_decrypt_oaep(encrypted, label_d, md_d, mgf1md_d) }.to raise_error(OpenSSL::PKey::RSAError)
      end
    end

    context 'with default params' do
      it_behaves_like 'success'
    end

    context 'with various params' do
      let(:label) { 'label' }
      let(:md) { OpenSSL::Digest::SHA256 }
      let(:mgf1md) { OpenSSL::Digest::SHA512 }
      it_behaves_like 'success'
    end

    describe 'source text length limit' do
      context 'with max plan text length' do
        let(:plan_text) { 'a' * 86 }
        it_behaves_like 'success'
      end

      context 'with longer plan text' do
        let(:plan_text) { 'a' * 87 }
        it_behaves_like 'fail on encryption'
      end
    end

    describe 'with inconsistent params' do
      context 'with different labels' do
        let(:label) { 'label' }
        let(:label_d) { 'label2' }
        it_behaves_like 'fail on decryption'
      end

      context 'with different md' do
        let(:md) { OpenSSL::Digest::SHA256 }
        let(:md_d) { OpenSSL::Digest::SHA1 }
        it_behaves_like 'fail on decryption'
      end

      context 'with different mgf1md' do
        let(:mgf1md) { OpenSSL::Digest::SHA256 }
        let(:mgf1md_d) { OpenSSL::Digest::SHA1 }
        it_behaves_like 'fail on decryption'
      end
    end
  end

  OAEP_DATA = [
    {
      msg: 'abcdefghij',
      len: 256,
      label:  '',
      md: nil,
      mgf1md: nil,
      rand: "\x85\x93\xEA\x9C\xC1\xC1@\xD6Z\x8F#6\xC6\xA3\xAD\x8C,!\xB7\xDE".b,
      em: "\x00M\x91\x7F\xC1e(hf\x99e\x1E\xFF2\xE5\x16\xB9S\x10u\xF7Q\v8\xD1\xD1x\xD1W\xF2\xE4\x91C\xE0\x80\xD6\xBA\xD2/\x14\xB9\x01&\xC4\x95\xF1\x16\xD3\xE9'R[gsq\xD2\xE4\xA9+\xF6o\x9E\x81\x14J\xE3\x94E\xA5\xB2\xDA<\xDC\xFB2\x7F\x91\xD1\xB6\xBF\xCC\xB1mn\x96gn\x97\xC0\xFA\xDA\x04\r\x8B`i\xDE\xE7\xE4$\xFC\x92\x9Dm\xCDwT\xDE\xD3\xF3\xFD\xF2)\xB0\xBC`\xA6\x8A\x0Ed\x8B:\aK\x1A\xC7C\xB7\xBCP\xE4b\xE7#\x1F5\x92\xAA\x97\xE2\x82\xC9\xC5~\x147\x89\xF4\x02WV\t\x8BM\xA55\\]\x87`\x8D\x11b5\x19\xB8]5H\xB47\xBE\f\x85w\xA1\xF0-Z/WbG[z\xD5\x9DV\xDC'\x8F!L\xE4\xE6\xC9\xFB\xACQ*\b\xDA\x917\xD7y\xC5b\xC6\xD8!\x1A.\r\xCE\a\xE3\xC0H\xA1;\xB4\xA0\xBE\xB7\x8E}J\x1D\xC5P:V6Y\xA9R[\x88s\xCFy\x02\xD1_\x06\x97\xDE\xC6\x9E\xD2\x81)\xD6X,".b,
    },
    {
      msg: 'xyz',
      len: 256,
      label:  'label',
      md: OpenSSL::Digest::SHA256,
      mgf1md: nil,
      rand: "\xDB\x14\xF5X\x14Q\x80\x89\x81\xBC\xC1\x8D\x0F\x8D\xF2\xD2\xF7\x1E\x16^\xA4\a)\xFC\x90w!\xFE\xE2\x19\x89\x93".b,
      em: "\x00\xE5DPm\x82\x14\xB9oP\xE1\xF4\xEA\xB6=\x14\x8B\xB9\xEA\xB0\xBB\xA3\x85\xB9\xA2\x13H\xC3r\xEE\xDE\xAF\x16\x81&\x99B\x94\x9C\xEC\xBE\x84\x14q\xA2\x80\xD0\xB5\xE7>\xA4\xAE\xB6h\xA2\x95\x06=\x11\"b\x1F\x91\x0F\x82\xDF\xEAas\xCFj\xA8\xA0\xAC9\x9C\xE1\xEFt\xAF\xDF\x0E\xBA62`\xF3\r\xE6\xCA\x96\x19!\x17\xD2\x12\\\xFF\xFA9K\xCD\xA01\xC9d\xF5\x80S\xE3\x14\xAC\xFA%\xCBY\xCBG$xQ\xD8\xE41^\xBF\xED\xB5(\xFE\x9F\xDEa*\xDC!\\\xFC\xEF$M\x9C\xBEQ\xB6\xE7#\x94`r-\xA4#\xBCx\xFB\xE3\xA2o%\x8F\x83.$i;\x97g\xB6\xB0\xFFH\xF5l4\x8E\xE1\xEA\x03\xEE\x8DF\x89\xFA\x8B\x9C@\xF1\x8Dc\xF4i\x1C\x816\\\xBEkk\x9At\x8AB\x1FF\xEBa\xEA\x80\xD2\xF9@e\xD3\xBEm\xD4\xFA\xBA\xD2.\xCBT55\xBC\x03\xD5\xA3\xFF\x81RkW$\x17\x9C\x1DrX&W\xBF\x8D\xE3\x99\x9Cw\xCC\x04m\tD\x8C\xCF\f".b,
    },
  ]

  describe 'PKCS1.add_oaep_mgf1' do
    it 'adds padding correctly' do
      OAEP_DATA.each do |msg:, len:, label:, md:, mgf1md:, rand:, em:|
        expect(SecureRandom).to receive(:random_bytes) { rand }
        encrypted = OpenSSL::PKCS1.add_oaep_mgf1(msg, len, label, md, mgf1md)
        expect(encrypted).to eq(em)
      end
    end
  end

  describe 'PKCS1.check_oaep_mgf1' do
    it 'checks padding correctly' do
      OAEP_DATA.each do |msg:, len:, label:, md:, mgf1md:, rand:, em:|
        decrypted = OpenSSL::PKCS1.check_oaep_mgf1(em, label, md, mgf1md)
        expect(decrypted).to eq(msg)
      end
    end
  end

  describe '.secure_byte_is_zero' do
    it 'returns 1s iff 0 is given' do
      expect(OpenSSL::PKCS1.secure_byte_is_zero(0)).to eq(-1)
      (1..255).each do |v|
        expect(OpenSSL::PKCS1.secure_byte_is_zero(v)).to eq(0)
      end
    end
  end

  describe '.secure_byte_eq' do
    it 'returns 1s iff values are the same' do
      expect(OpenSSL::PKCS1.secure_byte_eq(0, 0)).to eq(-1)
      expect(OpenSSL::PKCS1.secure_byte_eq(100, 100)).to eq(-1)
      expect(OpenSSL::PKCS1.secure_byte_eq(255, 255)).to eq(-1)
      expect(OpenSSL::PKCS1.secure_byte_eq(0, 100)).to eq(0)
      expect(OpenSSL::PKCS1.secure_byte_eq(0, 255)).to eq(0)
      expect(OpenSSL::PKCS1.secure_byte_eq(100, 255)).to eq(0)
      expect(OpenSSL::PKCS1.secure_byte_eq(255, 128)).to eq(0)
    end
  end

  describe '.secure_select' do
    it 'returns 1st if the mask is 1s, otherwise 2nd' do
      expect(OpenSSL::PKCS1.secure_select(0, 1, 0)).to eq(0)
      expect(OpenSSL::PKCS1.secure_select(-1, 1, 0)).to eq(1)
      expect(OpenSSL::PKCS1.secure_select(0, 12345, 6789)).to eq(6789)
      expect(OpenSSL::PKCS1.secure_select(-1, 12345, 6789)).to eq(12345)
    end
  end

  describe '.secure_hash_eq' do
    it 'returns 1s iff values are the same' do
      expect(OpenSSL::PKCS1.secure_hash_eq(''.bytes, ''.bytes)).to eq(-1)
      expect(OpenSSL::PKCS1.secure_hash_eq('abcd'.bytes, 'abcd'.bytes)).to eq(-1)
      expect(OpenSSL::PKCS1.secure_hash_eq('abcd'.bytes, 'abce'.bytes)).to eq(0)
      expect(OpenSSL::PKCS1.secure_hash_eq('0bcd'.bytes, 'abce'.bytes)).to eq(0)
    end
  end
end
