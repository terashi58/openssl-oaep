require 'openssl/oaep/version'
require 'openssl'
require 'securerandom'

module OpenSSL
  # Extends the OpenSSL library.

  module PKey
    class RSA
      def public_encrypt_oaep(str, label = '', md = nil, mgf1md = nil)
        padded = PKCS1.add_oaep_mgf1(str, n.num_bytes, label, md, mgf1md)
        public_encrypt(padded, OpenSSL::PKey::RSA::NO_PADDING)
      end

      def private_decrypt_oaep(str, label = '', md = nil, mgf1md = nil)
        padded = private_decrypt(str, OpenSSL::PKey::RSA::NO_PADDING)
        PKCS1.check_oaep_mgf1(padded, label, md, mgf1md)
      end
    end
  end

  module PKCS1
    def add_oaep_mgf1(str, len, label = '', md = nil, mgf1md = nil)
      md ||= OpenSSL::Digest::SHA1
      mgf1md ||= md

      mdlen = md.new.digest_length
      z_len = len - str.bytesize - 2 * mdlen - 2
      if z_len < 0
        raise OpenSSL::PKey::RSAError, 'data too large for key size'
      end
      if len < 2 * mdlen + 1
        raise OpenSSL::PKey::RSAError, 'key size too small'
      end

      l_hash = md.digest(label)
      db = l_hash + ([0] * z_len + [1]).pack('C*') + [str].pack('a*')
      seed = SecureRandom.random_bytes(mdlen)

      masked_db = mgf1_xor(db, seed, mgf1md)
      masked_seed = mgf1_xor(seed, masked_db, mgf1md)

      [0, masked_seed, masked_db].pack('Ca*a*')
    end

    module_function :add_oaep_mgf1

    def check_oaep_mgf1(str, label = '', md = nil, mgf1md = nil)
      md ||= OpenSSL::Digest::SHA1
      mgf1md ||= md

      mdlen = md.new.digest_length
      em = str.bytes
      if em.size < 2 * mdlen + 2
        raise OpenSSL::PKey::RSAError
      end

      # Keep constant calculation even if the text is invaid in order to avoid attacks.
      good = (em[0] == 0 ? 1 : 0)
      masked_seed = em[1...1+mdlen].pack('C*')
      masked_db = em[1+mdlen...em.size].pack('C*')

      seed = mgf1_xor(masked_seed, masked_db, mgf1md)
      db = mgf1_xor(masked_db, seed, mgf1md)
      db_bytes = db.bytes

      l_hash = md.digest(label)
      good &= (l_hash == db_bytes[0...mdlen].pack('C*') ? 1 : 0)

      one_index = 0
      found_one_byte = 0
      (mdlen...db_bytes.size).each do |i|
        equals1 = db_bytes[i] == 1 ? 1 : 0
        equals0 = db_bytes[i] == 0 ? 1 : 0
        one_index = ~found_one_byte & equals1 == 1 ? i : one_index
        found_one_byte |= equals1
        good &= ((found_one_byte | equals0) == 1 ? 1 : 0)
      end

      good &= (found_one_byte == 1 ? 1 : 0)

      if good != 1
        raise OpenSSL::PKey::RSAError
      end

      db_bytes[one_index+1...db_bytes.size].pack('C*')
    end

    module_function :check_oaep_mgf1

    def mgf1_xor(out, seed, md)
      counter = 0
      out_bytes = out.bytes
      mask_bytes = []
      while mask_bytes.size < out_bytes.size
        mask_bytes += md.digest([seed, counter].pack('a*N')).bytes
        counter += 1
      end
      out_bytes.size.times do |i|
        out_bytes[i] ^= mask_bytes[i]
      end
      out_bytes.pack('C*')
    end

    module_function :mgf1_xor
  end
end
