/*
 * libonepass - 1Password key database importer
 * Copyright (C) 2014 Christian Kindahl
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "cipher.hh"

#include <algorithm>
#include <cassert>
#include <cstring>

#include "exception.hh"
#include "stream.hh"
#include "util.hh"

namespace {

template <std::size_t N>
using BlockOperation = std::function<std::size_t(const std::array<uint8_t, N>&,
                                                 std::array<uint8_t, N>&,
                                                 std::size_t)>;

template <std::size_t N>
void block_transform(
    std::istream& src, std::ostream& dst,
    BlockOperation<N> op) {
  std::array<uint8_t, N> src_block, dst_block;

  std::streampos pos = src.tellg();
  src.seekg(0, std::ios::end);
  std::streampos end = src.tellg();
  src.seekg(pos, std::ios::beg);

  std::streamsize remaining = end - pos;

  while (src.good()) {
    src.read(reinterpret_cast<char *>(src_block.data()), src_block.size());
    if (src.eof() && src.gcount() == 0)
      break;

    std::streamsize read_bytes = src.gcount();
    remaining -= read_bytes;

    std::size_t dst_bytes = op(
        src_block, dst_block, read_bytes);

    dst.write(reinterpret_cast<const char*>(dst_block.data()), dst_bytes);
  }
}

}

namespace onepass {

void encrypt_ecb(std::istream& src, std::ostream& dst, const Cipher<16>& cipher) {
  block_transform<16>(src, dst, [&](const std::array<uint8_t, 16>& src,
                                    std::array<uint8_t, 16>& dst,
                                    std::size_t src_len) -> std::size_t {
    if (src_len != 16) {
      assert(false);
      throw InternalError("ECB can only encrypt an even number of blocks.");
    }

    cipher.Encrypt(src, dst);
    return 16;
  });
}

void decrypt_ecb(std::istream& src, std::ostream& dst, const Cipher<16>& cipher) {
  block_transform<16>(src, dst, [&](const std::array<uint8_t, 16>& src,
                                    std::array<uint8_t, 16>& dst,
                                    std::size_t src_len) -> std::size_t {
    if (src_len != 16) {
      assert(false);
      throw InternalError("ECB can only decrypt an even number of blocks.");
    }

    cipher.Decrypt(src, dst);
    return 16;
  });
}

std::array<uint8_t, 32> encrypt_ecb(const std::array<uint8_t, 32>& src,
                                    const Cipher<16>& cipher) {
  std::array<uint8_t, 32> arr = src;
  std::array<uint8_t, 32> dst = src;

  array_iostreambuf<32> src_buf(arr);
  array_iostreambuf<32> dst_buf(dst);

  std::istream src_stream(&src_buf);
  std::ostream dst_stream(&dst_buf);

  encrypt_ecb(src_stream, dst_stream, cipher);
  return dst;
}

std::array<uint8_t, 32> decrypt_ecb(const std::array<uint8_t, 32>& src,
                                    const Cipher<16>& cipher) {
  std::array<uint8_t, 32> arr = src;
  std::array<uint8_t, 32> dst = src;

  array_iostreambuf<32> src_buf(arr);
  array_iostreambuf<32> dst_buf(dst);

  std::istream src_stream(&src_buf);
  std::ostream dst_stream(&dst_buf);

  decrypt_ecb(src_stream, dst_stream, cipher);
  return dst;
}

void encrypt_cbc(std::istream& src, std::ostream& dst,
                 const Cipher<16>& cipher) {
  std::array<uint8_t, 16> prv = cipher.InitializationVector();

  uint32_t pad_len = 0;
  block_transform<16>(src, dst, [&](const std::array<uint8_t, 16>& src,
                                    std::array<uint8_t, 16>& dst,
                                    std::size_t src_len) -> std::size_t {
    std::array<uint8_t, 16> src_xor_iv;
    std::transform(src.begin(), src.end(),
                   prv.begin(), src_xor_iv.begin(),
                   std::bit_xor<uint8_t>());

    if (src_len != 16) {
      assert(false);
      throw InternalError("CBC can only encrypt an even number of blocks.");
    }

    cipher.Encrypt(src_xor_iv, dst);
    prv = dst;

    return 16;
  });

  // We must always apply padding.
  if (pad_len == 0) {
    std::array<uint8_t, 16> src_block, dst_block;
    std::array<uint8_t, 16> src_block_xor_iv;

    std::fill(src_block.begin(), src_block.end(), 16);
    std::transform(src_block.begin(), src_block.end(),
                   prv.begin(), src_block_xor_iv.begin(),
                   std::bit_xor<uint8_t>());

    cipher.Encrypt(src_block_xor_iv, dst_block);
    dst.write(reinterpret_cast<const char*>(dst_block.data()),
              dst_block.size());
  }
}

void decrypt_cbc(std::istream& src, std::ostream& dst, const Cipher<16>& cipher) {
  std::array<uint8_t, 16> prv = cipher.InitializationVector();

  block_transform<16>(src, dst, [&](const std::array<uint8_t, 16>& src,
                                    std::array<uint8_t, 16>& dst,
                                    std::size_t src_len) -> std::size_t {
    if (src_len != 16)
      throw IoError("Decryption error.");

    cipher.Decrypt(src, dst);

    std::transform(dst.begin(), dst.end(),
                   prv.begin(), dst.begin(),
                   std::bit_xor<uint8_t>());

    prv = src;
    return 16;
  });
}

AesCipher::AesCipher(const std::array<uint8_t, 32>& key,
                     const std::array<uint8_t, 16>& init_vec) :
    init_vec_(init_vec) {
  if (AES_set_decrypt_key(key.data(), 256, &key_dec_) != 0) {
    assert(false);
  }
  if (AES_set_encrypt_key(key.data(), 256, &key_enc_) != 0) {
    assert(false);
  }
}

void AesCipher::Decrypt(const std::array<uint8_t, 16>& src,
                        std::array<uint8_t, 16>& dst) const {
  AES_decrypt(src.data(), dst.data(), &key_dec_);
}

void AesCipher::Encrypt(const std::array<uint8_t, 16>& src,
                        std::array<uint8_t, 16>& dst) const {
  AES_encrypt(src.data(), dst.data(), &key_enc_);
}

}   // namespace onepass
