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

#include "opdata.hh"

#include <sstream>

#include <openssl/hmac.h>

#include "cipher.hh"
#include "exception.hh"
#include "io.hh"
#include "iterator.hh"

namespace {

constexpr std::size_t kOpHeaderSize = 8;
constexpr std::size_t kOpLengthSize = 8;
constexpr std::size_t kOpInitVectorSize = 16;
constexpr std::size_t kOpHmacSize = 32;
constexpr std::size_t kOpMinSize = kOpHeaderSize + kOpLengthSize +
                                   kOpInitVectorSize + kOpHmacSize;

const std::string kOpHeader = "opdata01";

} // namespace

namespace onepass {

std::string ReadOpData(const std::string& data,
                       const std::array<uint8_t, 32>& dec_key,
                       const std::array<uint8_t, 32>& mac_key) {
  if (data.size() < kOpMinSize || data.substr(0, kOpHeaderSize) != kOpHeader)
    throw FormatError("Expected opdata01.");

  // Ignore header and HMAC.
  std::stringstream src(data.substr(
      kOpHeaderSize, data.size() - (kOpHeaderSize + kOpHmacSize)));

  uint64_t content_len = consume<uint64_t>(src);
  std::array<uint8_t, 16> init_vec = consume<std::array<uint8_t, 16>>(src);

  std::stringstream content;
  AesCipher cipher(dec_key, init_vec);
  decrypt_cbc(src, content, cipher);

  std::string content_str = content.str();
  if (content_str.size() < content_len)
    throw FormatError("Not enough content in opdata01.");

  if (content_len % 16 == 0) {
    content_str = content_str.substr(16, content_str.size() - 16);
  } else {
    std::size_t padding = 16 - (content_len % 16);
    content_str = content_str.substr(padding, content_str.size() - padding);
  }
  assert(content_str.size() == content_len);

  std::string hmac_data = data.substr(0, data.size() - kOpHmacSize);
  std::string hmac_provided_raw = data.substr(
      data.size() - kOpHmacSize, kOpHmacSize);
  std::array<uint8_t, 32> hmac_computed = { 0 };
  std::array<uint8_t, 32> hmac_provided = { 0 };

  std::copy(hmac_provided_raw.begin(), hmac_provided_raw.end(),
            bounds_checked(hmac_provided));

  // Compute HMAC and verify integrity/authenticity.
  HMAC_CTX hmac_ctx;
  HMAC_CTX_init(&hmac_ctx);
  HMAC_Init(&hmac_ctx, mac_key.data(), mac_key.size(), EVP_sha256());
  HMAC_Update(&hmac_ctx, reinterpret_cast<const uint8_t*>(hmac_data.c_str()),
              hmac_data.size());

  unsigned int len = hmac_computed.size();
  HMAC_Final(&hmac_ctx, hmac_computed.data(), &len);
  assert(len == hmac_computed.size());

  if (hmac_computed != hmac_provided)
    throw IntegrityError("HMAC integrity and authenticity check failed.");

  return content_str;
}

}   // namespace onepass
