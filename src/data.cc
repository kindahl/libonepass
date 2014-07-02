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

#include "data.hh"

#include <sstream>

#include <openssl/hmac.h>

#include "cipher.hh"
#include "exception.hh"

namespace {

constexpr std::size_t kDataInitVectorSize = 16;
constexpr std::size_t kDataHmacSize = 32;
constexpr std::size_t kDataMinSize = kDataInitVectorSize + kDataHmacSize;

} // namespace

namespace onepass {

std::string ReadData(const std::string& data,
                     const std::array<uint8_t, 32>& dec_key,
                     const std::array<uint8_t, 32>& mac_key) {
  if (data.size() < kDataMinSize)
    throw FormatError("Too little data.");

  // Extract components from data.
  std::string data_init_vec = data.substr(0, kDataInitVectorSize);
  std::string data_enc = data.substr(
      kDataInitVectorSize, data.size() - kDataInitVectorSize - kDataHmacSize);
  std::string data_hmac = data.substr(
      data.size() - kDataHmacSize, kDataHmacSize);

  std::array<uint8_t, 16> init_vec = { 0 };
  std::copy(data_init_vec.begin(), data_init_vec.end(), init_vec.begin());

  std::array<uint8_t, 32> hmac = { 0 };
  std::copy(data_hmac.begin(), data_hmac.end(), hmac.begin());

  // Decrypt data.
  std::stringstream enc(data_enc), dec;
  AesCipher cipher(dec_key, init_vec);
  decrypt_cbc(enc, dec, cipher);

  // Compute HMAC and verify integrity/authenticity.
  HMAC_CTX hmac_ctx;
  HMAC_CTX_init(&hmac_ctx);
  HMAC_Init(&hmac_ctx, mac_key.data(), mac_key.size(), EVP_sha256());
  HMAC_Update(&hmac_ctx,
              reinterpret_cast<const uint8_t*>(data_init_vec.c_str()),
              data_init_vec.size());
  HMAC_Update(&hmac_ctx,
              reinterpret_cast<const uint8_t*>(data_enc.c_str()),
              data_enc.size());

  std::array<uint8_t, 32> hmac_computed = { 0 };
  unsigned int len = hmac_computed.size();
  HMAC_Final(&hmac_ctx, hmac_computed.data(), &len);
  assert(len == hmac_computed.size());

  if (hmac_computed != hmac)
    throw IntegrityError("HMAC integrity and authenticity check failed.");

  return dec.str();
}

}   // namespace onepass
