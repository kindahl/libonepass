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

#include "key.hh"

#include <openssl/evp.h>

#include "exception.hh"

namespace onepass {

Key::Key(const std::string& password, const std::vector<uint8_t>& salt,
         uint32_t iterations) {
  std::array<uint8_t, 64> key;
  // Note that the trailing zero is included when deriving the key.
  if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size() + 1,
                         salt.data(), salt.size(), iterations,
                         EVP_sha512(),
                         key.size(), key.data())) {
    throw InternalError("Unable to derive keys.");
  }

  std::copy(key.data(), key.data() + 32, derived_key_.begin());
  std::copy(key.data() + 32, key.data() + 64, derived_mac_key_.begin());
}

}   // namespace onepass
