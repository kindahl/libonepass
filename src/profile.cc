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

#include "profile.hh"

#include <cassert>
#include <fstream>

#include <openssl/sha.h>

#include "base64.hh"
#include "exception.hh"
#include "iterator.hh"
#include "json11.hh"
#include "key.hh"
#include "opdata.hh"
#include "util.hh"

namespace {

static const std::array<uint8_t, 32> kEmptyKey = { { 0 } };

} // namespace

namespace onepass {

void Profile::Load(const std::string& path) {
  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  std::string text;
  std::copy(std::istreambuf_iterator<char>(src), 
            std::istreambuf_iterator<char>(), 
            std::back_inserter(text));

  std::string err;
  json11::Json json = json11::Json::parse(ExtractJson(text), err);
  if (!err.empty())
    throw FormatError("Unable to parse JSON data in profile.");

  for (auto& obj : json.object_items()) {
    if (obj.first == "createdAt") {
      if (!obj.second.is_number())
        throw FormatError("Profile creation time is not a number.");
      creation_time_ = static_cast<std::time_t>(obj.second.number_value());
    } else if (obj.first == "iterations") {
      if (!obj.second.is_number())
        throw FormatError("Profile iteration count is not a number.");
      iterations_ = static_cast<uint32_t>(obj.second.number_value());
    } else if (obj.first == "lastUpdatedBy") {
      if (!obj.second.is_string())
        throw FormatError("Profile updater is not a string.");
      last_updater_ = obj.second.string_value();
    } else if (obj.first == "masterKey") {
      if (!obj.second.is_string())
        throw FormatError("Profile master key is not a string.");
      locked_master_key_ = base64_decode(obj.second.string_value());
    } else if (obj.first == "overviewKey") {
      if (!obj.second.is_string())
        throw FormatError("Profile overview key is not a string.");
      locked_overview_key_ = base64_decode(obj.second.string_value());
    } else if (obj.first == "profileName") {
      if (!obj.second.is_string())
        throw FormatError("Profile name is not a string.");
      name_ = obj.second.string_value();
    } else if (obj.first == "salt") {
      if (!obj.second.is_string())
        throw FormatError("Profile salt is not a string.");
      base64_decode(obj.second.string_value(), std::back_inserter(salt_));
    } else if (obj.first == "updatedAt") {
      if (!obj.second.is_number())
        throw FormatError("Profile modification time is not a number.");
      modification_time_ = static_cast<std::time_t>(obj.second.number_value());
    } else if (obj.first == "uuid") {
      if (!obj.second.is_string())
        throw FormatError("Profile UUID is not a string.");
      uuid_ = ParseUuid(obj.second.string_value());
    } else {
      assert(false);
      throw FormatError("Unknown entry in profile.");
    }
  }
}

bool Profile::IsLocked() const {
  return master_key_ == kEmptyKey;
}

void Profile::Unlock(const std::string& password) {
  Key key(password, salt_, iterations_);

  try {
    // Load the master key.
    std::string master_key_data =
        ReadOpData(locked_master_key_, key.derived_key(),
                   key.derived_mac_key());

    std::array<uint8_t, 64> master_key;
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, master_key_data.c_str(), master_key_data.size());
    SHA512_Final(master_key.data(), &sha512);

    std::copy(master_key.data(), master_key.data() + 32, master_key_.begin());
    std::copy(master_key.data() + 32, master_key.data() + 64,
              master_mac_key_.begin());

    // Load the overview key.
    std::string overview_key_data =
        ReadOpData(locked_overview_key_, key.derived_key(),
                   key.derived_mac_key());

    std::array<uint8_t, 64> overview_key;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, overview_key_data.c_str(), overview_key_data.size());
    SHA512_Final(overview_key.data(), &sha512);

    std::copy(overview_key.data(), overview_key.data() + 32,
              overview_key_.begin());
    std::copy(overview_key.data() + 32, overview_key.data() + 64,
              overview_mac_key_.begin());
  } catch (IntegrityError& e) {
    throw PasswordError();
  }
}

void Profile::Lock() {
  master_key_ = kEmptyKey;
  master_mac_key_ = kEmptyKey;
  overview_key_ = kEmptyKey;
  overview_mac_key_ = kEmptyKey;
}

}   // namespace onepass
