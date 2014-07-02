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

#include "bands.hh"

#include <cassert>
#include <fstream>

#include "base64.hh"
#include "data.hh"
#include "exception.hh"
#include "json11.hh"
#include "opdata.hh"
#include "profile.hh"
#include "util.hh"

namespace onepass {

Entry::Category CategoryFromString(const std::string& str) {
  if (str == "001") {
    return Entry::Category::kLogin;
  } else if (str == "002") {
    return Entry::Category::kCreditCard;
  } else if (str == "003") {
    return Entry::Category::kSecureNote;
  } else if (str == "004") {
    return Entry::Category::kIdentity;
  } else if (str == "005") {
    return Entry::Category::kPassword;
  } else if (str == "099") {
    return Entry::Category::kTombstone;
  } else if (str == "100") {
    return Entry::Category::kSoftwareLicense;
  } else if (str == "101") {
    return Entry::Category::kBankAccount;
  } else if (str == "102") {
    return Entry::Category::kDatabase;
  } else if (str == "103") {
    return Entry::Category::kDriverLicense;
  } else if (str == "104") {
    return Entry::Category::kOutdoorLicense;
  } else if (str == "105") {
    return Entry::Category::kMembership;
  } else if (str == "106") {
    return Entry::Category::kPassport;
  } else if (str == "107") {
    return Entry::Category::kRewards;
  } else if (str == "108") {
    return Entry::Category::kSocialSecurityNumber;
  } else if (str == "109") {
    return Entry::Category::kRouter;
  } else if (str == "110") {
    return Entry::Category::kServer;
  } else if (str == "111") {
    return Entry::Category::kEmail;
  }

  assert(false);
  return Entry::Category::kLogin;
}

Entry::Field::Field(const json11::Json& json) {
  assert(json.is_object());

  for (const auto& obj : json.object_items()) {
    if (obj.first == "k") {
      assert(obj.second.is_string());
      key_ = obj.second.string_value();
    } else if (obj.first == "v" || obj.first == "value") {
      value_ = obj.second.dump();
    } else if (obj.first == "n" || obj.first == "name") {
      assert(obj.second.is_string());
      name_ = obj.second.string_value();
    } else if (obj.first == "t") {
      assert(obj.second.is_string());
      title_ = obj.second.string_value();
    } else if (obj.first == "a") {
      assert(obj.second.is_object());

      for (const auto& attr : obj.second.object_items()) {
        assert(attr.second.is_string());
        attributes_.insert(std::make_pair(
            attr.first, attr.second.string_value()));
      }
    } else if (obj.first == "type") {
      assert(obj.second.is_string());
      type_ = obj.second.string_value();
    } else if (obj.first == "designation") {
      assert(obj.second.is_string());
      designation_ = obj.second.string_value();
    } else {
      assert(false);
    }
  }
}

Entry::Section::Section(const json11::Json& json) {
  assert(json.is_object());

  for (const auto& obj : json.object_items()) {
    if (obj.first == "name") {
      assert(obj.second.is_string());
      name_ = obj.second.string_value();
    } else if (obj.first == "title") {
      assert(obj.second.is_string());
      title_ = obj.second.string_value();
    } else if (obj.first == "fields") {
      assert(obj.second.is_array());

      for (const auto& item : obj.second.array_items()) {
        assert(item.is_object());
        fields_.push_back(std::make_shared<Field>(item));
      }
    } else {
      assert(false);
    }
  }
}

Entry::Form::Form(const json11::Json& json) {
  assert(json.is_object());

  for (const auto& obj : json.object_items()) {
    if (obj.first == "htmlAction") {
      assert(obj.second.is_string());
      action_ = obj.second.string_value();
    } else if (obj.first == "htmlName") {
      assert(obj.second.is_string());
      name_ = obj.second.string_value();
    } else if (obj.first == "htmlID") {
      assert(obj.second.is_string());
      id_ = obj.second.string_value();
    } else if (obj.first == "htmlMethod") {
      assert(obj.second.is_string());
      assert(obj.second.string_value() == "get" ||
             obj.second.string_value() == "post");
      if (obj.second.string_value() == "post") {
        method_ = Method::kPost;
      } else {
        method_ = Method::kGet;
      }
    } else {
      assert(false);
    }
  }
}

Entry::PasswordHistory::PasswordHistory(const json11::Json& json) {
  assert(json.is_object());

  for (const auto& obj : json.object_items()) {
    if (obj.first == "value") {
      assert(obj.second.is_string());
      value_ = obj.second.string_value();
    } else if (obj.first == "time") {
      assert(obj.second.is_number());
      time_ = static_cast<std::time_t>(obj.second.number_value());
    } else {
      assert(false);
    }
  }
}

void Entry::UpdateFromOverview(const std::string& overview) {
  std::string err;
  json11::Json json = json11::Json::parse(overview, err);
  if (!err.empty())
    throw FormatError("Unable to parse JSON data in entry overview.");

  for (const auto& obj : json.object_items()) {
    if (obj.first == "title") {
      assert(obj.second.is_string());
      title_ = obj.second.string_value();
    } else if (obj.first == "ps") {
      assert(obj.second.is_number());
      // FIXME: Don't know what this is.
    } else if (obj.first == "tags") {
      assert(obj.second.is_array());

      for (const auto& item : obj.second.array_items()) {
        assert(item.is_string());
        tags_.push_back(item.string_value());
      }
    } else if (obj.first == "ainfo") {
      assert(obj.second.is_string());
      info_ = obj.second.string_value();
    } else if (obj.first == "url") {
      assert(obj.second.is_string());
      url_ = obj.second.string_value();
    } else if (obj.first == "URLs") {
      assert(obj.second.is_array());

      for (const auto& item : obj.second.array_items()) {
        assert(item.is_object());
        for (const auto& obj : item.object_items()) {
          assert(obj.second.is_string());
          urls_.insert(std::make_pair(obj.first, obj.second.string_value()));
        }
      }
    } else {
      assert(false);
    }
  }
}

void Entry::UpdateFromDetails(const std::string& details) {
  std::string err;
  json11::Json json = json11::Json::parse(details, err);
  if (!err.empty())
    throw FormatError("Unable to parse JSON data in entry details.");

  for (const auto& obj : json.object_items()) {
    if (obj.first == "sections") {
      assert(obj.second.is_array());

      for (const auto& item : obj.second.array_items()) {
        assert(item.is_object());
        sections_.push_back(std::make_shared<Section>(item));
      }
    } else if (obj.first == "fields") {
      assert(obj.second.is_array());

      for (const auto& item : obj.second.array_items()) {
        assert(item.is_object());
        fields_.push_back(std::make_shared<Field>(item));
      }
    } else if (obj.first == "htmlForm") {
      assert(obj.second.is_object());

      assert(!form_);
      form_ = std::make_shared<Form>(obj.second);
    } else if (obj.first == "notesPlain") {
      assert(obj.second.is_string());
      notes_ = obj.second.string_value();
    } else if (obj.first == "passwordHistory") {
      assert(obj.second.is_array());
      for (const auto& item : obj.second.array_items()) {
        assert(item.is_object());
        password_history_.push_back(std::make_shared<PasswordHistory>(item));
      }
    } else {
      assert(false);
    }
  }
}

Entry::Entry(const std::array<uint8_t, 16>& uuid,
             const json11::Json& json,
             Profile& profile) :
    uuid_(uuid) {
  assert(json.is_object());

  std::string details;

  std::array<uint8_t, 32> key = { 0 };
  std::array<uint8_t, 32> mac_key = { 0 };
  std::array<uint8_t, 32> hmac = { 0 };

  for (const auto& obj : json.object_items()) {
    if (obj.first == "category") {
      assert(obj.second.is_string());
      category_ = CategoryFromString(obj.second.string_value());
    } else if (obj.first == "created") {
      assert(obj.second.is_number());
      creation_time_ = static_cast<std::time_t>(obj.second.number_value());
    } else if (obj.first == "tx") {
      assert(obj.second.is_number());
      transaction_time_ = static_cast<std::time_t>(obj.second.number_value());
    } else if (obj.first == "updated") {
      assert(obj.second.is_number());
      modification_time_ = static_cast<std::time_t>(obj.second.number_value());
    } else if (obj.first == "uuid") {
      assert(obj.second.is_string());
      std::array<uint8_t, 16> uuid = ParseUuid(
          obj.second.string_value());
      if (uuid_ != uuid) {
        assert(false);
        throw FormatError(
            "Entry internal and external UUIDs does not match.");
      }
    } else if (obj.first == "d") {
      assert(obj.second.is_string());
      details = base64_decode(obj.second.string_value());
    } else if (obj.first == "k") {
      assert(obj.second.is_string());
      std::string k = ReadData(base64_decode(obj.second.string_value()),
                               profile.master_key(),
                               profile.master_mac_key());
      if (k.size() != 64)
        throw FormatError("Entry key data is of incorrect size.");

      std::copy(k.c_str(), k.c_str() + 32, key.begin());
      std::copy(k.c_str() + 32, k.c_str() + 64, mac_key.begin());
    } else if (obj.first == "o") {
      assert(obj.second.is_string());
      UpdateFromOverview(ReadOpData(
          base64_decode(obj.second.string_value()),
          profile.overview_key(),
          profile.overview_mac_key()));
    } else if (obj.first == "hmac") {
      assert(obj.second.is_string());
      std::string hmac_str = base64_decode(obj.second.string_value());
      if (hmac_str.size() != 32)
        throw FormatError("Entry HMAC is of incorrect size.");

      std::copy(hmac_str.begin(), hmac_str.end(), hmac.begin());
    } else if (obj.first == "trashed") {
      if (!obj.second.is_bool())
        throw FormatError("Entry trashed flag is not a boolean.");
      trashed_ = obj.second.bool_value();
    } else if (obj.first == "folder") {
      assert(obj.second.is_string());
      folder_uuid_ = ParseUuid(obj.second.string_value());
    } else if (obj.first == "fave") {
      assert(obj.second.is_number());
      fave_ = static_cast<uint32_t>(obj.second.number_value());
    } else {
      assert(false);
    }
  }

  // Decrypt details.
  UpdateFromDetails(ReadOpData(details, key, mac_key));
}

void Bands::LoadIfExists(const std::string path, Profile& profile) {
  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    return;

  std::string text;
  std::copy(std::istreambuf_iterator<char>(src), 
            std::istreambuf_iterator<char>(), 
            std::back_inserter(text));

  std::string err;
  json11::Json json = json11::Json::parse(ExtractJson(text), err);
  if (!err.empty())
    throw FormatError("Unable to parse JSON data in profile.");

  for (const auto& obj : json.object_items()) {
    assert(obj.second.is_object());
    entries_.push_back(std::make_shared<Entry>(
        ParseUuid(obj.first), obj.second, profile));
  }
}

void Bands::Load(const std::string& dir_path, Profile& profile) {
  assert(!profile.IsLocked());

  for (std::size_t i = 0; i < 10; ++i) {
    std::string path = dir_path;
    path.append("/band_");
    path.append(std::to_string(i));
    path.append(".js");

    LoadIfExists(path, profile);
  }

  for (char c = 'A'; c < 'G'; ++c) {
    std::string path = dir_path;
    path.append("/band_");
    path.push_back(c);
    path.append(".js");

    LoadIfExists(path, profile);
  }
}

}   // namespace onepass
