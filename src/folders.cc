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

#include "folders.hh"

#include <cassert>
#include <fstream>

#include "base64.hh"
#include "exception.hh"
#include "json11.hh"
#include "opdata.hh"
#include "profile.hh"
#include "util.hh"

namespace onepass {

Folder::Folder(const std::array<uint8_t, 16>& uuid,
               const json11::Json& json,
               Profile& profile) :
    uuid_(uuid) {
  for (const auto& obj : json.object_items()) {
    if (obj.first == "created") {
      assert(obj.second.is_number());
      creation_time_ = static_cast<std::time_t>(obj.second.number_value());
    } else if (obj.first == "overview") {
      assert(obj.second.is_string());
      UpdateFromOverview(ReadOpData(
          base64_decode(obj.second.string_value()),
          profile.overview_key(),
          profile.overview_mac_key()));
    } else if (obj.first == "tx") {
      assert(obj.second.is_number());
      transaction_time_ = static_cast<std::time_t>(obj.second.number_value());
    } else if (obj.first == "updated") {
      assert(obj.second.is_number());
      modification_time_ = static_cast<std::time_t>(obj.second.number_value());
    } else if (obj.first == "uuid") {
      assert(obj.second.is_string());
      std::array<uint8_t, 16> uuid = ParseUuid(obj.second.string_value());
      if (uuid_ != uuid) {
        assert(false);
        throw FormatError(
            "Folder internal and external UUIDs does not match.");
      }
    } else if (obj.first == "smart") {
      if (!obj.second.is_bool())
        throw FormatError("Folder smart flag is not a boolean.");
      smart_ = obj.second.bool_value();
    } else {
      assert(false);
    }
  }
}

void Folder::UpdateFromOverview(const std::string& overview) {
  std::string err;
  json11::Json json = json11::Json::parse(overview, err);
  if (!err.empty())
    throw FormatError("Unable to parse JSON data in folder overview.");

  for (const auto& obj : json.object_items()) {
    if (obj.first == "title") {
      assert(obj.second.is_string());
      title_ = obj.second.string_value();
    } else if (obj.first == "predicate_b64") {
      assert(obj.second.is_string());

      // For some reason there appears to be a strange a trailing character at
      // the end of the base64 encoded predicate. I don't know why that is, but
      // decoding works fine when removing it.
      std::string pred = obj.second.string_value();
      if (pred.size() % 4 != 0) {
        std::string::size_type pos = pred.rfind('=');
        if (pos != std::string::npos)
          pred = pred.substr(0, pos + 1);
      }

      pred = base64_decode(pred);
      if (pred.size() > 8 && pred.substr(0, 8) == "bplist00") {
        // FIXME: bplist00 appears to be an Apple format of some sort. Not sure
        //        if it's worth parsing it.
      }
    } else {
      assert(false);
    }
  }
}

void Folders::Load(const std::string& path, Profile& profile) {
  assert(!profile.IsLocked());

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

  for (const auto& obj : json.object_items()) {
    assert(obj.second.is_object());
    folders_.push_back(
        std::make_shared<Folder>(ParseUuid(obj.first),
                                 obj.second,
                                 profile));
  }
}

}   // namespace onepass
