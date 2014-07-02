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

#pragma once
#include <array>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

namespace json11 {
  class Json;
} // namespace json11

namespace onepass {

class Profile;

class Folder final {
 private:
  std::array<uint8_t, 16> uuid_ = { { 0 } };
  std::time_t creation_time_ = 0;
  std::time_t modification_time_ = 0;
  std::time_t transaction_time_ = 0;
  std::string title_;
  bool smart_ = false;

  void UpdateFromOverview(const std::string& overview);

 public:
  Folder(const std::array<uint8_t, 16>& uuid,
         const json11::Json& json,
         Profile& profile);

  const std::array<uint8_t, 16>& uuid() const { return uuid_; }
  std::time_t creation_time() const { return creation_time_; }
  void set_creation_time(std::time_t time) { creation_time_ = time; }
  std::time_t modification_time() const { return modification_time_; }
  void set_modification_time(std::time_t time) { modification_time_ = time; }
  std::time_t transaction_time() const { return transaction_time_; }
  void set_transaction_time(std::time_t time) { transaction_time_ = time; }
  bool smart() const { return smart_; }
  void set_smart(bool smart) { smart_ = smart; }
};

class Folders final {
 private:
  std::vector<std::shared_ptr<Folder>> folders_;

 public:
  void Load(const std::string& path, Profile& profile);

  const std::vector<std::shared_ptr<Folder>>& folders() const {
    return folders_;
  }
};

}   // namespace onepass
