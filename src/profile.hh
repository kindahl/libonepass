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
#include <string>
#include <vector>

namespace onepass {

class Profile final {
 private:
  std::array<uint8_t, 16> uuid_ = { { 0 } };
  std::time_t creation_time_ = 0;
  std::time_t modification_time_ = 0;
  std::string name_;
  std::string last_updater_;
  uint32_t iterations_ = 0;
  std::vector<uint8_t> salt_;
  std::string locked_master_key_;
  std::string locked_overview_key_;

  std::array<uint8_t, 32> master_key_ = { { 0 } };
  std::array<uint8_t, 32> master_mac_key_ = { { 0 } };
  std::array<uint8_t, 32> overview_key_ = { { 0 } };
  std::array<uint8_t, 32> overview_mac_key_ = { { 0 } };

 public:
  void Load(const std::string& path);

  bool IsLocked() const;
  void Unlock(const std::string& password);
  void Lock();

  const std::array<uint8_t, 32> &master_key() const { return master_key_; }
  const std::array<uint8_t, 32> &master_mac_key() const {
    return master_mac_key_;
  }
  const std::array<uint8_t, 32> &overview_key() const { return overview_key_; }
  const std::array<uint8_t, 32> &overview_mac_key() const {
    return overview_mac_key_;
  }
};

}   // namespace onepass
