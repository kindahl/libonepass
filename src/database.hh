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
#include "folders.hh"
#include "bands.hh"

namespace onepass {

class Profile;

class Database final {
 public:
  class LoginItem final {
   private:
    std::string url_;
    std::string password_;

   public:
    LoginItem(const std::string& url, const std::string& password) :
        url_(url), password_(password) {}

    const std::string& url() const { return url_; }
    const std::string& password() const { return password_; }
  };

 private:
  Folders folders_;
  Bands bands_;

 public:
  void Load(const std::string& path, Profile& profile);

  std::vector<LoginItem> GetLoginItems() const;
};

}   // namespace onepass
