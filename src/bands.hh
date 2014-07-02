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
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace json11 {
  class Json;
} // namespace json11

namespace onepass {

class Profile;

class Entry final {
 public:
  enum class Category {
    kLogin = 1,
    kCreditCard = 2,
    kSecureNote = 3,
    kIdentity = 4,
    kPassword = 5,
    kTombstone = 99,
    kSoftwareLicense = 100,
    kBankAccount = 101,
    kDatabase = 102,
    kDriverLicense = 103,
    kOutdoorLicense = 104,
    kMembership = 105,
    kPassport = 106,
    kRewards = 107,
    kSocialSecurityNumber = 108,
    kRouter = 109,
    kServer = 110,
    kEmail = 111
  };

  class Field final {
   private:
    std::string key_;
    std::string value_; ///< Raw JSON value, including quotes for strings.
    std::string name_;
    std::string title_;
    std::string designation_;
    std::string type_;
    std::map<std::string, std::string> attributes_;

   public:
    Field(const json11::Json& json);

    const std::string& key() const { return key_; }
    const std::string& value() const { return value_; }
    const std::string& name() const { return name_; }
    const std::string& title() const { return title_; }
    const std::string& designation() const { return designation_; }
    const std::string& type() const { return type_; }
    const std::map<std::string, std::string>& attributes() const {
      return attributes_;
    }
  };

  class Section final {
   private:
    std::string name_;
    std::string title_;
    std::vector<std::shared_ptr<Field>> fields_;

   public:
    Section(const json11::Json& json);

    const std::string& name() const { return name_; }
    const std::string& title() const { return title_; }
    const std::vector<std::shared_ptr<Field>>& fields() const {
      return fields_;
    }
  };

  class Form final {
   public:
    enum class Method {
      kGet,
      kPost
    };

   private:
    std::string action_;
    std::string name_;
    std::string id_;
    Method method_ = Method::kGet;

   public:
    Form(const json11::Json& json);

    const std::string& action() const { return action_; }
    const std::string& name() const { return name_; }
    const std::string& id() const { return id_; }
    Method method() const { return method_; }
  };

  class PasswordHistory {
   private:
    std::string value_;
    std::time_t time_;

   public:
    PasswordHistory(const json11::Json& json);

    const std::string& value() const { return value_; }
    std::time_t time() const { return time_; }
  };

 private:
  std::array<uint8_t, 16> uuid_ = { { 0 } };
  std::array<uint8_t, 16> folder_uuid_ = { { 0 } };
  Category category_ = Category::kLogin;
  std::time_t creation_time_ = 0;
  std::time_t modification_time_ = 0;
  std::time_t transaction_time_ = 0;
  bool trashed_ = false;
  uint32_t fave_ = 0;
  std::string title_;
  std::string info_;
  std::string url_;
  std::string notes_;
  std::shared_ptr<Form> form_;
  std::map<std::string, std::string> urls_;
  std::vector<std::string> tags_;
  std::vector<std::shared_ptr<Section>> sections_;
  std::vector<std::shared_ptr<Field>> fields_;
  std::vector<std::shared_ptr<PasswordHistory>> password_history_;

  void UpdateFromOverview(const std::string& overview);
  void UpdateFromDetails(const std::string& details);

 public:
  Entry(const std::array<uint8_t, 16>& uuid,
        const json11::Json& json,
        Profile& profile);

  const std::array<uint8_t, 16>& uuid() const { return uuid_; }
  const std::array<uint8_t, 16>& folder_uuid() const { return folder_uuid_; }
  Category category() const { return category_; }
  std::time_t creation_time() const { return creation_time_; }
  std::time_t modification_time() const { return modification_time_; }
  std::time_t transaction_time() const { return transaction_time_; }
  bool trashed() const { return trashed_; }
  uint32_t fave() const { return fave_; }
  const std::string& title() const { return title_; }
  const std::string& info() const { return info_; }
  const std::string& url() const { return url_; }
  const std::string& notes() const { return notes_; }
  std::shared_ptr<Form> form() const { return form_; }
  const std::map<std::string, std::string>& urls() const { return urls_; }
  const std::vector<std::string>& tags() const { return tags_; }
  const std::vector<std::shared_ptr<Section>>& sections() const {
    return sections_;
  }
  const std::vector<std::shared_ptr<Field>>& fields() const { return fields_; }
  const std::vector<std::shared_ptr<PasswordHistory>>&
      password_history() const { return password_history_; }
};

class Bands final {
 private:
  std::vector<std::shared_ptr<Entry>> entries_;

  void LoadIfExists(const std::string path, Profile& profile);

 public:
  void Load(const std::string& dir_path, Profile& profile);

  const std::vector<std::shared_ptr<Entry>>& entries() const {
    return entries_;
  }
};

}   // namespace onepass
