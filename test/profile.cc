/*
 * libonepass - 1Password key database importer/exporter
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

#include <set>

#include <gtest/gtest.h>

#include "exception.hh"
#include "profile.hh"

using namespace onepass;

namespace {

std::string GetTestPath(const std::string& name) {
  return "./test/data/" + name;
}

std::string GetTestProfilePath(const std::string& name) {
  return GetTestPath(name) + "/default/profile.js";
}

} // namespace

TEST(ProfileTest, NonExistingFile) {
  Profile profile;
  EXPECT_THROW(profile.Load("./test/data/non_existing.js"),
               FileNotFoundError);
}

TEST(ProfileTest, NonProfileFile) {
  Profile profile;
  EXPECT_THROW(profile.Load(GetTestPath("freddy-2013-12-04") +
      "/default/1C7D72EFA19A4EE98DB7A9661D2F5732_3B94A1F475014E27BFB00C99A42214DF.attachment"), FormatError);
}

TEST(ProfileTest, CorrectPassword) {
  Profile profile;
  EXPECT_NO_THROW(profile.Load(GetTestProfilePath("freddy-2013-12-04")));
  EXPECT_NO_THROW(profile.Unlock("freddy"));
}

TEST(KdbxTest, InvalidPassword) {
  Profile profile;
  EXPECT_NO_THROW(profile.Load(GetTestProfilePath("freddy-2013-12-04")));
  EXPECT_THROW(profile.Unlock("wrong_password"),
               PasswordError);
}
