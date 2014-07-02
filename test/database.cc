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

#include "database.hh"
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

TEST(DatabaseTest, GetPasswords) {
  Profile profile;
  EXPECT_NO_THROW(profile.Load(GetTestProfilePath("freddy-2013-12-04")));
  EXPECT_NO_THROW(profile.Unlock("freddy"));

  Database db;
  EXPECT_NO_THROW(db.Load(GetTestPath("freddy-2013-12-04"), profile));

  std::vector<Database::LoginItem> logins = db.GetLoginItems();
  EXPECT_EQ(logins.size(), 10);
  EXPECT_EQ(logins[0].url(), "http://www.hulu.com/");
  EXPECT_EQ(logins[0].password(), "frirp7i1ob7wig4d");
  EXPECT_EQ(logins[1].url(), "https://secure.skype.com/account/login?message=login_required");
  EXPECT_EQ(logins[1].password(), "dej3ur9unsh5ian1and5");
  EXPECT_EQ(logins[2].url(), "http://www.youtube.com/login?next=/index");
  EXPECT_EQ(logins[2].password(), "snaip5uc5keds7as5ocs");
  EXPECT_EQ(logins[3].url(), "https://www.getdropbox.com/");
  EXPECT_EQ(logins[3].password(), "vet4juf4nim1ow6ay2ph");
  EXPECT_EQ(logins[4].url(), "ftp://ftp.dreamhost.com");
  EXPECT_EQ(logins[4].password(), "auj7r5?u61ww");
  EXPECT_EQ(logins[5].url(), "http://www.tumblr.com/login");
  EXPECT_EQ(logins[5].password(), "vow6wem2wo");
  EXPECT_EQ(logins[6].url(), "https://www.last.fm/login");
  EXPECT_EQ(logins[6].password(), "dowg1af5kam7oak9at");
  EXPECT_EQ(logins[7].url(), "http://www.tuaw.com");
  EXPECT_EQ(logins[7].password(), "tiac1nut2jab1eiv2oc5");
  EXPECT_EQ(logins[8].url(), "https://www.bankofamerica.com/");
  EXPECT_EQ(logins[8].password(), "");
  EXPECT_EQ(logins[9].url(), "https://www.icloud.com/");
  EXPECT_EQ(logins[9].password(), "iINe4uig8suLny");
}
