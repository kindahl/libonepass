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

#include <iostream>

#include "database.hh"
#include "profile.hh"

using namespace onepass;

int main(int argc, const char* argv[]) {
  if (argc != 2) {
    std::cerr << "error: invalid usage." << std::endl;
    return 1;
  }

  std::string path = argv[1];

  try {
    Profile profile;
    profile.Load(path + "/default/profile.js");
    profile.Unlock("freddy");

    Database db;
    db.Load(path, profile);
  } catch (std::exception& e) {
    std::cerr << "error: " << e.what() << std::endl;
  }

  return 0;
}
