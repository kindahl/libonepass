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

#include "util.hh"

#include <locale>

#include "exception.hh"

namespace onepass {

std::string ExtractJson(const std::string& text) {
  std::string::size_type start = text.find('{');
  std::string::size_type end = text.rfind('}');
  if (start == std::string::npos || end == std::string::npos)
    throw FormatError("Unable to extract JSON from JavaScript source.");

  if (start >= end)
    throw FormatError("Unable to extract JSON from JavaScript source.");

  return text.substr(start, end - start + 1);
}

std::array<uint8_t, 16> ParseUuid(const std::string hex) {
  if (hex.size() != 32)
    throw FormatError("Invalid UUID length.");

  std::array<uint8_t, 16> uuid = { 0 };
  for (std::size_t i = 0, j = 0; i < hex.size(); i += 2, ++j) {
    char c0 = std::tolower(hex[i], std::locale::classic());
    char c1 = std::tolower(hex[i + 1], std::locale::classic());

    uint8_t v = 0;
    if (c0 >= 'a' && c0 <= 'f') {
      v = (static_cast<uint8_t>(c0 - 'a') + 10) * 16;
    } else if (c0 >= '0' && c0 <= '9') {
      v = static_cast<uint8_t>(c0 - '0') * 16;
    } else {
      throw FormatError("Unexpected character in UUID.");
    }

    if (c1 >= 'a' && c1 <= 'f') {
      v += (static_cast<uint8_t>(c1 - 'a') + 10);
    } else if (c1 >= '0' && c1 <= '9') {
      v += static_cast<uint8_t>(c1 - '0');
    } else {
      throw FormatError("Unexpected character in UUID.");
    }

    uuid[j] = v;
  }

  return uuid;
}

}   // namespace onepass
