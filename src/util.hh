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
#include <string>

namespace onepass {

/**
 * Clamps a value into a specific range.
 * @param [in] min Minimum value.
 * @param [in] max Maximum value.
 * @param [in] val Value to clamp.
 * @return Clamped @a val.
 */
template <typename T>
inline T clamp(T min, T max, T val) {
  return std::max<T>(min, std::min<T>(max, val));
}

/**
 * Extracts the JSON part from a 1Password .js file. The file really is
 * JavaScript and not JSON but this function does some assumptions in order
 * to find the actual JSON content.
 * @param [in] text JavaScript test.
 * @return JSON content contained in @a text.
 */
std::string ExtractJson(const std::string& text);

/**
 * Parses a string of 16 hexadecimal characters into a an UUID byte array.
 * @param [in] hex String of hexadecimal characters to parse.
 * @return UUID.
 */
std::array<uint8_t, 16> ParseUuid(const std::string hex);

}   // namespace onepass
