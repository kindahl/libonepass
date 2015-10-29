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
#include <algorithm>
#include <cassert>
#include <memory>
#include <istream>
#include <ostream>

#include "util.hh"

namespace onepass {

template <std::size_t N>
class array_iostreambuf :
    public std::basic_streambuf<char, std::char_traits<char>> {
 private:
  std::array<uint8_t, N>& buffer_;

 protected:
  virtual std::streampos seekoff(std::streamoff off,
                                 std::ios_base::seekdir way,
                                 std::ios_base::openmode which) override {
    if (which == 0)
      return std::streampos(std::streamoff(-1));

    off = clamp<std::streamoff>(0, buffer_.size(), off);

    std::streamoff lin_off = 0;
    switch (way) {
      case std::ios_base::beg:
        lin_off = clamp<std::streamoff>(0, buffer_.size(), off);
        break;
      case std::ios_base::cur:
        lin_off = clamp<std::streamoff>(0, buffer_.size(), (gptr() - eback()) + off);
        break;
      case std::ios_base::end:
        lin_off = clamp<std::streamoff>(0, buffer_.size(), buffer_.size() - off);
        break;
      default:
        assert(false);
        break;
    };

    if (which & std::ios_base::in) {
      char* buffer_ptr = reinterpret_cast<char*>(buffer_.data());
      setg(buffer_ptr, buffer_ptr + lin_off, buffer_ptr + buffer_.size());
    }

    return lin_off;
  }

  virtual std::streampos seekpos(std::streampos sp,
                                 std::ios_base::openmode which) override {
    if (which == 0 || sp < 0 ||
        sp >= static_cast<std::streampos>(buffer_.size())) {
      return std::streampos(std::streamoff(-1));
    }

    if (which & std::ios_base::in) {
      char* buffer_ptr = reinterpret_cast<char*>(buffer_.data());
      setg(buffer_ptr, buffer_ptr + sp, buffer_ptr + buffer_.size());
    }

    return sp;
  }

 public:
  array_iostreambuf(std::array<uint8_t, N>& buffer) : buffer_(buffer) {
    char* buffer_ptr = reinterpret_cast<char*>(buffer.data());
    setg(buffer_ptr, buffer_ptr, buffer_ptr + buffer.size());
    setp(buffer_ptr, buffer_ptr + buffer.size());
  }
};

}   // namespace onepass
