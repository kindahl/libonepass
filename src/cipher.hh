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
#include <cassert>
#include <cstdint>
#include <memory>
#include <iostream>

#include <openssl/aes.h>

namespace onepass {

template <std::size_t N>
class Cipher;

std::array<uint8_t, 32> encrypt_ecb(const std::array<uint8_t, 32>& src,
                                    const Cipher<16>& cipher);
std::array<uint8_t, 32> decrypt_ecb(const std::array<uint8_t, 32>& src,
                                    const Cipher<16>& cipher);
void encrypt_cbc(std::istream& src, std::ostream& dst,
                 const Cipher<16>& cipher);
void decrypt_cbc(std::istream& src, std::ostream& dst,
                 const Cipher<16>& cipher);

template <std::size_t N>
class Cipher {
 public:
  virtual ~Cipher() = default;

  virtual const std::array<uint8_t, N>& InitializationVector() const = 0;

  virtual void Decrypt(const std::array<uint8_t, N>& src,
                       std::array<uint8_t, N>& dst) const = 0;
  virtual void Encrypt(const std::array<uint8_t, N>& src,
                       std::array<uint8_t, N>& dst) const = 0;
};

class AesCipher final : public Cipher<16> {
 private:
  const std::array<uint8_t, 16> init_vec_;
  AES_KEY key_dec_;
  AES_KEY key_enc_;

 public:
  AesCipher(const std::array<uint8_t, 32>& key) :
    AesCipher(key, { 0 }) {}
  AesCipher(const std::array<uint8_t, 32>& key,
            const std::array<uint8_t, 16>& init_vec);

  const std::array<uint8_t, 16>& InitializationVector() const override {
    return init_vec_;
  }

  virtual void Decrypt(const std::array<uint8_t, 16>& src,
                       std::array<uint8_t, 16>& dst) const override;
  virtual void Encrypt(const std::array<uint8_t, 16>& src,
                       std::array<uint8_t, 16>& dst) const override;
};

}
