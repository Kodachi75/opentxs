/************************************************************
 *
 *                 OPEN TRANSACTIONS
 *
 *       Financial Cryptography and Digital Cash
 *       Library, Protocol, API, Server, CLI, GUI
 *
 *       -- Anonymous Numbered Accounts.
 *       -- Untraceable Digital Cash.
 *       -- Triple-Signed Receipts.
 *       -- Cheques, Vouchers, Transfers, Inboxes.
 *       -- Basket Currencies, Markets, Payment Plans.
 *       -- Signed, XML, Ricardian-style Contracts.
 *       -- Scripted smart contracts.
 *
 *  EMAIL:
 *  fellowtraveler@opentransactions.org
 *
 *  WEBSITE:
 *  http://www.opentransactions.org/
 *
 *  -----------------------------------------------------
 *
 *   LICENSE:
 *   This Source Code Form is subject to the terms of the
 *   Mozilla Public License, v. 2.0. If a copy of the MPL
 *   was not distributed with this file, You can obtain one
 *   at http://mozilla.org/MPL/2.0/.
 *
 *   DISCLAIMER:
 *   This program is distributed in the hope that it will
 *   be useful, but WITHOUT ANY WARRANTY; without even the
 *   implied warranty of MERCHANTABILITY or FITNESS FOR A
 *   PARTICULAR PURPOSE.  See the Mozilla Public License
 *   for more details.
 *
 ************************************************************/

#ifndef OPENTXS_CORE_CRYPTO_BIP32_HPP
#define OPENTXS_CORE_CRYPTO_BIP32_HPP

#include <string>

#include <opentxs-proto/verify/VerifyCredentials.hpp>

#include <opentxs/core/crypto/CryptoSymmetric.hpp>
#include <opentxs/core/crypto/OTAsymmetricKey.hpp>
#include <opentxs/core/crypto/PaymentCode.hpp>

namespace opentxs
{
const uint32_t NYM_PURPOSE = 0x4f544e4d; // OTNM
const uint32_t PC_PURPOSE = 47; // BIP-47
const uint32_t HARDENED = 0x80000000; // set MSB to indicate hardened derivation
const uint32_t BITCOIN_TYPE = 0; // coin type
const uint32_t AUTH_KEY = 0x41555448; // AUTH
const uint32_t ENCRYPT_KEY = 0x454e4352; // ENCR
const uint32_t SIGN_KEY = 0x5349474e; // SIGN

class OTPassword;

class Bip32
{
public:
    virtual std::string SeedToFingerprint(
        const OTPassword& seed) const = 0;
    virtual serializedAsymmetricKey SeedToPrivateKey(
        const OTPassword& seed) const = 0;
    virtual serializedAsymmetricKey GetChild(
        const proto::AsymmetricKey& parent,
        const uint32_t index) const = 0;
    virtual serializedAsymmetricKey PrivateToPublic(
        const proto::AsymmetricKey& key) const = 0;

    BinarySecret GetHDSeed() const;
    serializedAsymmetricKey GetHDKey(proto::HDPath& path) const;
    serializedAsymmetricKey GetPaymentCode(const uint32_t nym) const;

};

} // namespace opentxs

#endif // OPENTXS_CORE_CRYPTO_BIP32_HPP
