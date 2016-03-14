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

#ifndef OPENTXS_CORE_OTIDENTIFIER_HPP
#define OPENTXS_CORE_OTIDENTIFIER_HPP

#include <opentxs/core/crypto/CryptoHash.hpp>
#include "OTData.hpp"

#include <string>

// An Identifier is basically a 256 bit hash value.
// This class makes it easy to convert IDs back and forth to strings.

namespace opentxs
{

class OTCachedKey;
class Contract;
class Nym;
class String;
class OTSymmetricKey;

class Identifier : public OTData
{
public:
    EXPORT friend std::ostream& operator<<(std::ostream& os, const String& obj);
    EXPORT static const CryptoHash::HashType DefaultHashAlgorithm;
    EXPORT static bool validateID(const std::string & strPurportedID);

    EXPORT Identifier();

    EXPORT Identifier(const Identifier& theID);
    EXPORT Identifier(const char* szStr);
    EXPORT Identifier(const std::string& szStr);
    EXPORT Identifier(const String& theStr);
    EXPORT Identifier(const Nym& theNym);
    EXPORT Identifier(const Contract& theContract);
    EXPORT Identifier(const OTSymmetricKey& theKey);
    EXPORT Identifier(const OTCachedKey& theKey);

    EXPORT virtual ~Identifier();
    using OTData::swap;
    EXPORT Identifier& operator=(Identifier rhs);
    EXPORT bool operator==(const Identifier& s2) const;
    EXPORT bool operator!=(const Identifier& s2) const;

    EXPORT bool operator>(const Identifier& s2) const;
    EXPORT bool operator<(const Identifier& s2) const;
    EXPORT bool operator<=(const Identifier& s2) const;
    EXPORT bool operator>=(const Identifier& s2) const;
    EXPORT bool CalculateDigest(const OTData& dataInput);
    EXPORT bool CalculateDigest(const String& strInput);

    // If someone passes in the pretty string of alphanumeric digits,
    // convert it to the actual binary hash and set it internally.
    EXPORT void SetString(const char* szString);
    EXPORT void SetString(const String& theStr);
    // theStr will contain pretty hex string after call.
    EXPORT void GetString(String& theStr) const;
};

} // namespace opentxs

#endif // OPENTXS_CORE_OTIDENTIFIER_HPP
