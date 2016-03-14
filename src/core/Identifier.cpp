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

#include <opentxs/core/stdafx.hpp>

#include <opentxs/core/Identifier.hpp>
#include <opentxs/core/Contract.hpp>
#include <opentxs/core/crypto/OTCachedKey.hpp>
#include <opentxs/core/app/App.hpp>
#include <opentxs/core/Nym.hpp>
#include <opentxs/core/crypto/OTSymmetricKey.hpp>
#include <bitcoin-base58/hash.h>
#include <cstring>
#include <iostream>

namespace opentxs
{

Identifier::Identifier()
    : OTData()
{
}

Identifier::Identifier(const Identifier& theID)
    : OTData(theID)
{
}

Identifier::Identifier(const char* szStr)
    : OTData()
{
    OT_ASSERT(nullptr != szStr);
    SetString(szStr);
}

Identifier::Identifier(const std::string& theStr)
    : OTData()
{
    if (theStr.empty()) {
        SetString("");
    } else {
        SetString(theStr.c_str());
    }
}

Identifier::Identifier(const String& theStr)
    : OTData()
{
    SetString(theStr);
}

Identifier::Identifier(const Contract& theContract)
    : OTData() // Get the contract's ID into this identifier.
{
    (const_cast<Contract&>(theContract)).GetIdentifier(*this);
}

Identifier::Identifier(const Nym& theNym)
    : OTData() // Get the Nym's ID into this identifier.
{
    (const_cast<Nym&>(theNym)).GetIdentifier(*this);
}

Identifier::Identifier(const OTSymmetricKey& theKey)
    : OTData() // Get the Symmetric Key's ID into *this. (It's a hash of the
               // encrypted form of the symmetric key.)
{
    (const_cast<OTSymmetricKey&>(theKey)).GetIdentifier(*this);
}

Identifier::Identifier(const OTCachedKey& theKey)
    : OTData() // Cached Key stores a symmetric key inside, so this actually
               // captures the ID for that symmetrickey.
{
    const bool bSuccess =
        (const_cast<OTCachedKey&>(theKey)).GetIdentifier(*this);

    OT_ASSERT(bSuccess); // should never fail. If it does, then we are calling
                         // this function at a time we shouldn't, when we aren't
                         // sure the master key has even been generated yet. (If
                         // this asserts, need to examine the line of code that
                         // tried to do this, and figure out where its logic
                         // went wrong, since it should have made sure this
                         // would not happen, before constructing like this.)
}

Identifier& Identifier::operator=(Identifier rhs)
{
    swap(rhs);
    return *this;
}

void Identifier::SetString(const char* szString)
{
    OT_ASSERT(nullptr != szString);
    const String theStr(szString);
    SetString(theStr);
}

bool Identifier::operator==(const Identifier& s2) const
{
    const String ots1(*this), ots2(s2);
    return ots1.Compare(ots2);
}

bool Identifier::operator!=(const Identifier& s2) const
{
    const String ots1(*this), ots2(s2);
    return !(ots1.Compare(ots2));
}

bool Identifier::operator>(const Identifier& s2) const
{
    const String ots1(*this), ots2(s2);
    return ots1.operator>(ots2);
}

bool Identifier::operator<(const Identifier& s2) const
{
    const String ots1(*this), ots2(s2);
    return ots1.operator<(ots2);
}

bool Identifier::operator<=(const Identifier& s2) const
{
    const String ots1(*this), ots2(s2);
    return ots1.operator<=(ots2);
}

bool Identifier::operator>=(const Identifier& s2) const
{
    const String ots1(*this), ots2(s2);
    return ots1.operator>=(ots2);
}

Identifier::~Identifier()
{
}

bool Identifier::validateID(const std::string & strPurportedID)
{
    if (strPurportedID.empty())
        return false;
    Identifier theID;
    const String strID(strPurportedID);
    App::Me().Crypto().Util().SetIDFromEncoded(strID, theID);
    return !theID.empty();
}

// When calling SignContract or VerifySignature with "HASH256" as the hash type,
// the signature will use (sha256 . sha256) as a message digest.
// In this case, SignContractDefaultHash and VerifyContractDefaultHash are used,
// which resort to low level calls to accomplish non standard message digests.
// Otherwise, it will use whatever OpenSSL provides by that name (see
// GetOpenSSLDigestByName).
const CryptoHash::HashType Identifier::DefaultHashAlgorithm = CryptoHash::SHA256;

bool Identifier::CalculateDigest(const String& strInput)
{
    return App::Me().Crypto().Hash().Digest(
        CryptoHash::HASH160,
        strInput,
        *this);
}

bool Identifier::CalculateDigest(const OTData& dataInput)
{
    return App::Me().Crypto().Hash().Digest(
        CryptoHash::HASH160,
        dataInput,
        *this);
}

// SET (binary id) FROM ENCODED STRING
//
void Identifier::SetString(const String& theStr)
{
    App::Me().Crypto().Util().SetIDFromEncoded(theStr, *this);
}

// This Identifier is stored in binary form.
// But what if you want a pretty string version of it?
// Just call this function.
//
void Identifier::GetString(String& theStr) const
{
    App::Me().Crypto().Util().EncodeID(*this, theStr); // *this input, theStr output.
}

} // namespace opentxs
