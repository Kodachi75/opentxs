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

#ifndef OPENTXS_CORE_CRYPTO_OTENVELOPE_HPP
#define OPENTXS_CORE_CRYPTO_OTENVELOPE_HPP

#include <opentxs/core/OTData.hpp>

#include <map>
#include <set>
#include <string>

namespace opentxs
{

class OTASCIIArmor;
class OTAsymmetricKey;
class OTPassword;
class OTPasswordData;
class Nym;
class String;
class OTSymmetricKey;
class Letter;

typedef std::multimap<std::string, OTAsymmetricKey*> mapOfAsymmetricKeys;
typedef std::set<const Nym*> setOfNyms;

class OTEnvelope
{
    friend Letter;
    OTData m_dataContents; // Stores only encrypted contents.

public:
    EXPORT OTEnvelope();
    EXPORT OTEnvelope(const OTASCIIArmor& theArmoredText);
    EXPORT OTEnvelope(const String& strArmorWithBookends);
    EXPORT virtual ~OTEnvelope();

    // SYMMETRIC CRYPTO  (AES)

    EXPORT bool Encrypt(const String& theInput, OTSymmetricKey& theKey,
                        const OTPassword& thePassword);
    EXPORT bool Decrypt(String& theOutput, const OTSymmetricKey& theKey,
                        const OTPassword& thePassword);

    // ASYMMETRIC CRYPTO (RSA / AES)

    EXPORT bool Seal(const setOfNyms& recipients,
                     const String& theInput); // Put data into this object
                                              // with Seal().

    EXPORT bool Seal(const Nym& theRecipient,
                     const String& theInput); // Put data into this object
                                              // with Seal().

    EXPORT bool Seal(const mapOfAsymmetricKeys& recipientKeys,
                     const String& theInput); // Currently supports strings
                                              // only.

    EXPORT bool Seal(const OTAsymmetricKey& RecipPubKey,
                     const String& theInput); // Currently supports strings
    // only.

    // (Opposite of Seal.)
    //
    EXPORT bool Open(const Nym& theRecipient, String& theOutput,
                     const OTPasswordData* pPWData = nullptr);

    // Should be called "Get Envelope's binary Ciphertext data into an
    // Ascii-Armored output String."
    //
    // Presumably this Envelope contains encrypted data (in binary form.)
    // If you would like an ASCII-armored version of that data, just call this
    // function.
    // (Bookends not included.)
    //
    EXPORT bool GetAsciiArmoredData(OTASCIIArmor& theArmoredText,
                                    bool bLineBreaks = true) const;
    EXPORT bool GetAsBookendedString(String& strArmorWithBookends,
                                     bool bEscaped = false) const;

    // Should be called "Set This Envelope's binary ciphertext data, from an
    // ascii-armored input string."
    //
    // Let's say you just retrieved the ASCII-armored contents of an encrypted
    // envelope.
    // Perhaps someone sent it to you, and you just read it out of his message.
    // And let's say you want to get those contents back into binary form in an
    // Envelope object again, so that they can be decrypted and extracted back
    // as
    // plaintext. Fear not, just call this function.
    //
    EXPORT bool SetAsciiArmoredData(const OTASCIIArmor& theArmoredText,
                                    bool bLineBreaks = true);
    EXPORT bool SetFromBookendedString(const String& strArmorWithBookends,
                                       bool bEscaped = false);
};

} // namespace opentxs

#endif // OPENTXS_CORE_CRYPTO_OTENVELOPE_HPP
