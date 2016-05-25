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

#ifndef OPENTXS_CORE_CRYPTO_CONTACTCREDENTIAL_HPP
#define OPENTXS_CORE_CRYPTO_CONTACTCREDENTIAL_HPP

#include "opentxs/core/Proto.hpp"
#include "opentxs/core/Types.hpp"
#include "opentxs/core/crypto/Credential.hpp"
#include "opentxs/core/crypto/NymParameters.hpp"

#include <memory>

namespace opentxs
{

class String;

class ContactCredential : public Credential
{
private:
    typedef Credential ot_super;
    friend class Credential;

    std::unique_ptr<proto::ContactData> data_;

    ContactCredential() = delete;
    ContactCredential(
        CredentialSet& parent,
        const proto::Credential& credential);
    ContactCredential(
        CredentialSet& parent,
        const NymParameters& nymParameters);

public:
    static std::string ClaimID(
        const std::string& nymid,
        const uint32_t section,
        const proto::ContactItem& item);
    static Claim asClaim(
        const String& nymid,
        const uint32_t section,
        const proto::ContactItem& item);

    bool GetContactData(
        std::unique_ptr<proto::ContactData>& contactData) const override;
    serializedCredential asSerialized(
        SerializationModeFlag asPrivate,
        SerializationSignatureFlag asSigned) const override;

    virtual ~ContactCredential() = default;
};

} // namespace opentxs

#endif // OPENTXS_CORE_CRYPTO_CONTACTCREDENTIAL_HPP
