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

#ifndef OPENTXS_CORE_SIGNABLE_HPP
#define OPENTXS_CORE_SIGNABLE_HPP

#include <list>
#include <memory>
#include <string>

#include <opentxs-proto/verify/VerifyCredentials.hpp>

#include "opentxs/core/Identifier.hpp"
#include "opentxs/core/OTData.hpp"

namespace opentxs
{

typedef std::shared_ptr<const class Nym> ConstNym;
typedef std::shared_ptr<proto::Signature> SerializedSignature;
typedef std::list<SerializedSignature> Signatures;

class Nym;

class Signable
{
protected:
    std::string alias_;
    Identifier id_;
    ConstNym nym_;
    Signatures signatures_;
    uint32_t version_ = 0;
    std::string conditions_; // Human-readable portion

    // Calculate identifier
    virtual Identifier GetID() const = 0;
    // Calculate and unconditionally set id_
    bool CalculateID() { id_ = GetID(); return true; }
    // Calculate the ID and verify that it matches the existing id_ value
    bool CheckID() const { return (GetID() == id_); }

    Signable() = delete;
    Signable(const ConstNym& nym);

public:
    ConstNym Nym() const { return nym_; }

    virtual std::string Alias() const { return alias_; }

    virtual Identifier ID() const { return id_; }
    virtual std::string Terms() const { return conditions_; }

    virtual void SetAlias(std::string alias) { alias_ = alias;}

    virtual std::string Name() const = 0;
    virtual OTData Serialize() const = 0;
    virtual bool Validate() const = 0;

    virtual ~Signable() = default;
};

} // namespace opentxs

#endif // OPENTXS_CORE_SIGNABLE_HPP
