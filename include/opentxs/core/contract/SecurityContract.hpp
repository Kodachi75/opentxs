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

#ifndef OPENTXS_CORE_SECURITYCONTRACT_HPP
#define OPENTXS_CORE_SECURITYCONTRACT_HPP

#include "opentxs/core/contract/UnitDefinition.hpp"

namespace opentxs
{

class Nym;

class SecurityContract : public UnitDefinition
{
private:
    typedef UnitDefinition ot_super;
    friend ot_super;

    std::string issue_date_;

    SecurityContract(
        const ConstNym& nym,
        const proto::UnitDefinition serialized);
    SecurityContract(
        const ConstNym& nym,
        const std::string& shortname,
        const std::string& name,
        const std::string& symbol,
        const std::string& terms,
        const std::string& date);

    proto::UnitDefinition IDVersion() const override;

public:
    EXPORT std::string IssueDate() const { return issue_date_; }
    EXPORT proto::UnitType Type() const override
        { return proto::UNITTYPE_SECURITY; }

    virtual ~SecurityContract() = default;
};

} // namespace opentxs

#endif // OPENTXS_CORE_SECURITYCONTRACT_HPP
