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
 *       -- Currency Currencies, Markets, Payment Plans.
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

#include <opentxs/core/Nym.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/contract/SecurityContract.hpp>

namespace opentxs
{

SecurityContract::SecurityContract(
    const ConstNym& nym,
    const proto::UnitDefinition serialized)
        : ot_super(nym, serialized)
{
}

SecurityContract::SecurityContract(
    const ConstNym& nym,
    const std::string& shortname,
    const std::string& name,
    const std::string& symbol,
    const std::string& terms)
        : ot_super(nym, shortname, name, symbol, terms)
{
}

proto::UnitDefinition SecurityContract::IDVersion() const
{
    proto::UnitDefinition contract = ot_super::IDVersion();

    contract.set_type(Type());

    auto security = contract.mutable_security();
    security->set_version(1);
    security->set_type(proto::EQUITYTYPE_SHARES);

    return contract;
}

} // namespace opentxs
